"""Evidence-bound planning, using npm's installed SemVer and the existing Rust gate."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess
import discover as d
import runtime_discovery as r
import adapter_registry as adapters
import runtime_bindings
P=pathlib.Path
def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
def semver_module():
    exe=shutil.which("npm")
    if not exe:return None
    for parent in P(exe).resolve().parents:
        if parent.name=="node_modules":break
        meta=d.read_metadata(parent/"package.json")
        if not isinstance(meta,dict) or meta.get("name")!="npm":continue
        path=parent/"node_modules/semver"
        m=d.read_metadata(path/"package.json")
        if isinstance(m,dict) and m.get("name")=="semver" and d.stable(m.get("version")):
            return path.resolve(),m["version"]
        return None
    return None
def node_range(version,constraint):
    if not d.stable(version) or not isinstance(constraint,str) or not re.fullmatch(r"[0-9v.xX*<>=~^| &+-]{1,120}",constraint):
        return {"status":"UNKNOWN","reason":"INVALID_OR_UNSUPPORTED_INPUT"}
    mod=semver_module();node=shutil.which("node")
    if not mod or not node:return {"status":"UNKNOWN","reason":"NATIVE_SEMVER_UNAVAILABLE"}
    path,lib_version=mod
    script="""const fs=require('node:fs');const s=require(process.argv[1]);const x=JSON.parse(fs.readFileSync(0,'utf8'));if(!s.valid(x.version)||!s.validRange(x.range)){process.exitCode=2;}else{process.stdout.write(JSON.stringify(s.satisfies(x.version,x.range)));}"""
    try:
        # Fixed script and local installed dependency; no package download or shell.
        proc=subprocess.run([node,"-e",script,str(path)],input=json.dumps({"version":version,"range":constraint}),
                            capture_output=True,text=True,timeout=5,env={"PATH":os.environ.get("PATH","/usr/bin"),"LANG":"C"})
        if proc.returncode!=0 or proc.stdout not in ("true","false"):return {"status":"UNKNOWN","reason":"NATIVE_SEMVER_REJECTED"}
        return {"status":"MATCH" if proc.stdout=="true" else "MISMATCH","version":version,"constraint":constraint,
                "evaluator":"npm bundled semver "+lib_version,"scope":"selected PATH Node only; actual runtime binding not established"}
    except (OSError,subprocess.TimeoutExpired):return {"status":"UNKNOWN","reason":"NATIVE_SEMVER_FAILED"}
def graph_impact(edges,subject):
    # from = consumer, to = dependency. Walk each direction separately;
    # sharing a dependency does not prove a dependency between two consumers.
    valid=[]
    for e in edges:
        if not isinstance(e,dict) or e.get("kind") not in ("declared_engine","declared_package_dependency","declared_mcp"):continue
        a,b=e.get("from"),e.get("to")
        if isinstance(a,str) and isinstance(b,str) and len(a)<200 and len(b)<200:valid.append(e)
    def walk(reverse):
        visited={subject}; todo=[subject]; result=[]
        while todo:
            n=todo.pop(0)
            for e in valid:
                a,b=(e["to"],e["from"]) if reverse else (e["from"],e["to"])
                if a==n and b not in visited:
                    visited.add(b);todo.append(b)
                    result.append({"asset":b,"edge":e,"evidence_sha256":digest(e)})
        return result
    return {"declared_dependencies":walk(False),"declared_consumers":walk(True),
            "scope":"observed graph only; no inferred or runtime-verified edges"}
def check(id,status,evidence=None):
    return {"id":id,"status":status,"evidence_sha256":digest(evidence) if evidence is not None else None}
def core_receipt(row,core,static):
    if core is None:return None
    inp={"schema":"tredven.upstream.preflight-input.v1","project":row["tool"],
         "baseline":{"tag":row["installed"]},"candidate":{"tag":row["latest"]},"compare_coverage":"unknown",
         "changed_paths":[],"checks":[{"name":"runtime_compatibility","status":"not_run"},
         {"name":"selected_node_engine_constraint","status":{"MATCH":"passed","MISMATCH":"failed"}.get(static.get("status"),"unknown")}]}
    try:
        p=subprocess.run([str(core),"inspect","--stdin"],input=json.dumps(inp),text=True,capture_output=True,timeout=5)
        if p.returncode not in (0,2):return None
        out=p.stdout
    except (OSError,subprocess.TimeoutExpired):return None
    try:
        rep=json.loads(out)
        if rep.get("schema")!="tredven.upstream.preflight-report.v1" or rep.get("project")!=row["tool"] or rep.get("baseline_tag")!=row["installed"] or rep.get("candidate_tag")!=row["latest"]:return None
        if rep.get("production_ready") is not False or not rep.get("authority") or any(v is not False for v in rep["authority"].values()):return None
        if rep.get("decision") not in ("UNKNOWN","BLOCKED"):return None
        return {"input_sha256":digest(inp),"core_sha256":d.PIN,"report":rep}
    except (ValueError,AttributeError,TypeError):return None
def plans(report,core=None):
    out=[]
    node=next((a.get("installed") for a in report["assets"] if a.get("tool")=="node"),None)
    for row in report["assets"]:
        if row.get("version_status")!="CANDIDATE_AVAILABLE":continue
        engine=row.get("candidate_engine",{})
        static=node_range(node,engine.get("node_constraint")) if engine.get("status")=="OBSERVED_DECLARATION" else {"status":"UNKNOWN","reason":"CANDIDATE_ENGINE_NOT_OBSERVED"}
        release=row.get("release_evidence",{})
        impact=graph_impact(report["dependency_edges"],row["tool"])
        checks=[check("exact_candidate_release","OBSERVED" if release.get("status")=="OBSERVED_EXACT_TAG" else "UNKNOWN",release),
                check("selected_node_constraint",static["status"],static),
                check("complete_release_range","NOT_RUN"),check("source_identity","NOT_RUN"),
                check("runtime_binding","NOT_RUN"),check("isolated_runtime_compatibility","NOT_RUN"),check("rollback","NOT_RUN")]
        for name in row.get("required_checks",[]):
            if name in ("agent bridge contract","MCP integration","global package CLI compatibility"):
                checks.append(check(name.replace(" ","_"),"NOT_RUN"))
        receipt=core_receipt(row,core,static)
        out.append({"asset_id":row["asset_id"],"tool":row["tool"],"installed":row["installed"],"candidate":row["latest"],
                    "candidate_evidence_sha256":digest(row),"impact":impact,"static_node_check":static,"checks":checks,
                    "core_receipt":receipt,"disposition":receipt["report"]["decision"] if receipt else "UNKNOWN",
                    "next_action":"Do not upgrade. Qualify source, release range, runtime binding, affected integrations and rollback."})
    return out
def platform(args):
    if args.core and hashlib.sha256(args.core.read_bytes()).hexdigest()!=d.PIN:
        raise ValueError("pinned Rust CLI hash mismatch")
    # The R3 receipt replaces the R1 per-candidate call; do not evaluate the same candidate twice.
    inventory_args=argparse.Namespace(**vars(args))
    inventory_args.core=None
    report=r.enrich(d.inventory(inventory_args),args)
    for row in report["assets"]:
        if row.get("version_status")=="CANDIDATE_AVAILABLE":
            row["maintenance_action"]="See evidence-bound compatibility plan; do not upgrade."

    for row in report["assets"]:
        if row["tool"] in ("git","podman","docker","python","node","uv"):
            row["native_package_ownership"]=adapters.rpm_ownership("python3" if row["tool"]=="python" else row["tool"],d.run)
    # Stable identity and normalized catalog are separate from detected coverage.
    catalog=[{"id":a.id,"version":a.version,"kind":a.kind} for a in adapters.CATALOG]
    report["runtime_bindings"]=runtime_bindings.scan(runtime_bindings.known_entries(args.hermes_venv,args.hermes_source))
    source_sha=digest(report)
    report.update({"schema":"tredven.upstream.compatibility-platform.v3","adapter_catalog":catalog,
                   "adapter_contract_version":1,"source_inventory_sha256":source_sha,
                   "compatibility_plans":plans(report,args.core)})
    return report
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--public-lookup",action="store_true");p.add_argument("--core",type=P)
    p.add_argument("--hermes-source",type=P);p.add_argument("--repo",type=P,action="append",default=[])
    p.add_argument("--hermes-venv",type=P);p.add_argument("--hermes-config",type=P,action="append",default=[]);p.add_argument("--containers",action="store_true")
    a=p.parse_args()
    if len(a.repo)>20 or len(a.hermes_config)>10:p.error("explicit scope limit")
    if a.core:
        if not a.core.is_file() or hashlib.sha256(a.core.read_bytes()).hexdigest()!=d.PIN:p.error("pinned Rust CLI hash mismatch")
        a.core=a.core.resolve()
    print(json.dumps(platform(a),indent=2))
if __name__=="__main__":main()
