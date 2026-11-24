#!/usr/bin/env python3
"""Read-only host evidence adapter for the pinned Rust preflight CLI."""
import argparse, datetime, hashlib, importlib.metadata, json, os, pathlib, re, shutil, subprocess, sys, tomllib, urllib.request
import adapter_registry as adapters
P = pathlib.Path
PIN = "556ec2226dac1b4ff27aaa919458d27ae883333f39372fd2e7b4a36e95dfcaf8"
SOURCES = adapters.npm_sources()
SEMVER = re.compile(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
def ver(x):
    return x if isinstance(x,str) and len(x)<80 and re.fullmatch(r"[a-zA-Z0-9.+_-]+",x) else None
def stable(x):
    m = SEMVER.fullmatch(x or "")
    return tuple(map(int,m.groups())) if m else None
def compare(a,b):
    x,y=stable(a),stable(b)
    return "UNKNOWN" if x is None or y is None else ("CANDIDATE_AVAILABLE" if y>x else "SAME_VERSION" if x==y else "INSTALLED_AHEAD")
def run(argv, stdin=None):
    try:
        p=subprocess.run(argv,input=stdin,text=True,capture_output=True,timeout=5,check=False,
                         env={**os.environ,"GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"})
        return p.stdout.strip() if p.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired): return None
def read_metadata(path,kind="json"):
    try:
        if path.stat().st_size>2_000_000: return None
        with path.open("rb") as f:
            return json.load(f) if kind=="json" else tomllib.load(f)
    except (OSError,ValueError): return None
def npm_tool(name,allowed):
    target=shutil.which(name)
    if target:
        for parent in P(target).resolve().parents:
            if parent.name=="node_modules": break
            data=read_metadata(parent/"package.json")
            if isinstance(data,dict) and data.get("name") in allowed:
                return {"tool":name,"kind":"npm","identity":data["name"],"installed":ver(data.get("version")),
                        "evidence":"resolved executable ancestor package.json","scope":"PATH"}
    return {"tool":name,"kind":"npm","installed":None,"evidence":"metadata not resolved" if target else "not on PATH","scope":"PATH"}
def lookup(url,key,expected=None):
    # Fixed public endpoints only; no credentials, no redirects, no proxy.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"Tredven-Upstream-readonly","Accept":"application/json"})
        with opener.open(req,timeout=5) as f: raw=f.read(2_000_001)
        if len(raw)>2_000_000: return None
        data=json.loads(raw)
        if expected is not None and data.get("name")!=expected: return None
        return ver(data.get(key))
    except (OSError,ValueError,AttributeError): return None
def git_repo(path,tool="git-repository"):
    commit=run(["git","--no-optional-locks","-C",str(path),"rev-parse","--verify","HEAD"])
    tag=run(["git","--no-optional-locks","-C",str(path),"describe","--tags","--exact-match","HEAD"])
    return {"tool":tool,"kind":"git","installed":ver(tag),"commit":commit if commit and re.fullmatch("[0-9a-f]{40,64}",commit) else None,
            "evidence":"explicit checkout HEAD and exact tag","scope":"selected checkout; runtime not proven"}
def hermes(path):
    if not path:
        return {"tool":"hermes","kind":"git","installed":None,"evidence":"no selected source; PATH presence only","scope":"PATH","path_present":bool(shutil.which("hermes"))}
    row=git_repo(path,"hermes")
    data=read_metadata(path/"pyproject.toml","toml") or {}
    project=data.get("project",{})
    origin=run(["git","--no-optional-locks","-C",str(path),"config","--local","--get","remote.origin.url"])
    # Never return the remote URL, which could embed credentials.
    official=origin in ("https://github.com/NousResearch/hermes-agent.git","https://github.com/NousResearch/hermes-agent","git@github.com:NousResearch/hermes-agent.git","https://github.com/nousresearch/hermes-agent.git")
    row["identity"]="NousResearch/hermes-agent" if official else None
    row["metadata_version"]=ver(project.get("version"))
    row["evidence"]="explicit checkout; exact origin string and HEAD; no running instance verification"
    return row
def native(name,pattern):
    out=run([name,"--version"]) if shutil.which(name) else None
    m=re.search(pattern,out or "")
    return {"tool":name,"kind":"runtime","installed":ver(m.group(1)) if m else None,
            "evidence":"native --version" if m else "version unavailable","scope":"PATH; no daemon query"}
def core_review(row,core):
    inp={"schema":"tredven.upstream.preflight-input.v1","project":row["tool"],
         "baseline":{"tag":row["installed"]},"candidate":{"tag":row["latest"]},
         "compare_coverage":"unknown","changed_paths":[],
         "checks":[{"name":"runtime_compatibility","status":"not_run"}]}
    # The existing Rust core remains the only decision engine.
    out=run([str(core),"inspect","--stdin"],json.dumps(inp))
    try:
        report=json.loads(out or "")
        if report["production_ready"] or any(report["authority"].values()): raise ValueError("authority")
        return report
    except (ValueError,KeyError,AttributeError): return None
def inventory(args):
    rows=adapters.collect(args,npm_tool=npm_tool,native=native,hermes=hermes,git_repo=git_repo,ver=ver)
    for r in rows:
        ident=r.get("identity")
        url=SOURCES.get(ident)
        if r["tool"]=="hermes" and ident=="NousResearch/hermes-agent":
            url="https://api.github.com/repos/NousResearch/hermes-agent/releases/latest"
        r["upstream"]=url
        r["latest"]=lookup(url,"tag_name" if r["tool"]=="hermes" else "version",None if r["tool"]=="hermes" else ident) if args.public_lookup and url else None
        r["version_status"]=compare(r.get("installed"),r["latest"])
        r["core_review"]=core_review(r,args.core) if r["version_status"]=="CANDIDATE_AVAILABLE" and args.core else None
        r["maintenance_action"]="Review release notes and qualify actual integrations" if r["version_status"]=="CANDIDATE_AVAILABLE" else "No upgrade conclusion without sufficient scoped evidence" if r["version_status"]=="UNKNOWN" else "No newer stable version indicated by selected channel"
        if r["version_status"]=="CANDIDATE_AVAILABLE" and not r["core_review"]: r["maintenance_action"]="Candidate detected; core review unavailable; do not upgrade"
    return {"schema":"tredven.upstream.host-inventory.v1","observed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "adapter_catalog_version":1,"public_lookup":args.public_lookup,"scope":"selected host / PATH / explicit checkouts; not a fleet or running-service inventory",
            "coverage_gaps":["MCP server identities and dependencies","running containers and services","non-PATH installs and other interpreters","release notes and compatibility","publisher authenticity beyond selected endpoints"],
            "production_ready":False,"authority":{"patch":False,"merge":False,"deploy":False,"send":False,"provider_writes":False,"release":False},"assets":rows}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--public-lookup",action="store_true");p.add_argument("--core",type=P)
    p.add_argument("--hermes-source",type=P);p.add_argument("--repo",type=P,action="append",default=[])
    a=p.parse_args()
    if a.core:
        if not a.core.is_file() or hashlib.sha256(a.core.read_bytes()).hexdigest()!=PIN: p.error("pinned Rust CLI hash mismatch")
        a.core=a.core.resolve()
    if len(a.repo)>20: p.error("at most 20 selected repositories")
    print(json.dumps(inventory(a),indent=2))
if __name__=="__main__": main()
