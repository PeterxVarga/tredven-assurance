#!/usr/bin/env python3
"""Runtime and structural dependency evidence. No service starts, updates or MCP calls."""
import argparse, datetime, hashlib, json, os, pathlib, re, shutil, subprocess, sys, urllib.request, urllib.parse, email.parser
import discover as d
P=pathlib.Path
MAX_CONFIG=262144
PUBLIC_REPOS=d.adapters.release_sources()
COMMANDS={"node","npx","npm","uv","uvx","python","python3","docker","podman","bun","bunx","deno","pi","hermes","opencode"}
TOOLS={"pi","hermes","opencode","orca","node","nodejs","podman","conmon","dockerd","containerd","postgres","redis-server","python","python3","mcp-server"}
KEYWORDS={"breaking":r"\bbreaking\b","migration":r"\bmigrat(?:e|ion|ions)\b","mcp":r"\bmcp\b","auth":r"\b(?:auth|authentication|oauth)\b","provider":r"\bproviders?\b","security":r"\b(?:security|vulnerability|cve-\d+)\b","plugin":r"\b(?:plugin|extension)s?\b"}
def jsonc(text):
    # Tokens protect quoted strings (including URLs) from comment removal.
    pat=re.compile(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/|,|[}\]]')
    parts=[]; last=0
    for m in pat.finditer(text):
        parts.append(text[last:m.start()]); s=m.group()
        parts.append(" " if s.startswith(("//","/*")) else s); last=m.end()
    parts.append(text[last:])
    cleaned="".join(parts)
    # Remove trailing commas without changing commas inside strings.
    cleaned=re.sub(r'"(?:\\.|[^"\\])*"|,(\s*[}\]])',lambda m:m.group(1) if m.group(1) else m.group(),cleaned)
    return json.loads(cleaned)
def config_data(path):
    try:
        if not path.is_file(): return None,"ABSENT"
        if path.stat().st_size>MAX_CONFIG: return None,"SIZE_LIMIT"
        text=path.read_text(encoding="utf-8")
        if path.suffix in (".yaml",".yml"):
            try: import yaml
            except ImportError: return None,"PARSER_UNAVAILABLE"
            # Do not expand YAML aliases or custom tags.
            for token in yaml.scan(text,Loader=yaml.SafeLoader):
                if isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken,yaml.tokens.TagToken)):
                    return None,"UNSUPPORTED_YAML_FEATURE"
            obj=yaml.safe_load(text)
        else: obj=jsonc(text)
        return (obj,"PARSED") if isinstance(obj,dict) else (None,"INVALID_STRUCTURE")
    except Exception: return None,"PARSE_OR_READ_ERROR"
def mcp_config(path,owner,section):
    obj,status=config_data(path)
    result={"owner":owner,"status":status,"section":section,"servers":[]}
    if obj is None: return result
    if section not in obj:
        result["status"]="SECTION_ABSENT";return result
    servers=obj[section]
    if not isinstance(servers,dict): result["status"]="INVALID_SECTION";return result
    if len(servers)>200: result["status"]="LIMIT_EXCEEDED";return result
    for index,(name,entry) in enumerate(servers.items()):
        if not isinstance(entry,dict):
            result["status"]="PARTIAL_INVALID_ENTRIES"; continue
        # Aliases are hashed; command arguments, URL, env, headers and secret values never exported.
        alias=hashlib.sha256(str(name).encode()).hexdigest()[:16]
        cmd=entry.get("command")
        if isinstance(cmd,list): cmd=cmd[0] if cmd else None
        cmd=P(cmd).name if isinstance(cmd,str) else None
        transport="remote" if entry.get("type")=="remote" or "url" in entry else "local" if entry.get("type")=="local" or "command" in entry else "unknown"
        enabled=entry.get("enabled")
        result["servers"].append({"id":f"{owner}:{alias}","transport":transport,"command_family":cmd if cmd in COMMANDS else None,
                                  "enabled":enabled if isinstance(enabled,bool) else None,"state":"CONFIGURED_ONLY"})
    return result
def process_inventory(proc=P("/proc"),which=shutil.which):
    rows={}; denied=0; seen=0
    resolved={}
    for tool in ("pi","hermes","opencode"):
        path=which(tool)
        if path:
            try: resolved[tool]=P(path).resolve()
            except OSError: pass
    for p in proc.iterdir():
        if not p.name.isdecimal(): continue
        if seen>=20000: break
        seen+=1
        try:
            if p.stat().st_uid!=os.getuid(): continue
            comm=(p/"comm").read_text().strip()
            exe=P(os.readlink(p/"exe"))
        except (OSError,UnicodeError):
            denied+=1; continue
        tool=next((t for t,expected in resolved.items() if exe==expected),None)
        evidence="resolved executable path match" if tool else "kernel comm / executable basename"
        if tool is None:
            tool=comm if comm in TOOLS else exe.name if exe.name in TOOLS else None
        if tool:
            k=(tool,evidence)
            rows[k]=rows.get(k,0)+1
    return {"status":"OBSERVED","scope":"same-UID procfs; no cmdline or env read; no runtime version claim",
            "processes":[{"tool":k[0],"evidence":k[1],"count":v,"running_version":None} for k,v in sorted(rows.items())],
            "unreadable_or_exited":denied,"limit_reached":seen>=20000}
def services():
    socket=P("/run/user")/str(os.getuid())/"bus"
    env=dict(os.environ)
    if socket.is_socket() and socket.stat().st_uid==os.getuid():
        env["XDG_RUNTIME_DIR"]=str(socket.parent)
        env["DBUS_SESSION_BUS_ADDRESS"]="unix:path="+str(socket)
    try:
        result=subprocess.run(["systemctl","--user","--no-pager","list-units","--type=service","--state=running","--plain","--no-legend"],env=env,capture_output=True,text=True,timeout=5)
        raw=result.stdout if result.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired):raw=None
    if raw is None: return {"status":"UNKNOWN","units":[]}
    units=[]
    for line in raw.splitlines():
        fields=line.split()
        if not fields: continue
        name=fields[0].lower()
        if any(t in name for t in ("tredven","hermes","opencode","orca","mcp","podman","container","pi-")):
            units.append({"id":hashlib.sha256(name.encode()).hexdigest()[:16],"state":"running","identity":"name match only"})
    return {"status":"OBSERVED","scope":"user systemd running units; filtered names hashed","units":units}
def containers(enabled):
    if not enabled:return {"status":"NOT_REQUESTED","containers":[]}
    if not (P.home()/".local/share/containers/storage").is_dir(): return {"status":"NO_EXISTING_DEFAULT_STORAGE","containers":[]}
    # Prefer the existing native local rootless CLI. On re-exec denial only,
    # reuse the same UID's already present local Podman socket. Never enable it,
    # use a remote endpoint, or issue a container mutation.
    transport="native-local"
    try:
        result=subprocess.run(["podman","--remote=false","ps","--format","{{.ID}}\t{{.Image}}"],capture_output=True,text=True,timeout=5)
        if result.returncode!=0 and "cannot re-exec" in result.stderr.lower():
            socket=P("/run/user")/str(os.getuid())/"podman/podman.sock"
            if socket.is_socket() and socket.stat().st_uid==os.getuid() and not socket.is_symlink():
                result=subprocess.run(["podman","--remote=true","--url","unix://"+str(socket),"ps","--format","{{.ID}}\t{{.Image}}"],capture_output=True,text=True,timeout=10)
                transport="existing-same-uid-unix-socket"
        if result.returncode!=0:
            reason="USER_NAMESPACE_PERMISSION" if "uid_map" in result.stderr and "Operation not permitted" in result.stderr else "NATIVE_QUERY_FAILED"
            return {"status":"UNKNOWN","reason":reason,"containers":[]}
        raw=result.stdout
    except (OSError,subprocess.TimeoutExpired):return {"status":"UNKNOWN","reason":"UNAVAILABLE_OR_TIMEOUT","containers":[]}
    rows=[]
    for line in raw.splitlines():
        a=line.split("\t")
        if len(a)!=2 or not re.fullmatch("[0-9a-f]{12,64}",a[0]): continue
        image=a[1]
        # Avoid emitting private image refs: only a digest of the observed reference.
        rows.append({"id":a[0],"image_ref_hash":hashlib.sha256(image.encode()).hexdigest(),"state":"running","version":None})
    return {"status":"OBSERVED","scope":"rootless local Podman running containers; not image version or health proof","transport":transport,"containers":rows}
def release(row):
    ident=row.get("identity"); source=PUBLIC_REPOS.get(ident)
    tag=row.get("latest")
    if not source or not d.stable(tag): return {"status":"UNSUPPORTED_OR_UNKNOWN"}
    repo,prefix=source
    tag=prefix+tag.removeprefix("v")
    url="https://api.github.com/repos/"+repo+"/releases/tags/"+tag
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k):return None
    try:
        op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        req=urllib.request.Request(url,headers={"User-Agent":"Tredven-Upstream-readonly","Accept":"application/vnd.github+json"})
        with op.open(req,timeout=5) as f: raw=f.read(1_000_001)
        if len(raw)>1_000_000:return {"status":"SIZE_LIMIT","source":url}
        data=json.loads(raw)
        if data.get("tag_name")!=tag or data.get("draft") is not False or data.get("prerelease") is not False:
            return {"status":"TAG_OR_CHANNEL_MISMATCH","source":url}
        body=data.get("body")
        if not isinstance(body,str) or not body.strip():return {"status":"EMPTY_NOTES","source":url}
        return {"status":"OBSERVED_EXACT_TAG","source":url,"tag":tag,"body_sha256":hashlib.sha256(body.encode()).hexdigest(),
                "published_at":data.get("published_at"),"keyword_hits":{k:len(re.findall(v,body,re.I)) for k,v in KEYWORDS.items()},
                "scope":"candidate release only; keyword signals not compatibility proof"}
    except (OSError,ValueError,AttributeError):return {"status":"UNAVAILABLE","source":url}
def package_edges():
    edges=[]
    for tool in tuple(a.id for a in d.adapters.CATALOG if a.kind=="npm"):
        target=shutil.which(tool)
        if not target:continue
        for parent in P(target).resolve().parents:
            if parent.name=="node_modules":break
            obj=d.read_metadata(parent/"package.json")
            if not isinstance(obj,dict) or obj.get("name") not in next(a.identities for a in d.adapters.CATALOG if a.id==tool):continue
            engines=obj.get("engines",{})
            constraint=engines.get("node") if isinstance(engines,dict) else None
            if isinstance(constraint,str) and re.fullmatch(r"[0-9v.xX*<>=~^| &+-]{1,120}",constraint):
                edges.append({"from":tool,"to":"node","kind":"declared_engine","constraint":constraint,"evidence":"installed package manifest","runtime_verified":False})
            deps=obj.get("dependencies",{})
            if isinstance(deps,dict):
                for name,version in deps.items():
                    if not isinstance(name,str) or not isinstance(version,str):continue
                    if (name.startswith(("@earendil-works/pi-","@mariozechner/pi-","@opencode/")) or name=="@modelcontextprotocol/sdk") and re.fullmatch(r"[@a-zA-Z0-9/_-]{1,100}",name) and re.fullmatch(r"[0-9v.xX*<>=~^| &+-]{1,120}",version):
                        edges.append({"from":tool,"to":name,"kind":"declared_package_dependency","constraint":version,"evidence":"installed package manifest","runtime_verified":False})
            break
    return edges
def hermes_install(venv,source):
    if not venv or not source:return {"status":"NOT_SELECTED"}
    for meta in venv.glob("lib/python*/site-packages/hermes_agent-*.dist-info"):
        obj=d.read_metadata(meta/"direct_url.json")
        if not isinstance(obj,dict):continue
        url=obj.get("url")
        if not isinstance(url,str):continue
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!="file" or parsed.netloc not in ("","localhost"):continue
        if P(urllib.parse.unquote(parsed.path)).resolve()!=source.resolve():continue
        try:
            f=meta/"METADATA"
            if f.stat().st_size>MAX_CONFIG:continue
            headers=email.parser.Parser().parsestr(f.read_text(),headersonly=True)
            if headers.get("Name","").lower().replace("_","-")!="hermes-agent":continue
            return {"status":"EDITABLE_SOURCE_MATCH","metadata_version":d.ver(headers.get("Version")),"runtime_verified":False,"source_relation":"direct_url local path matches explicit checkout","editable":obj.get("dir_info",{}).get("editable") is True}
        except (OSError,ValueError):continue
    return {"status":"UNKNOWN"}
def candidate_engine(row):
    url=d.SOURCES.get(row.get("identity"))
    if not url:return {"status":"UNKNOWN"}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k):return None
    try:
        op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        req=urllib.request.Request(url,headers={"User-Agent":"Tredven-Upstream-readonly","Accept":"application/json"})
        with op.open(req,timeout=5) as f:raw=f.read(2_000_001)
        if len(raw)>2_000_000:return {"status":"SIZE_LIMIT"}
        obj=json.loads(raw)
        if obj.get("name")!=row.get("identity") or obj.get("version")!=row.get("latest"):return {"status":"IDENTITY_OR_VERSION_MISMATCH"}
        engines=obj.get("engines",{})
        node=engines.get("node") if isinstance(engines,dict) else None
        if isinstance(node,str) and re.fullmatch(r"[0-9v.xX*<>=~^| &+-]{1,120}",node):
            return {"status":"OBSERVED_DECLARATION","node_constraint":node,"source":url,"package_version":row["latest"],"compatibility_verified":False}
        return {"status":"NOT_DECLARED_OR_UNSUPPORTED"}
    except (OSError,ValueError,AttributeError):return {"status":"UNAVAILABLE"}
def enrich(report,args):
    h=P.home()
    configs=[mcp_config(h/".config/opencode/opencode.json","opencode-json","mcp"),
             mcp_config(h/".config/opencode/opencode.jsonc","opencode-jsonc","mcp"),
             mcp_config(h/".pi/agent/mcp.json","pi-mcp","mcpServers"),
             mcp_config(h/".hermes/config.yaml","hermes-default","mcp_servers")]
    for i,path in enumerate(args.hermes_config):
        configs.append(mcp_config(path,"hermes-selected-"+str(i),"mcp_servers"))
    edges=package_edges()
    for c in configs:
        for r in c["servers"]:
            edges.append({"from":c["owner"],"to":r["id"],"kind":"declared_mcp","evidence":"config structure","runtime_verified":False})
    for row in report["assets"]:
        if row["version_status"]=="CANDIDATE_AVAILABLE":
            row["release_evidence"]=release(row) if args.public_lookup else {"status":"NOT_REQUESTED"}
            row["candidate_engine"]=candidate_engine(row) if args.public_lookup else {"status":"NOT_REQUESTED"}
            row["required_checks"]=["source identity","release range","isolated runtime compatibility","rollback"]
            if row["tool"]=="opencode":row["required_checks"]+=["agent bridge contract","MCP integration"]
            if row["tool"]=="npm":row["required_checks"]+=["Node engine constraints","global package CLI compatibility"]
    report.update({"schema":"tredven.upstream.runtime-inventory.v2","runtime":process_inventory(),
                   "services":services(),"container_runtime":containers(args.containers),"mcp_structure":configs,"dependency_edges":edges,"hermes_install":hermes_install(args.hermes_venv,args.hermes_source)})
    report["coverage_gaps"]=["running versions not independently established","configured MCP not connected or verified","explicit profile coverage only; Pi extensions and bridge edges not inferred","container image versions and health unknown","candidate notes are not a complete release range","runtime compatibility not tested"]
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
    print(json.dumps(enrich(d.inventory(a),a),indent=2))
if __name__=="__main__":main()
