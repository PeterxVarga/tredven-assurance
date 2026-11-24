"""Self-service, local stdio Node MCP qualification. Explicit disposable candidates only."""
import argparse, hashlib, html, json, os, pathlib, re, resource, shutil, stat, subprocess, tempfile
import compatibility as c
import discover as d
import workspace as w
import fcntl
P=pathlib.Path
APP=P(__file__).resolve().parent
DEPS=APP/"oss-contract-fixture"
PIN_LOCK="f7b23dbf7b13db623b4432a4d3a9101783816b4a4f9b4d5f0b8695b534aab864"
SCHEMA="tredven.assurance.selfservice.v1"
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def bounded_json(p):
    if not p.is_file() or p.stat().st_size>w.MAX:raise ValueError("invalid JSON file")
    return json.loads(p.read_text())
def seal(r):
    r["sha256"]=c.digest(r);return r
def verify(r):
    if r.get("schema")!=SCHEMA or r.get("sha256")!=c.digest({k:v for k,v in r.items() if k!="sha256"}) or r.get("live_upgrade_authorized") is not False:raise ValueError("invalid receipt")
    return r
def lock(root):
    fd=os.open(root/"monitor.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:
        os.close(fd);raise ValueError("unsafe lock")
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:os.close(fd);raise ValueError("workspace already running")
    return fd
def ready():
    if sha(DEPS/"package-lock.json")!=PIN_LOCK:raise ValueError("dependency lock mismatch")
    for name,version in (("@mcp-contracts/cli","0.10.0"),("@modelcontextprotocol/sdk","1.32.2")):
        if bounded_json(DEPS/"node_modules"/name/"package.json")["version"]!=version:raise ValueError("dependency version mismatch")
    node=shutil.which("node");box=shutil.which("bwrap")
    if not node or not box:raise ValueError("Node and bubblewrap required")
    return P(node).resolve(),box
def project_digest(root):
    # Explicit, prepared project only; refuse links escaping the read-only mount.
    h=hashlib.sha256();count=total=0
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in sorted(dirs+files):
            p=P(folder)/name;rel=str(p.relative_to(root));st=p.lstat()
            count+=1
            if count>20000:raise ValueError("project file limit")
            if stat.S_ISLNK(st.st_mode):
                target=os.readlink(p)
                if P(target).is_absolute() or not p.resolve(strict=True).is_relative_to(root):raise ValueError("external symlink")
                value=["link",target]
            elif stat.S_ISDIR(st.st_mode):value=["directory"]
            elif stat.S_ISREG(st.st_mode):
                total+=st.st_size
                if total>200_000_000:raise ValueError("project size limit")
                value=["file",st.st_size,sha(p)]
            else:raise ValueError("special file in prepared project")
            h.update(json.dumps([rel,value],separators=(",",":")).encode()+b"\n")
        dirs.sort()
    return h.hexdigest()
def server_meta(server,entry):
    server=server.resolve(strict=True)
    if not server.is_dir() or not re.fullmatch(r"[A-Za-z0-9_./-]+\.m?js",entry) or entry.startswith("/") or ".." in P(entry).parts:raise ValueError("explicit relative JS entry required")
    file=(server/entry).resolve(strict=True)
    if not file.is_relative_to(server) or not file.is_file():raise ValueError("entry outside project")
    meta=bounded_json(server/"package.json")
    if not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+",meta.get("name","")) or not d.stable(meta.get("version")):raise ValueError("stable package identity required")
    return server,{"name":meta["name"],"version":meta["version"],"entry":entry,"entry_sha256":sha(file),"manifest_sha256":sha(server/"package.json"),"project_sha256":project_digest(server),"identity_scope":"declared local package; not upstream attestation"}
def spec_load(path):
    s=bounded_json(path)
    if set(s)!={"tool","arguments","expected_content"} or not isinstance(s["tool"],str) or not s["tool"] or not isinstance(s["arguments"],dict) or not isinstance(s["expected_content"],list):raise ValueError("explicit replay contract required")
    if len(json.dumps(s))>65536:raise ValueError("replay limit")
    return s
def invoke(server,entry,args,files=None,allowed=(0,)):
    node,box=ready()
    with tempfile.TemporaryDirectory(prefix="assurance-input-") as tmp:
        p=P(tmp)
        for name,value in (files or {}).items():w.atomic(p/name,value)
        cmd=[box,"--unshare-all","--die-with-parent","--new-session","--clearenv","--ro-bind","/usr","/usr","--ro-bind","/lib64","/lib64","--symlink","usr/bin","/bin","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/opt","--ro-bind",str(node),"/opt/node","--ro-bind",str(DEPS),"/app","--ro-bind",str(server),"/server","--ro-bind",tmp,"/input","--setenv","HOME","/tmp","--setenv","PATH","/opt:/usr/bin","--setenv","LANG","C","--chdir","/server","--","/opt/node",*args]
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE,(w.MAX,w.MAX))
            resource.setrlimit(resource.RLIMIT_CPU,(30,35))
        with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
            result=subprocess.run(cmd,stdout=stdout,stderr=stderr,timeout=45,preexec_fn=limits)
            stdout.seek(0);raw=stdout.read(w.MAX+1)
        if result.returncode not in allowed or len(raw)>w.MAX:raise ValueError("isolated native command failed")
        return json.loads(raw),result.returncode
def observe(server,entry,spec):
    server,meta=server_meta(server,entry)
    snap,_=invoke(server,entry,["/app/node_modules/.bin/mcpdiff","--format","json","snapshot","--command","/opt/node","--args","/server/"+entry])
    if not isinstance(snap.get("tools"),dict) or not re.fullmatch("sha256:[a-f0-9]{64}",snap.get("contentHash","")):raise ValueError("invalid native snapshot")
    replay,_=invoke(server,entry,["/app/selfservice-replay.mjs","/server/"+entry],{"replay.json":spec})
    if type(replay.get("match")) is not bool or type(replay.get("isError")) is not bool:raise ValueError("invalid replay")
    if server_meta(server,entry)[1]!=meta:raise ValueError("source changed during observation")
    return {"package":meta,"snapshot":snap,"replay":replay,"runtime_sha256":sha(ready()[0])}
def baseline(root,server,entry,spec):
    if (root/"baseline.json").exists():raise ValueError("baseline already exists; use a new workspace")
    r=observe(server,entry,spec)
    if r["replay"]["match"] is not True:raise ValueError("baseline replay failed")
    x=seal({"schema":SCHEMA,"kind":"baseline","observation":r,"spec":spec,"created_utc":w.now(),"live_upgrade_authorized":False})
    w.atomic(root/"baseline.json",x);return x
def compare(base,server,entry,core):
    old=base["observation"];new=observe(server,entry,base["spec"])
    if old["package"]["name"]!=new["package"]["name"] or old["runtime_sha256"]!=new["runtime_sha256"]:raise ValueError("package/runtime identity mismatch")
    diff,rc=invoke(server.resolve(),entry,["/app/node_modules/.bin/mcpdiff","--format","json","diff","/input/before.json","/input/after.json"],{"before.json":old["snapshot"],"after.json":new["snapshot"]},(0,1))
    s=diff["summary"]
    if any(type(s.get(k)) is not int or s[k]<0 for k in ("breaking","warning","safe","total")) or s["total"]!=s["breaking"]+s["warning"]+s["safe"] or bool(rc)!=bool(s["breaking"]):raise ValueError("native diff summary mismatch")
    if diff["meta"]["before"]["contentHash"]!=old["snapshot"]["contentHash"] or diff["meta"]["after"]["contentHash"]!=new["snapshot"]["contentHash"]:raise ValueError("native diff binding mismatch")
    failed=bool(s["breaking"]) or not new["replay"]["match"]
    inp={"schema":"tredven.upstream.preflight-input.v1","project":new["package"]["name"],"baseline":{"tag":old["package"]["version"]},"candidate":{"tag":new["package"]["version"]},"compare_coverage":"unknown","changed_paths":[],"checks":[{"name":"runtime_compatibility","status":"not_run"},{"name":"mcp_contract","status":"failed" if s["breaking"] else "passed"},{"name":"isolated_replay","status":"passed" if new["replay"]["match"] else "failed"}]}
    result=subprocess.run([str(core),"inspect","--stdin"],input=json.dumps(inp),text=True,capture_output=True,timeout=5)
    native=json.loads(result.stdout)
    if result.returncode not in (0,2) or native["decision"]!=("BLOCKED" if failed else "UNKNOWN") or native["project"]!=inp["project"] or native["baseline_tag"]!=old["package"]["version"] or native["candidate_tag"]!=new["package"]["version"] or native["production_ready"] is not False or not native["authority"] or any(v is not False for v in native["authority"].values()):raise ValueError("native safety gate")
    return {"package":new["package"],"snapshot_sha256":c.digest(new["snapshot"]),"contract_hash":new["snapshot"]["contentHash"],"diff_summary":s,"diff_sha256":c.digest(diff),"replay":new["replay"],"decision":"BLOCKED" if failed else "REVIEW_REQUIRED" if s["warning"] else "PASS_SCOPED_CONTRACT_AND_REPLAY","native":native,"live_upgrade_authorized":False}
def evaluate(root,servers,entry,core,resolve=False):
    base=verify(w.private_read(root/"baseline.json"))
    if base["kind"]!="baseline":raise ValueError("baseline required")
    rows=[]
    for path in servers:
        try:rows.append(compare(base,path,entry,core))
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:rows.append({"decision":"UNKNOWN","reason":type(exc).__name__,"live_upgrade_authorized":False})
    viable=[r for r in rows if r["decision"]=="PASS_SCOPED_CONTRACT_AND_REPLAY" and (not resolve or d.compare(base["observation"]["package"]["version"],r["package"]["version"])=="CANDIDATE_AVAILABLE")]
    # Only choose a unique highest stable version from the supplied local candidates.
    selected=None
    if viable:
        key=lambda r:d.stable(r["package"]["version"])
        high=max(key(r) for r in viable);top=[r for r in viable if key(r)==high]
        if len(top)==1:selected=top[0]["package"]
    decision="REVIEW_REQUIRED" if selected else "BLOCKED" if rows and all(r["decision"]=="BLOCKED" for r in rows) else "UNKNOWN"
    return seal({"schema":SCHEMA,"kind":"resolution" if resolve else "check","baseline_sha256":base["sha256"],"created_utc":w.now(),"candidates":rows,"selected":selected,"decision":decision,"ci_exit":0 if selected else 1 if decision=="BLOCKED" else 2,"live_upgrade_authorized":False,"production_ready":False,"scope":"isolated local Node stdio servers, one explicit replay, highest uniquely qualified supplied stable version, no host deployment"})
def render(root,r):
    esc=lambda v:html.escape(str(v))
    body="<h1>Tredven Assurance</h1><p>"+esc(r["decision"])+"</p><p>Scoped compatibility only; no live upgrade authority.</p>"
    for row in r["candidates"]:
        body+="<section><h2>"+esc(row.get("package",{}).get("version","unknown"))+"</h2><p>"+esc(row["decision"])+"</p><pre>"+esc(json.dumps(row.get("diff_summary",{})))+"</pre></section>"
    body+="<p>Selected: "+esc((r["selected"] or {}).get("version","none"))+"</p>"
    fd,tmp=tempfile.mkstemp(dir=root,prefix=".report-")
    with os.fdopen(fd,"w") as f:f.write('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Tredven Assurance</title><style>body{font:16px system-ui;max-width:760px;margin:40px auto;padding:20px;color:#202725}section{border-top:1px solid #ccc;padding:12px 0}pre{white-space:pre-wrap}</style>'+body)
    os.replace(tmp,root/"report.html")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--workspace",type=P,required=True);p.add_argument("--core",type=P);sub=p.add_subparsers(dest="cmd",required=True)
    sub.add_parser("init");sub.add_parser("discover");sub.add_parser("corpus").add_argument("--allow-public-acquisition",action="store_true",required=True)
    replay=sub.add_parser("reproduce");replay.add_argument("--catalog",type=P,required=True);replay.add_argument("--locks",type=P,required=True);replay.add_argument("--allow-public-acquisition",action="store_true",required=True)
    cat=sub.add_parser("catalog");cat.add_argument("--evidence",type=P,required=True);cat.add_argument("--locks",type=P,required=True);cat.add_argument("--discover-public",action="store_true")
    look=sub.add_parser("lookup");look.add_argument("--catalog",type=P,required=True);look.add_argument("--sdk",required=True);look.add_argument("--zod",required=True);look.add_argument("--requires",nargs="+",required=True);look.add_argument("--allow-dependency-change",action="store_true")
    for name in ("protect","check","resolve"):
        s=sub.add_parser(name);s.add_argument("--entry",required=True)
        s.add_argument("--server" if name!="resolve" else "--candidates",type=P,required=True)
        if name=="protect":s.add_argument("--replay",type=P,required=True)
    a=p.parse_args();os.umask(0o077);root=a.workspace.absolute();core=w.core_path(a.core)
    if a.cmd=="init":ready();w.init(root);print("Workspace initialized.");return 0
    w.open_root(root);fd=lock(root)
    try:
        if a.cmd=="catalog":
            import market_catalog as market
            x=market.build(a.evidence,a.locks,core,a.discover_public)
            market.write_site(root/"catalog",x);print(json.dumps({"catalog_sha256":x["sha256"],"cases":len(x["cases"]),"discovery":x["discovery"]["status"]}));return 0 if x["discovery"]["status"]!="UNKNOWN" else 2
        if a.cmd=="lookup":
            import market_catalog as market
            x=market.verify_catalog(bounded_json(a.catalog));q=market.query(x,a.sdk,a.zod,a.requires,a.allow_dependency_change);print(json.dumps(q));return 0 if q["candidate"] else 2
        if a.cmd=="reproduce":
            import realworld
            r=realworld.run(root,core,bounded_json(a.catalog),a.locks)
            print(json.dumps({"reference_replay":r["reference_replay"],"sha256":r["sha256"]}))
            return 0 if r["reference_replay"]["exact_lock_matrix_equal"] else 2
        if a.cmd=="corpus":
            import realworld
            r=realworld.run(root,core)
            print(json.dumps({"schema":r["schema"],"latest":r["latest_observed"],"cases":r["cases"],"sha256":r["sha256"]}))
            return 0 if all(v["status"]=="OBSERVED" for v in r["observations"]) else 2
        if a.cmd=="discover":
            cfg=argparse.Namespace(public_lookup=False,core=core,containers=False,hermes_source=None,hermes_venv=None,hermes_config=[],repo=[])
            r=c.platform(cfg);w.atomic(root/"discovery.json",r);print(json.dumps({"assets":[{"tool":x["tool"],"installed":x.get("installed")} for x in r["assets"]],"mcp_profiles":r.get("mcp_structure",[]),"scope":"configured only; no discovered server auto-executed"}));return 0
        if a.cmd=="protect":
            x=baseline(root,a.server,a.entry,spec_load(a.replay));print("Baseline protected:",x["sha256"]);return 0
        w.atomic(root/"attempt.json",{"state":"RUNNING","started_utc":w.now()})
        try:
            if a.cmd=="resolve":
                paths=sorted(p for p in a.candidates.iterdir() if p.is_dir() and not p.is_symlink())
                if not 1<=len(paths)<=12:raise ValueError("1-12 explicit candidate directories required")
            else:paths=[a.server]
            r=evaluate(root,paths,a.entry,core,a.cmd=="resolve");render(root,r);w.atomic(root/"report.json",r);w.atomic(root/"attempt.json",{"state":"FINISHED","sha256":r["sha256"]});print(json.dumps(r));return r["ci_exit"]
        except Exception:
            w.atomic(root/"attempt.json",{"state":"FAILED"});raise
    finally:os.close(fd)
if __name__=="__main__":
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print("Assurance stopped:",type(exc).__name__,file=__import__("sys").stderr);raise SystemExit(2)
