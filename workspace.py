#!/usr/bin/env python3
"""Local-first product workspace. Existing Rust core owns GitHub and safety decisions."""
import argparse, datetime, hashlib, html, json, os, pathlib, re, stat, subprocess, tempfile, time
import compatibility as c
import discover as d
P=pathlib.Path
SCHEMA="tredven.upgrade.workspace.v1"
MAX=8*1024*1024
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def label(v):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}",v):raise ValueError("invalid environment id")
    return v
def private_dir(p):
    st=p.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise ValueError("private owned directory required")
    return p
def private_read(p):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_size>MAX:raise ValueError("unsafe state file")
        raw=f.read(MAX+1)
    if len(raw)>MAX:raise ValueError("state size")
    return json.loads(raw)
def atomic(p,obj):
    private_dir(p.parent)
    raw=json.dumps(obj,indent=2,ensure_ascii=True).encode()
    if len(raw)>MAX:raise ValueError("state size")
    fd,n=tempfile.mkstemp(dir=p.parent,prefix=".tmp-")
    try:
        with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(n,p)
    finally:
        if os.path.exists(n):os.unlink(n)
def init(root):
    root.mkdir(mode=0o700,parents=False,exist_ok=False)
    for n in ("environments","github","qualification"): (root/n).mkdir(mode=0o700)
    atomic(root/"workspace.json",{"schema":SCHEMA,"created_utc":now()})
def open_root(root):
    private_dir(root)
    for n in ("environments","github","qualification"):private_dir(root/n)
    if private_read(root/"workspace.json").get("schema")!=SCHEMA:raise ValueError("workspace schema")
    return root
def core_path(arg):
    p=(arg or P(__file__).resolve().parent/"bin/tredven-upstream").resolve()
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=d.PIN:raise ValueError("pinned core required")
    return p
def scan(root,args):
    env=label(args.environment); p=root/"environments"/env
    report=c.platform(args)
    if report.get("schema")!="tredven.upstream.compatibility-platform.v3" or report["production_ready"] or any(report["authority"].values()):raise ValueError("unsafe report")
    p.mkdir(mode=0o700,exist_ok=True);private_dir(p)
    previous=private_read(p/"latest.json") if (p/"latest.json").exists() else None
    if previous and previous.get("source")!="local collector":raise ValueError("remote environment cannot be overwritten by local scan")
    if previous and c.digest(previous["report"])!=previous["report_sha256"]:raise ValueError("previous inventory digest mismatch")
    old={v["asset_id"]:v for v in previous["report"]["assets"]} if previous else {}
    changes=[]
    for a in report["assets"]:
        b=old.get(a["asset_id"])
        if not b or (a.get("installed"),a.get("latest"),a.get("version_status"))!=(b.get("installed"),b.get("latest"),b.get("version_status")):
            changes.append({"asset_id":a["asset_id"],"before":{k:b.get(k) for k in ("installed","latest","version_status")} if b else None,"after":{k:a.get(k) for k in ("installed","latest","version_status")}})
    record={"environment":env,"observed_utc":report["observed_utc"],"report_sha256":c.digest(report),"report":report,"changes":changes,"previous_sha256":previous["report_sha256"] if previous else None,"source":"local collector"}
    stamp=time.time_ns();atomic(p/("scan-"+str(stamp)+".json"),record);atomic(p/"latest.json",record)
    return {"environment":env,"assets":len(report["assets"]),"candidates":len(report["compatibility_plans"]),"changes":len(changes),"report_sha256":record["report_sha256"]}
def github(root,core,action,repo_id=None,pr=None):
    argv=[str(core),"github-workspace",action,"--state",str(root/"github/state.json")]
    if action in ("select","deselect","review"):
        if not isinstance(repo_id,int) or repo_id<=0:raise ValueError("repository id required")
        if action=="deselect":argv[2]="select"
        argv+=["--id",str(repo_id)]
        if action in ("select","deselect"):argv+=["--on" if action=="select" else "--off"]
        if pr is not None and action=="review" and pr>0:argv+=["--pr",str(pr)]
    result=subprocess.run(argv,capture_output=True,text=True,timeout=90,env={**os.environ,"GH_PROMPT_DISABLED":"1"})
    if result.returncode!=0:raise ValueError("native GitHub workspace command failed")
    state=json.loads(result.stdout)
    if state.get("schema")!="tredven.upstream.github-workspace.v1" or state.get("provider_writes_authorized") is not False or state.get("automated_upgrade_authorized") is not False:raise ValueError("unsafe GitHub state")
    return state
def view(root,core):
    envs=[]
    for p in sorted((root/"environments").iterdir()):
        private_dir(p)
        if not (p/"latest.json").exists():continue
        r=private_read(p/"latest.json")
        if c.digest(r["report"])!=r["report_sha256"]:raise ValueError("inventory digest mismatch")
        if "host_context" in r and c.digest(r["host_context"])!=r.get("context_sha256"):raise ValueError("host context digest mismatch")
        if "public_security" in r and c.digest(r["public_security"])!=r.get("security_sha256"):raise ValueError("remote security digest mismatch")
        if r["report"]["production_ready"] or any(r["report"]["authority"].values()):raise ValueError("unsafe inventory")
        envs.append({**r,"scan_count":len(list(p.glob("scan-*.json")))})
    state=github(root,core,"list") if (root/"github/state.json").exists() else None
    repos=[]
    if state:
        for r in state["repositories"]:
            if r["selected"]:
                review=r.get("review")
                security_file=root/"github"/("security-"+str(r["id"])+".json")
                security=private_read(security_file) if security_file.exists() and not r["private"] else None
                if security and (not review or security.get("source_commit")!=review.get("source_commit") or security.get("repository_id")!=r["id"] or security.get("live_upgrade_authorized") is not False):security=None
                repos.append({"id":r["id"],"name":r["full_name"],"private":r["private"],"review":review,"security":security})
    quals=[]
    for f in sorted((root/"qualification").glob("*.json")):
        q=private_read(f)
        if q.get("schema")!="tredven.upgrade.isolated-npm-qualification.v1" or q.get("live_upgrade_authorized") is not False:raise ValueError("qualification schema")
        # Qualification is a separate lab observation, never an authorization or proof about this host.
        quals.append(q)
    result={"schema":SCHEMA,"environments":envs,"github":{"status":"OBSERVED_SNAPSHOT" if state else "NOT_CONNECTED","total":len(state["repositories"]) if state else None,"selected":repos,"synced_unix":state["synced_unix"] if state else None},"qualification":quals,"production_ready":False}
    if (root/"monitor-latest.json").exists():
        import beta_monitor
        result["monitor"]=beta_monitor.monitor_status(root)
    if (root/"engine-handoff.json").exists():
        handoff=private_read(root/"engine-handoff.json")
        if handoff.get("publish_authorized") is not False or handoff.get("live_upgrade_authorized") is not False:raise ValueError("unsafe handoff")
        result["engine_handoff"]=handoff
    if (root/"resolution-review.json").exists():
        import resolution_review
        result["resolution_review"]=resolution_review.display(root,envs)
    return result
def escape(x):return html.escape(str(x if x is not None else "UNKNOWN"))
def dashboard(data):
    h=escape
    envs=data["environments"]; repos=data["github"]["selected"]
    count=sum(len(e["report"]["assets"]) for e in envs)
    plans=sum(len(e["report"]["compatibility_plans"]) for e in envs)
    css="""*{box-sizing:border-box}body{margin:0;background:#f7f7f4;color:#20231f;font:14px system-ui,sans-serif}main{max-width:1240px;margin:auto;padding:38px 32px 70px}header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #dedfd8;padding:0 0 24px;margin-bottom:36px}.brand{font-size:13px;font-weight:750;letter-spacing:.13em}.mode{font-size:11px;border:1px solid #c8d5c7;padding:7px 11px;border-radius:4px;background:#edf2ea;color:#28583e}h1{font-size:43px;letter-spacing:-.05em;font-weight:550;line-height:1.1;margin:0 0 10px}h2{font-size:21px;letter-spacing:-.025em;font-weight:600;margin:35px 0 14px}p{color:#61665e;line-height:1.6}nav{display:flex;gap:20px;flex-wrap:wrap;border-bottom:1px solid #dedfd8;padding:12px 0}a{color:#315f45;text-decoration:none}a:hover{text-decoration:underline}.stats{display:grid;grid-template-columns:repeat(4,1fr);border-block:1px solid #dedfd8;margin:25px 0}.stat{padding:22px 15px;border-right:1px solid #dedfd8}.stat:last-child{border:0}.stat small{color:#656a61;font-size:12px}.stat b{display:block;font-size:36px;letter-spacing:-.04em;font-weight:550;margin-top:8px}.panel{background:#fff;border:1px solid #dedfd8;border-radius:8px;overflow:hidden;margin:12px 0}.pad{padding:17px 20px}table{width:100%;border-collapse:collapse;text-align:left}td,th{padding:12px 15px;border-bottom:1px solid #ecece7;vertical-align:top;overflow-wrap:anywhere}th{font-size:11px;letter-spacing:.05em;color:#666d63;text-transform:uppercase;background:#fafaf8}tr:last-child td{border-bottom:0}details{border-top:1px solid #ecece7;padding:12px 20px}summary{cursor:pointer;font-weight:600}.muted{font-size:12px;color:#6a7066}.warn{color:#98610e}.good{color:#326648}.scroll{overflow-x:auto}code{font-size:11px;overflow-wrap:anywhere}ul{padding-left:20px}li{margin:7px 0}footer{padding-top:30px;color:#71766c;font-size:12px}@media(max-width:660px){main{padding:22px 16px}h1{font-size:34px}.stats{grid-template-columns:repeat(2,1fr)}.stat{border-bottom:1px solid #dedfd8}td,th{padding:9px;font-size:12px}}"""
    parts=["<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>Tredven Upgrade — Workspace</title><style>"+css+"</style><main><header><span class='brand'>TREDVEN / UPGRADE</span><span class='mode'>READ-ONLY MAINTENANCE</span></header><h1>Maintenance workspace</h1><p>Technology inventory, upgrade evidence and compatibility plans. Local snapshots, not live authorization.</p><nav><a href='#inventory'>Inventory</a><a href='#updates'>Maintenance</a><a href='#github'>Repositories</a><a href='#qualification'>Qualification</a><a href='#coverage'>Coverage</a></nav><div class='stats'>"]
    for title,num in [("Environments",len(envs)),("Inventory entries",count),("Update candidates",plans),("Selected repositories",len(repos))]:
        parts.append(f"<div class='stat'><small>{title}</small><b>{num}</b></div>")
    parts.append("</div><h2 id='inventory'>Technology inventory</h2>")
    for e in envs:
        r=e["report"];parts.append(f"<div class='panel'><div class='pad'><b>{h(e['environment'])}</b><p class='muted'>{h(e['observed_utc'])} · {e['scan_count']} scans · {len(e['changes'])} changes in latest scan</p></div><div class='scroll'><table><thead><tr><th>Technology</th><th>Installed</th><th>Upstream</th><th>Observation</th></tr></thead><tbody>")
        for a in r["assets"]:parts.append("<tr>"+"".join(f"<td>{h(v)}</td>" for v in (a["tool"],a.get("installed"),a.get("latest"),a.get("version_status")))+"</tr>")
        parts.append("</tbody></table></div></div>")
    for e in envs:
        ctx=e.get("host_context")
        if ctx:
            parts.append("<h2>Installation profiles · "+h(e["environment"])+"</h2><div class='panel'><div class='scroll'><table><thead><tr><th>Profile</th><th>Installed</th><th>Upstream</th><th>Observation</th></tr></thead><tbody>")
            for v in ctx["installation_profiles"]:
                parts.append("<tr>"+"".join("<td>"+h(t)+"</td>" for t in (v["id"],v.get("installed"),v.get("latest"),v["status"]))+"</tr>")
            parts.append("</tbody></table></div><div class='pad'><p>Container inventory: "+h(e["report"]["container_runtime"]["status"])+" · "+(str(len(e["report"]["container_runtime"]["containers"]))+" observed entries." if e["report"]["container_runtime"]["status"]=="OBSERVED" else "count unknown.")+"</p>")
            for v in ctx["services"]:parts.append("<p>"+h(v["service"])+" · "+h(v["status"])+" · profile executable match: "+h(v.get("runtime_profile_executable_match"))+"</p>")
            if "public_security" in e:parts.append("<p>Public security cycle: "+h(e["public_security"]["status"])+"</p>")
            parts.append("<p class='muted'>Runtime protocol coverage: "+h(ctx["active_protocol_coverage"])+"</p></div></div>")
    if "monitor" in data:
        parts.append("<h2>Maintenance monitor</h2><div class='panel pad'><b>"+h(data["monitor"]["freshness"])+"</b><p>Last completed local cycle; observations only, not a deployment or authorization.</p></div>")
    for e in envs:
        b=e["report"].get("runtime_bindings",{})
        if b:
            parts.append("<div class='panel pad'><b>Runtime bindings · "+h(e["environment"])+"</b><p>"+h(b.get("active_integration_coverage"))+" integration coverage; "+str(len(b.get("bindings",[])))+" exact binding types observed.</p></div>")
    parts.append("<h2 id='updates'>Maintenance queue</h2>")
    for e in envs:
        for p in e["report"]["compatibility_plans"]:
            parts.append(f"<div class='panel'><div class='pad'><b>{h(p['tool'])} · {h(p['installed'])} → {h(p['candidate'])}</b><p class='warn'>{h(p['disposition'])} — {h(p['next_action'])}</p></div><details><summary>Compatibility evidence</summary><ul>")
            for k in p["checks"]:parts.append(f"<li>{h(k['id'])}: <b>{h(k['status'])}</b></li>")
            parts.append("</ul><p>Declared dependencies: "+h(", ".join(x["asset"] for x in p["impact"]["declared_dependencies"]) or "none observed")+"</p><p>Declared consumers: "+h(", ".join(x["asset"] for x in p["impact"]["declared_consumers"]) or "none observed")+"</p><p class='muted'>Candidate evidence <code>"+h(p["candidate_evidence_sha256"])+"</code></p></details></div>")
    if data.get("factory_review"):
        f=data["factory_review"]
        parts.append("<h2>Continuous resolution queue</h2><p>Evidence-bound review only. No live upgrade authority.</p>")
        for q in f["queue"]:
            parts.append("<div class='panel pad'><b>"+h(q["id"])+" · "+h(q["installed"])+" → "+h(q["candidate"])+"</b><p>"+h(q["disposition"])+" · "+h(q["qualification"]["status"])+"</p><p>"+h(q["reason"])+"</p></div>")
    if data.get("factory_review",{}).get("cross_stack_assurance"):
        a=data["factory_review"]["cross_stack_assurance"]
        parts.append("<h2>Cross-stack assurance · isolated fixture</h2><div class='panel pad'><p>"+h(a["scope"])+"</p>")
        for phase,v in a["phases"].items():parts.append("<p>"+h(phase)+" · "+h(v["replay"])+"</p>")
        parts.append("<p>APM: "+h(a["apm_drift"])+"</p><p>Breaking candidate: "+h(a["native"]["breaking"]["report"]["decision"])+" · fixed candidate: "+h(a["native"]["fixed"]["report"]["decision"])+"</p><p>"+h(a["selection"])+"</p></div>")
    if data.get("resolution_review"):
        r=data["resolution_review"]
        parts.append("<h2>Verified resolution review</h2><div class='panel pad'><b>"+h(r["qualification"])+"</b><p>"+h(r["binding_status"])+" · "+h(r["disposition"])+"</p><p>"+h(r["recommended"])+"</p></div>")
    parts.append("<h2 id='github'>GitHub repositories</h2><div class='panel pad'><p>"+h(data["github"]["status"])+" · authorized inventory: "+h(data["github"]["total"])+" · selection is explicit; snapshot is not current access proof.</p>")
    for r in repos:
        rev=r.get("review") or {};parts.append(f"<p><b>{h(r['name'])}</b> · {h(rev.get('decision'))} · {len(rev.get('manifest_paths',[]))} manifest paths</p>")
        sec=r.get("security")
        if sec:
            sr=sec.get("rust_report",{})
            parts.append("<p class='muted'>Security · "+h(sec["status"])+" · "+h(sr.get("decision",sr.get("status")))+" · "+h(sec["scope"])+"</p>")
    parts.append("</div><h2 id='qualification'>Isolated qualification</h2><div class='panel pad'>")
    if not data["qualification"]:parts.append("<p>No isolated execution evidence yet.</p>")
    for q in data["qualification"]:
        parts.append(f"<p><b>npm {h(q.get('baseline'))} → {h(q.get('candidate'))}</b> · {h(q.get('result'))} · {h(q.get('scope'))}</p><ul>")
        for k,v in q.get("checks",{}).items():parts.append(f"<li>{h(k)}: {h(v)}</li>")
        parts.append("</ul>")
    parts.append("</div><h2 id='coverage'>Coverage &amp; limitations</h2>")
    for e in envs:
        parts.append("<div class='panel pad'><b>"+h(e["environment"])+"</b><ul>")
        for g in e["report"]["coverage_gaps"]:parts.append("<li>"+h(g)+"</li>")
        parts.append("</ul></div>")
    if "engine_handoff" in data:
        a=data["engine_handoff"]
        parts.append("<h2>Upgrade Engine handoff</h2><div class='panel pad'><b>"+h(a["status"])+"</b><p>"+h(a.get("reason"))+" · No publication or host upgrade authority.</p></div>")
    parts.append("<footer>Local exported snapshot. No external scripts, telemetry, automatic upgrades or production approval.</footer></main></html>")
    return "".join(parts)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--workspace",type=P,required=True);p.add_argument("--core",type=P)
    subs=p.add_subparsers(dest="action",required=True)
    subs.add_parser("init");subs.add_parser("status");subs.add_parser("dashboard")
    g=subs.add_parser("github");g.add_argument("operation",choices=["discover","list","select","deselect","review"]);g.add_argument("--id",type=int);g.add_argument("--pr",type=int)
    for name in ("scan","watch"):
        s=subs.add_parser(name);s.add_argument("--environment",required=True);s.add_argument("--public-lookup",action="store_true");s.add_argument("--hermes-source",type=P);s.add_argument("--hermes-venv",type=P);s.add_argument("--hermes-config",type=P,action="append",default=[]);s.add_argument("--repo",type=P,action="append",default=[]);s.add_argument("--containers",action="store_true")
        if name=="watch":s.add_argument("--interval",type=int,default=60);s.add_argument("--cycles",type=int,default=2)
    args=p.parse_args();os.umask(0o077)
    root=args.workspace.absolute()
    if args.action=="init":init(root);print("Workspace initialized");return
    open_root(root);args.core=core_path(args.core)
    if args.action in ("scan","watch"):
        if len(args.repo)>20 or len(args.hermes_config)>10:raise ValueError("scope limit")
        if args.action=="scan":print(json.dumps(scan(root,args)));return
        if not 60<=args.interval<=86400 or not 1<=args.cycles<=100:raise ValueError("bounded monitoring only")
        for i in range(args.cycles):
            if i:time.sleep(args.interval)
            print(json.dumps(scan(root,args)),flush=True)
        return
    if args.action=="github":
        x=github(root,args.core,args.operation,args.id,args.pr)
        print(json.dumps({"total":len(x["repositories"]),"selected":[{"id":r["id"],"name":r["full_name"],"decision":(r.get("review") or {}).get("decision")} for r in x["repositories"] if r["selected"]]}));return
    data=view(root,args.core)
    if args.action=="status":print(json.dumps(data,indent=2));return
    print(dashboard(data))
if __name__=="__main__":main()
