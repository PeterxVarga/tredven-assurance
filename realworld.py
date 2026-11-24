"""Curated public SDK compatibility corpus. No arbitrary registry execution or publication."""
import hashlib,html,json,os,pathlib,re,resource,shutil,subprocess,tempfile,time,urllib.request,urllib.parse
import compatibility as c
import discover as d
import workspace as w
P=pathlib.Path
APP=P(__file__).resolve().parent
PACKAGE="@modelcontextprotocol/sdk"
VERSIONS=("1.21.0","1.24.3","1.25.0","1.25.3","1.29.0","1.30.0")
Z3="3.25.76";Z4="4.4.3"
CASES={
"1302":("JSON-RPC exports","1.25.0",Z3),
"1376":("Global fetch identity","1.25.0",Z3),
"1960":("RegisteredTool.update with ZodObject","1.29.0",Z3),
"1869":("Prompt with omitted optional arguments","1.29.0",Z3),
"1956":("Tool validation error semantics","1.29.0",Z3),
"2084":("JSON Schema 2020-12 input/output dialect","1.29.0",Z4),
"2636":("Closed input schema after Zod migration","1.29.0",Z4),
"2464":("Date in output schema blocks tools/list","1.29.0",Z4),
"2627":("registerTool ZodObject input schema","1.21.0",Z3),
"1864":("Tool icon metadata","1.29.0",Z3)}
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def fetch(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    req=urllib.request.Request(url,headers={"User-Agent":"Tredven-Assurance-public-corpus","Accept":"application/json"})
    with opener.open(req,timeout=15) as f:raw=f.read(w.MAX+1)
    if len(raw)>w.MAX:raise ValueError("metadata limit")
    return json.loads(raw)
def verify_lock(path,version,zod):
    data=json.loads(path.read_text());packages=data["packages"]
    if len(packages)>300:raise ValueError("lock package limit")
    for name,row in packages.items():
        if not name:continue
        u=urllib.parse.urlsplit(row.get("resolved",""))
        if u.scheme!="https" or u.hostname!="registry.npmjs.org" or u.username or u.password or u.port is not None or not row.get("integrity","").startswith("sha512-") or row.get("link"):raise ValueError("non-public/unpinned dependency")
    for name,v in ((PACKAGE,version),("zod",zod)):
        if packages["node_modules/"+name]["version"]!=v:raise ValueError("root identity mismatch")
    return len(packages)-1
def valid_result(x):
    return isinstance(x,dict) and set(x)==set(CASES) and all(isinstance(row,dict) and type(row.get("pass")) is bool for row in x.values())
def runner(out,version,zod,node,npm,bwrap,locked=None):
    key=version+"-z"+zod;p=out/"matrix"/key;p.mkdir(mode=0o700)
    shutil.copyfile(APP/"sdk-realworld-probe.mjs",p/"probe.mjs")
    w.atomic(p/"package.json",{"private":True,"type":"module","dependencies":{PACKAGE:version,"zod":zod}})
    env={"HOME":str(out/"empty-home"),"PATH":str(node.parent)+":/usr/bin:/bin","LANG":"C","npm_config_cache":str(out/"cache"),"npm_config_registry":"https://registry.npmjs.org","npm_config_userconfig":"/dev/null","npm_config_globalconfig":str(out/"empty-home"/"global.npmrc")}
    t=time.monotonic()
    flags=["--ignore-scripts","--no-audit","--no-fund","--loglevel=error"]
    with (out/(key+".install.log")).open("wb") as log:
        if locked is None:
            subprocess.run([str(npm),"install","--package-lock-only",*flags],cwd=p,env=env,stdout=log,stderr=log,timeout=90,check=True)
        else:
            shutil.copyfile(locked,p/"package-lock.json")
        count=verify_lock(p/"package-lock.json",version,zod)
        subprocess.run([str(npm),"ci",*flags],cwd=p,env=env,stdout=log,stderr=log,timeout=90,check=True)
    cmd=[bwrap,"--unshare-all","--die-with-parent","--new-session","--clearenv","--ro-bind","/usr","/usr","--ro-bind","/lib64","/lib64","--symlink","usr/bin","/bin","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/opt","--ro-bind",str(node),"/opt/node","--ro-bind",str(p),"/lab","--setenv","HOME","/tmp","--setenv","PATH","/opt:/usr/bin","--chdir","/lab","--","/opt/node","/lab/probe.mjs"]
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(w.MAX,w.MAX));resource.setrlimit(resource.RLIMIT_CPU,(30,35))
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        probe_start=time.monotonic()
        r=subprocess.run(cmd,stdout=stdout,stderr=stderr,timeout=45,preexec_fn=limits)
        runtime_ms=round((time.monotonic()-probe_start)*1000)
        stdout.seek(0);raw=stdout.read(w.MAX+1)
        stderr.seek(0);err=stderr.read(w.MAX)
    if r.returncode or len(raw)>w.MAX:raise ValueError("probe failed")
    obs=json.loads(raw)
    if not valid_result(obs):raise ValueError("incomplete probe")
    return {"sdk":version,"zod":zod,"status":"OBSERVED","cases":obs,"lock_sha256":sha(p/"package-lock.json"),"dependencies":count,"probe_ms":runtime_ms,"total_ms":round((time.monotonic()-t)*1000)}
def decision(rows):
    by={(r["sdk"],r["zod"]):r for r in rows if r["status"]=="OBSERVED"}
    result=[]
    for id,(title,v,z) in CASES.items():
        baseline=by.get((v,z))
        same=[r for (rv,rz),r in by.items() if rz==z and d.stable(rv)>=d.stable(v) and r["cases"][id]["pass"]]
        alternate=[r for (rv,rz),r in by.items() if rv==v and rz!=z and r["cases"][id]["pass"]]
        pick=max(same,key=lambda r:d.stable(r["sdk"])) if same else None
        state="UNKNOWN_BASELINE" if not baseline else "NOT_REPRODUCED" if baseline["cases"][id]["pass"] else "OBSERVED_VERSION_ALTERNATIVE" if pick else "OBSERVED_DEPENDENCY_ALTERNATIVE" if alternate else "REPRODUCED_NO_TESTED_FIX"
        chosen=pick if state=="OBSERVED_VERSION_ALTERNATIVE" else alternate[0] if state=="OBSERVED_DEPENDENCY_ALTERNATIVE" else None
        result.append({"id":id,"title":title,"source":"https://github.com/modelcontextprotocol/typescript-sdk/issues/"+id,"baseline":{"sdk":v,"zod":z},"status":state,"alternative":{"sdk":chosen["sdk"],"zod":chosen["zod"]} if chosen else None,"scope":"specific probe only; not general integration or security approval","live_upgrade_authorized":False})
    return result
def native_gate(core,case,profile,passed):
    tag=lambda x:x["sdk"]+"+zod."+x["zod"]
    inp={"schema":"tredven.upstream.preflight-input.v1","project":"mcp-sdk-issue-"+case["id"],"baseline":{"tag":tag(case["baseline"])},"candidate":{"tag":tag(profile)},"compare_coverage":"unknown","changed_paths":[],"checks":[{"name":"issue_probe","status":"passed" if passed else "failed"},{"name":"runtime_compatibility","status":"not_run"}]}
    p=subprocess.run([str(core),"inspect","--stdin"],input=json.dumps(inp),capture_output=True,text=True,timeout=5)
    r=json.loads(p.stdout)
    if p.returncode not in (0,2) or r.get("project")!=inp["project"] or r.get("baseline_tag")!=tag(case["baseline"]) or r.get("candidate_tag")!=tag(profile) or r.get("decision")!=("UNKNOWN" if passed else "BLOCKED") or r.get("production_ready") is not False or not r.get("authority") or any(x is not False for x in r["authority"].values()):raise ValueError("native gate")
    return {"input_sha256":c.digest(inp),"report":r}
def gates(core,decisions):
    for a in decisions:
        if a["status"]=="UNKNOWN_BASELINE":continue
        a["baseline_gate"]=native_gate(core,a,a["baseline"],a["status"]=="NOT_REPRODUCED")
        if a["alternative"]:a["alternative_gate"]=native_gate(core,a,a["alternative"],True)
    return decisions
def run(root,core,reference=None,locks=None):
    if (reference is None)!=(locks is None):raise ValueError("reference and locks required together")
    locked={}
    if reference is not None:
        import market_catalog as market
        market.verify_catalog(reference)
        if reference["probe_sha256"]!=sha(APP/"sdk-realworld-probe.mjs"):raise ValueError("reference probe drift")
        for profile in reference["profiles"]:
            v,z=profile["sdk"],profile["zod"]
            path=locks/(v+"-z"+z+".json")
            if sha(path)!=profile["lock_sha256"]:raise ValueError("reference lock drift")
            verify_lock(path,v,z);locked[v,z]=path
        if not 1<=len(locked)<=12:raise ValueError("reference profile limit")
    out=root/"public-corpus";out.mkdir(mode=0o700,exist_ok=False)
    for n in ("matrix","cache","empty-home"):(out/n).mkdir(mode=0o700)
    node=P(shutil.which("node") or "/missing").resolve(strict=True)
    npm=P(shutil.which("npm") or "/missing").resolve(strict=True);box=shutil.which("bwrap")
    if not box:raise ValueError("bubblewrap required")
    if reference is None:
        meta=fetch("https://registry.npmjs.org/@modelcontextprotocol%2Fsdk/latest");latest=meta.get("version")
        if meta.get("name")!=PACKAGE or not d.stable(latest) or not latest.startswith("1.") or d.stable(latest)<(1,30,0):raise ValueError("unsupported latest SDK; v2 requires separate qualification")
        pairs=list(dict.fromkeys([(v,Z3) for v in VERSIONS[:5]]+[("1.29.0",Z4),("1.30.0",Z4),(latest,Z3),(latest,Z4)]))
    else:
        pairs=list(locked)
        latest=max((v for v,z in pairs),key=d.stable)
    start=time.monotonic();rows=[]
    w.atomic(out/"attempt.json",{"state":"RUNNING","started_utc":w.now()})
    for v,z in pairs:
        try:r=runner(out,v,z,node,npm,box,locked.get((v,z)))
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:r={"sdk":v,"zod":z,"status":"UNKNOWN","reason":type(exc).__name__}
        rows.append(r);w.atomic(out/"observations.json",rows)
    decisions=gates(core,decision(rows))
    result={"schema":"tredven.assurance.public-corpus.v1","observed_utc":w.now(),"latest_observed":latest,"probe_sha256":sha(APP/"sdk-realworld-probe.mjs"),"node_sha256":sha(node),"node_version":subprocess.check_output([str(node),"--version"],text=True,timeout=5).strip(),"core_sha256":sha(core),"observations":rows,"cases":decisions,"elapsed_ms":round((time.monotonic()-start)*1000),"scope":"public SDK packages only; independently authored in-memory MCP probes; no arbitrary issue code or live provider calls","manual_baseline_measured":False,"external_customer_validated":False,"production_ready":False,"live_upgrade_authorized":False}
    if reference is not None:
        expected={(p["sdk"],p["zod"]):p for p in reference["profiles"]}
        equal=all(p["status"]=="OBSERVED" and p["lock_sha256"]==expected[p["sdk"],p["zod"]]["lock_sha256"] and {k:v["pass"] for k,v in p["cases"].items()}==expected[p["sdk"],p["zod"]]["checks"] for p in rows)
        result["reference_replay"]={"catalog_sha256":reference["sha256"],"exact_lock_matrix_equal":equal,"scope":"reference lockfiles and probe outcomes; runtime identity separately recorded"}
    result["sha256"]=c.digest(result)
    w.atomic(out/"report.json",result)
    # Publishable view: no host path, raw logs, issue body or private environment.
    esc=lambda x:html.escape(str(x))
    body='<h1>Tredven Assurance · SDK compatibility</h1><p>Public package lab evidence, not deployment advice.</p><table><tr><th>Issue</th><th>Result</th><th>Tested alternative</th></tr>'
    for a in decisions:
        body+='<tr><td><a href="'+esc(a["source"])+'">#'+esc(a["id"])+'</a> '+esc(a["title"])+'</td><td>'+esc(a["status"])+'</td><td>'+esc(a["alternative"] or "—")+'</td></tr>'
    body+="</table><h2>Observed compatibility matrix</h2><p>PASS is the individual probe only. FAIL is a failed expectation, not necessarily a new regression.</p><table><tr><th>SDK / Zod</th>"+"".join("<th>#"+esc(k)+"</th>" for k in CASES)+"</tr>"
    for row in rows:
        body+="<tr><td>"+esc(row["sdk"]+" / "+row["zod"])+"</td>"+"".join("<td>"+("PASS" if row["cases"][k]["pass"] else "FAIL")+"</td>" if row["status"]=="OBSERVED" else "<td>UNKNOWN</td>" for k in CASES)+"</tr>"
    body+="</table><p>Local automated run: "+esc(result["elapsed_ms"])+" ms. Human baseline and external customer value not measured.</p>"
    (out/"report.html").write_text('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>SDK compatibility</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:16px}td,th{padding:12px;text-align:left;border-bottom:1px solid #ddd}table{border-collapse:collapse;width:100%}</style>'+body)
    w.atomic(out/"attempt.json",{"state":"FINISHED","sha256":result["sha256"]})
    return result
