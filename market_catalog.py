"""Verified public evidence catalogue. Discovery is metadata only, never code execution."""
import argparse,html,json,os,pathlib,re,shutil,urllib.parse
import compatibility as c
import discover as d
import realworld as r
import workspace as w
P=pathlib.Path
APP=P(__file__).resolve().parent
SCHEMA="tredven.assurance.catalog.v1"
def verify_evidence(evidence,locks,core):
    x=w.private_read(evidence/"report.json");a=w.private_read(evidence/"attempt.json")
    if x["schema"]!="tredven.assurance.public-corpus.v1" or x["sha256"]!=c.digest({k:v for k,v in x.items() if k!="sha256"}) or a["state"]!="FINISHED" or a["sha256"]!=x["sha256"]:raise ValueError("incomplete or altered corpus")
    if x["live_upgrade_authorized"] is not False or x["production_ready"] is not False or x["core_sha256"]!=r.sha(core) or x["probe_sha256"]!=r.sha(APP/"sdk-realworld-probe.mjs"):raise ValueError("source or authority mismatch")
    seen=set()
    for row in x["observations"]:
        v,z=row["sdk"],row["zod"]
        if not d.stable(v) or z not in (r.Z3,r.Z4) or (v,z) in seen or row["status"]!="OBSERVED" or not r.valid_result(row["cases"]):raise ValueError("incomplete/duplicate profile")
        seen.add((v,z))
        p=locks/(v+"-z"+z+".json")
        if r.sha(p)!=row["lock_sha256"] or r.verify_lock(p,v,z)!=row["dependencies"]:raise ValueError("lock provenance mismatch")
    if r.gates(core,r.decision(x["observations"]))!=x["cases"]:raise ValueError("decision drift")
    return x
def seal(x):return {**x,"sha256":c.digest(x)}
def verify_catalog(x):
    if x.get("schema")!=SCHEMA or x.get("sha256")!=c.digest({k:v for k,v in x.items() if k!="sha256"}) or x.get("live_upgrade_authorized") is not False:raise ValueError("invalid catalogue")
    if set(a["id"] for a in x["cases"])!=set(r.CASES):raise ValueError("case identity")
    seen=set()
    for p in x["profiles"]:
        k=(p["sdk"],p["zod"])
        if k in seen or not d.stable(k[0]) or not k[0].startswith("1.") or k[1] not in (r.Z3,r.Z4) or not re.fullmatch("[a-f0-9]{64}",p["lock_sha256"]) or set(p["checks"])!=set(r.CASES) or any(type(v) is not bool for v in p["checks"].values()):raise ValueError("profile identity")
        seen.add(k)
    return x
def query(x,sdk,zod,required,allow_dependency_change=False):
    verify_catalog(x)
    required=set(required)
    if not required or not required<=set(r.CASES):raise ValueError("select known required checks")
    baseline=next((p for p in x["profiles"] if (p["sdk"],p["zod"])==(sdk,zod)),None)
    result={"baseline":{"sdk":sdk,"zod":zod},"required":sorted(required),"candidate":None,"status":"UNKNOWN_BASELINE","preserved":[],"live_upgrade_authorized":False}
    if not baseline:return result
    preserve={k for k,v in baseline["checks"].items() if v}
    result["preserved"]=sorted(preserve);needed=required|preserve
    eligible=[p for p in x["profiles"] if d.stable(p["sdk"])>=d.stable(sdk) and (p["zod"]==zod or allow_dependency_change) and all(p["checks"][k] for k in needed)]
    if not eligible:return {**result,"status":"NO_TESTED_COMBINATION"}
    chosen=min(eligible,key=lambda p:(p["zod"]!=zod,d.stable(p["sdk"])))
    return {**result,"status":"KEEP_TESTED_PROFILE" if chosen==baseline else "SCOPED_ALTERNATIVE_FOR_REVIEW","candidate":{"sdk":chosen["sdk"],"zod":chosen["zod"],"lock_sha256":chosen["lock_sha256"]},"other_failed_checks":sorted(k for k,v in chosen["checks"].items() if not v),"scope":"required checks plus all previously passing checks; no security or production approval"}
def discover_public():
    # Only official SDK repository. Page window is a sample, not complete coverage.
    url="https://api.github.com/repos/modelcontextprotocol/typescript-sdk/issues?state=all&sort=updated&direction=desc&per_page=50"
    items=r.fetch(url)
    if not isinstance(items,list) or len(items)>50:raise ValueError("issue window")
    rows=[]
    for a in items:
        if "pull_request" in a:continue
        id=str(a["number"]);title=a["title"]
        if not id.isdecimal() or len(id)>10 or not isinstance(title,str):raise ValueError("issue identity")
        if a["html_url"]!="https://github.com/modelcontextprotocol/typescript-sdk/issues/"+id:raise ValueError("source identity")
        match=id in r.CASES
        relevant=bool(re.search(r"schema|regression|compatib|tool[s /]|prompt|zod|version|import|export",title,re.I))
        if match or relevant:rows.append({"id":id,"title":title[:200],"source":a["html_url"],"updated_utc":a["updated_at"],"status":"KNOWN_PROBE" if match else "NEEDS_REPRODUCTION_REVIEW"})
    return {"status":"OBSERVED","source":url,"scanned":len(items),"issues":rows,"coverage":"one recent page; title heuristic; unknown cases not executed"}
def build(evidence,locks,core,public=False):
    x=verify_evidence(evidence,locks,core)
    profiles=[{"sdk":v["sdk"],"zod":v["zod"],"checks":{k:v["cases"][k]["pass"] for k in r.CASES},"lock_sha256":v["lock_sha256"]} for v in x["observations"]]
    cases=[{k:a[k] for k in ("id","title","source","baseline","status","alternative")} for a in x["cases"]]
    try:discovery=discover_public() if public else {"status":"NOT_REQUESTED","issues":[]}
    except (OSError,ValueError,KeyError,TypeError):discovery={"status":"UNKNOWN","issues":[],"coverage":"metadata acquisition unsuccessful"}
    return seal({"schema":SCHEMA,"observed_utc":x["observed_utc"],"source_receipt_sha256":x["sha256"],"probe_sha256":x["probe_sha256"],"runtime":x["node_version"],"profiles":profiles,"cases":cases,"discovery":discovery,"live_upgrade_authorized":False,"production_ready":False,"scope":"public SDK v1 and fixed Zod profiles; local observations only; no live client assurance"})
def write_site(out,x):
    verify_catalog(x);out.mkdir(mode=0o700,exist_ok=False)
    w.atomic(out/"catalog.json",x)
    esc=lambda v:html.escape(str(v),quote=True)
    labels={"OBSERVED_VERSION_ALTERNATIVE":"Tested SDK alternative","OBSERVED_DEPENDENCY_ALTERNATIVE":"Tested dependency alternative","REPRODUCED_NO_TESTED_FIX":"No tested fix","NOT_REPRODUCED":"Not reproduced","UNKNOWN_BASELINE":"Unknown"}
    def page(title,description,body,prefix=""):
        return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\';style-src \'self\';script-src \'self\'"><title>'+esc(title)+' | Tredven Assurance</title><meta name="description" content="'+esc(description)+'"><link rel="stylesheet" href="'+prefix+'style.css"><script src="'+prefix+'search.js" defer></script></head><body><header><a href="'+prefix+'index.html" class="brand">TREDVEN<span> / ASSURANCE</span></a><a href="'+prefix+'guide.html">Quickstart</a></header><main>'+body+'</main><footer>Local evidence preview · No deployment authority · '+esc(x["observed_utc"][:10])+'</footer></body></html>'
    cards=[]
    for a in x["cases"]:
        id=a["id"];status=labels[a["status"]];base=a["baseline"];alt=a["alternative"]
        cards.append('<article data-case><div class="eyebrow">SDK ISSUE #'+id+'</div><h2><a href="issues/'+id+'.html">'+esc(a["title"])+'</a></h2><p>'+esc(status)+'</p><p class="sub">SDK '+esc(base["sdk"])+' · Zod '+esc(base["zod"])+'</p></article>')
    hero='<div class="hero"><div class="eyebrow">OPEN-SOURCE RELEASE CANDIDATE</div><h1>Know what breaks.<br>Before you upgrade.</h1><p>Reproduce documented MCP SDK compatibility failures and inspect tested alternatives. No model API or account required.</p><a class="cta" href="guide.html">Run locally</a></div>'
    stats='<div class="stats"><div><strong>'+str(len(x["cases"]))+'</strong> documented issues</div><div><strong>'+str(len(x["profiles"]))+'</strong> tested profiles</div><div><strong>'+str(sum(a["alternative"] is not None for a in x["cases"]))+'</strong> scoped alternatives</div></div>'
    queue=x["discovery"].get("issues",[])
    queuehtml='<section><h2>Upstream watch</h2><p>New candidates are not qualified. Recent public metadata, not a comprehensive incident feed.</p>'+''.join('<p><a href="'+esc(a["source"])+'">#'+esc(a["id"])+' '+esc(a["title"])+'</a> · '+esc(a["status"])+'</p>' for a in queue)+'</section>'
    index=hero+stats+'<section><h2>Find a compatibility issue</h2><label for="search">Search issue, version or symptom</label><input type="search" id="search" placeholder="e.g. 2464, Zod, prompt"><p id="count" aria-live="polite">'+str(len(cards))+' results</p><div class="cards">'+''.join(cards)+'</div></section><section><h2>Evidence and limits</h2><p>Tested on '+esc(x["runtime"])+'. Results refer to individual probes, not complete applications. Unobserved combinations are unknown. This preview does not publish or install anything.</p><a href="catalog.json">Machine-readable catalogue</a></section>'
    index+=queuehtml
    (out/"index.html").write_text(page("MCP compatibility intelligence","Reproducible MCP SDK compatibility observations and scoped alternatives.",index))
    issues=out/"issues";issues.mkdir(mode=0o700)
    for a in x["cases"]:
        id=a["id"];alt=a["alternative"];base=a["baseline"]
        table='<table><thead><tr><th>SDK</th><th>Zod</th><th>Probe</th></tr></thead><tbody>'+''.join('<tr><td>'+esc(p["sdk"])+'</td><td>'+esc(p["zod"])+'</td><td>'+("PASS" if p["checks"][id] else "FAIL")+'</td></tr>' for p in x["profiles"])+'</tbody></table>'
        cmd='./tredven-assurance --workspace ./state lookup --catalog ./catalog.json --sdk '+base["sdk"]+' --zod '+base["zod"]+' --requires '+id
        body='<a href="../index.html">All issues</a><div class="eyebrow">SDK ISSUE #'+id+'</div><h1>'+esc(a["title"])+'</h1><p>'+esc(labels[a["status"]])+'</p><p>Reported profile: SDK '+esc(base["sdk"])+' / Zod '+esc(base["zod"])+'</p><p>Observed alternative: '+esc((alt["sdk"]+" / "+alt["zod"]) if alt else "None established")+'</p><p><a href="'+esc(a["source"])+'">Original upstream issue</a></p><h2>Measured profiles</h2>'+table+'<h2>Check your requirements locally</h2><pre>'+esc(cmd)+'</pre><p>Dependency changes require explicit opt-in. A passing individual probe does not prove whole-stack compatibility or security.</p><p>Evidence SHA-256: <code>'+esc(x["source_receipt_sha256"])+'</code></p>'
        (issues/(id+".html")).write_text(page(a["title"],"Observed MCP SDK issue "+id+" across tested SDK and Zod combinations.",body,"../"))
    guide='<h1>Get started locally</h1><p>Linux x86-64, Python 3.11+, Node 22.19+, npm, bubblewrap with unprivileged namespaces. Review the archive and SHA-256 before running.</p><h2>Install and discover</h2><pre>./install.sh\n./tredven-assurance --workspace ./state init\n./tredven-assurance --workspace ./state discover</pre><h2>Reproduce the public SDK corpus</h2><pre>./tredven-assurance --workspace ./state corpus --allow-public-acquisition</pre><h2>Inspect a tested combination</h2><pre>./tredven-assurance --workspace ./state lookup --catalog ./catalog.json --sdk 1.25.0 --zod 3.25.76 --requires 1302</pre><p>Use the included README for disposable stdio projects. No arbitrary public code, OAuth, remote MCP or production changes. A package release is not yet public.</p>'
    (out/"guide.html").write_text(page("Local quickstart","Install and use the local Tredven Assurance release candidate.",guide))
    shutil.copyfile(APP/"market-site.css",out/"style.css");shutil.copyfile(APP/"market-search.js",out/"search.js")
    (out/"robots.txt").write_text("User-agent: *\nDisallow: /\n") # review preview, no crawl until authorized
    return out
