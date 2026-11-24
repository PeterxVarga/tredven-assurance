"""Bounded same-UID process evidence; never serialize arguments, paths, PIDs or env."""
import os,pathlib,shutil
P=pathlib.Path
def known_entries(hermes_venv=None,hermes_source=None):
    entries={}
    for name in ("pi","hermes","opencode","codex"):
        p=shutil.which(name)
        if p:
            try:
                entries[str(P(p).resolve(strict=True))]=name
                entries[str(P(p).absolute())]=name
            except OSError:pass
    if hermes_venv:
        for name in ("hermes","hermes-agent"):
            p=hermes_venv/"bin"/name
            if p.is_file():entries[str(p)]= "hermes";entries[str(p.resolve())]="hermes"
    if hermes_source:
        p=hermes_source/"hermes_cli/main.py"
        if p.is_file():entries[str(p.resolve())]="hermes"
    return entries
def scan(entries,proc=P("/proc")):
    observed={};unreadable=0;seen=0
    for p in proc.iterdir():
        if not p.name.isdecimal():continue
        if seen>=20000:break
        seen+=1
        try:
            if p.stat().st_uid!=os.getuid():continue
            exe=os.readlink(p/"exe")
            # Never inspect argv of unrelated executables.
            tool=entries.get(exe);how="EXACT_EXECUTABLE"
            if not tool and P(exe).name in ("node","nodejs","python","python3","python3.11","python3.12","python3.13","python3.14"):
                with (p/"cmdline").open("rb") as f:raw=f.read(8192)
                argv=raw.split(b"\0",3)
                # Only a literal first script argument can bind; no general argv search.
                if len(argv)>=3:
                    path=os.fsdecode(argv[1])
                    tool=entries.get(path)
                    how="EXACT_SCRIPT_ARGUMENT"
            if not tool:continue
            stat=(p/"stat").read_text().rsplit(")",1)[1].split()
            if len(stat)<20:continue
            observed[int(p.name)]={"tool":tool,"binding":how,"parent":int(stat[1])}
        except (OSError,UnicodeError,ValueError,IndexError):unreadable+=1
    counts={}
    for v in observed.values():
        key=(v["tool"],v["binding"]);counts[key]=counts.get(key,0)+1
    edges=set()
    for v in observed.values():
        parent=observed.get(v["parent"])
        if parent and parent["tool"]!=v["tool"]:edges.add((parent["tool"],v["tool"]))
    return {"status":"OBSERVED","scope":"same UID, exact known entries only; no env read; no network or model calls",
            "bindings":[{"tool":k[0],"binding":k[1],"count":n,"running_version":None} for k,n in sorted(counts.items())],
            "process_edges":[{"from":a,"to":b,"kind":"observed_parent_child","runtime_protocol_verified":False} for a,b in sorted(edges)],
            "unreadable_or_exited":unreadable,"limit_reached":seen>=20000,
            "active_integration_coverage":"UNKNOWN"}
