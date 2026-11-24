#!/bin/bash
set -euo pipefail
umask 077
app=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(realpath -m -- "${1:?new demo directory required}")
test ! -e "$root"; mkdir -m 700 "$root"
mkdir -m 700 "$root/baseline" "$root/candidates" "$root/candidates/v110" "$root/candidates/v111" "$root/home"
python3 -B - "$root" "$app/oss-contract-fixture/server.mjs" <<'PY'
import pathlib,sys,json
p=pathlib.Path(sys.argv[1]);source=pathlib.Path(sys.argv[2]).read_text()
for rel,v,variant in [("baseline","1.0.0","baseline"),("candidates/v110","1.1.0","breaking"),("candidates/v111","1.1.1","fixed")]:
 q=p/rel
 (q/"package.json").write_text(json.dumps({"name":"example-mcp","version":v,"type":"module"}))
 (q/"server.mjs").write_text(source.replace("const v=process.argv[2]==='selected'?JSON.parse(readFileSync('/fixture/selected.json','utf8')).variant:process.argv[2];","const v="+json.dumps(variant)+";"))
(p/"replay.json").write_text(json.dumps({"tool":"read_record","arguments":{"id":"test"},"expected_content":[{"type":"text","text":"record:test"}]}))
PY
for p in "$root/baseline" "$root/candidates/v110" "$root/candidates/v111"; do cp -a "$app/oss-contract-fixture/node_modules" "$p/"; done
# Fake customer profile; never modify the real user's home.
export HOME="$root/home"; mkdir -p "$HOME/.config/opencode"; printf '{"mcp":{"example":{"type":"local","command":["node","server.mjs"]}}}\n' > "$HOME/.config/opencode/opencode.json"
cli(){ "$app/tredven-assurance" --workspace "$root/state" "$@"; }
cli init
cli discover > "$root/discovery.json"
cli protect --server "$root/baseline" --entry server.mjs --replay "$root/replay.json"
rc=0; cli check --server "$root/candidates/v110" --entry server.mjs > "$root/breaking.json" || rc=$?
test "$rc" = 1
cli resolve --candidates "$root/candidates" --entry server.mjs > "$root/resolution.json"
python3 -B - "$root" <<'PY'
import pathlib,sys,json
p=pathlib.Path(sys.argv[1]);d=json.loads((p/"discovery.json").read_text());b=json.loads((p/"breaking.json").read_text());r=json.loads((p/"resolution.json").read_text())
assert any(a["owner"]=="opencode-json" and len(a["servers"])==1 for a in d["mcp_profiles"])
assert b["decision"]=="BLOCKED" and b["ci_exit"]==1
assert r["selected"]["version"]=="1.1.1" and r["ci_exit"]==0 and r["live_upgrade_authorized"] is False
assert r["candidates"][0]["native"]["decision"]=="BLOCKED" and r["candidates"][1]["native"]["decision"]=="UNKNOWN"
print("SELF_SERVICE_E2E_PASS: discovered config, protected baseline, blocked 1.1.0, selected 1.1.1 for review")
PY
