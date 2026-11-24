#!/bin/bash
set -euo pipefail
umask 077
app=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
cli(){ "$app/tredven-assurance" --workspace "$root/state" "$@"; }
cli init
cli lookup --catalog "$app/catalog.json" --sdk 1.25.0 --zod 3.25.76 --requires 1302 > "$root/lookup.json"
python3 -B - "$root/lookup.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["candidate"]["sdk"]=="1.25.3" and not r["live_upgrade_authorized"]
PY
rc=0; cli lookup --catalog "$app/catalog.json" --sdk 1.29.0 --zod 4.4.3 --requires 2464 2084 --allow-dependency-change > "$root/hold.json" || rc=$?
test "$rc" = 2
python3 -B - "$root/hold.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["status"]=="NO_TESTED_COMBINATION" and r["candidate"] is None
PY
cli catalog --evidence "$app/reference-evidence" --locks "$app/reference-locks"
if [ "$#" = 1 ] && [ "$1" = --reproduce ]; then
 cli reproduce --catalog "$app/catalog.json" --locks "$app/reference-locks" --allow-public-acquisition
elif [ "$#" != 0 ]; then exit 2; fi
echo "MARKET_REFERENCE_CI_PASS"
