#!/bin/bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
sha256sum -c SHA256SUMS >/dev/null
command -v python3 >/dev/null; command -v node >/dev/null; command -v npm >/dev/null; command -v bwrap >/dev/null
python3 -B - "$root/oss-contract-fixture/package-lock.json" <<'PY'
import json,sys,urllib.parse,hashlib
p=sys.argv[1];raw=open(p,"rb").read()
assert hashlib.sha256(raw).hexdigest()=="f7b23dbf7b13db623b4432a4d3a9101783816b4a4f9b4d5f0b8695b534aab864"
for k,v in json.loads(raw)["packages"].items():
 if k:
  u=urllib.parse.urlsplit(v["resolved"])
  assert u.scheme=="https" and u.hostname=="registry.npmjs.org" and not u.username and v["integrity"].startswith("sha512-")
PY
cache="$root/npm-cache"; mode=()
if [ "$#" -eq 2 ] && [ "$1" = "--offline-cache" ]; then cache=$(realpath -- "$2"); mode=(--offline); elif [ "$#" -ne 0 ]; then echo 'Usage: install.sh [--offline-cache PATH]' >&2;exit 2;fi
tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
cd "$root/oss-contract-fixture"
env -i HOME="$tmp" PATH="$(dirname "$(command -v node)"):$(dirname "$(command -v npm)"):/usr/bin:/bin" LANG=C npm_config_cache="$cache" npm_config_registry=https://registry.npmjs.org npm_config_userconfig=/dev/null npm_config_globalconfig="$tmp/global.npmrc" npm ci --ignore-scripts --no-audit --no-fund --loglevel=error "${mode[@]}"
cd "$root"
python3 -B -c 'import selfservice as s; s.ready();s.w.core_path(None);print("Tredven Assurance ready.")'
