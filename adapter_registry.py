"""Versioned, built-in discovery adapters; no arbitrary plugin execution."""
from dataclasses import dataclass
from pathlib import Path
import importlib.metadata, re, shutil, sys

@dataclass(frozen=True)
class Adapter:
    id: str
    kind: str
    identities: tuple = ()
    pattern: str = ""
    version: int = 1
    releases: tuple = ()

# Extending support for an installed npm CLI only requires a static entry.
# Network destinations are derived solely from these reviewed public identities.
CATALOG = (
    Adapter("pi","npm",("@earendil-works/pi-coding-agent","@mariozechner/pi-coding-agent"),releases=(("@earendil-works/pi-coding-agent","earendil-works/pi","v"),)),
    Adapter("opencode","npm",("@opencode/cli","opencode-ai"),releases=(("@opencode/cli","anomalyco/opencode","v"),("opencode-ai","anomalyco/opencode","v"))),
    Adapter("npm","npm",("npm",),releases=(("npm","npm/cli","v"),)),
    Adapter("codex","npm",("@openai/codex",),releases=(("@openai/codex","openai/codex","rust-v"),)),
    Adapter("claude","npm",("@anthropic-ai/claude-code",)),
    Adapter("gemini","npm",("@google/gemini-cli",)),
    Adapter("hermes","git-source"),
    Adapter("podman","native",pattern=r"podman version ([\w.+-]+)"),
    Adapter("docker","native",pattern=r"Docker version ([\w.+-]+)"),
    Adapter("git","native",pattern=r"git version ([\w.+-]+)"),
    Adapter("uv","native",pattern=r"uv ([\w.+-]+)"),
    Adapter("node","native",pattern=r"v([0-9.]+)"),
    Adapter("python","interpreter"),
    Adapter("mcp","python-distribution",("mcp",)),
    Adapter("mcp-config","config-presence"),
    Adapter("git-repository","selected-repository"),
)
def npm_sources():
    from urllib.parse import quote
    return {ident:"https://registry.npmjs.org/"+quote(ident,safe="@")+"/latest"
            for a in CATALOG if a.kind=="npm" for ident in a.identities}
def release_sources():
    return {ident:(repo,prefix) for a in CATALOG for ident,repo,prefix in a.releases}

def collect(args, *, npm_tool, native, hermes, git_repo, ver):
    rows=[]
    for a in CATALOG:
        if a.kind=="npm":
            row=npm_tool(a.id,set(a.identities))
        elif a.kind=="native":
            row=native(a.id,a.pattern)
        elif a.kind=="git-source":
            row=hermes(args.hermes_source)
        elif a.kind=="interpreter":
            row={"tool":a.id,"kind":"runtime","installed":sys.version.split()[0],"evidence":"running Python interpreter","scope":"collector interpreter"}
        elif a.kind=="python-distribution":
            try: v=importlib.metadata.version(a.identities[0])
            except importlib.metadata.PackageNotFoundError: v=None
            row={"tool":a.id,"kind":"python-package","installed":ver(v),"evidence":"current interpreter distribution metadata only","scope":"not an MCP server inventory"}
        elif a.kind=="config-presence":
            paths=[".config/opencode/opencode.json",".config/opencode/opencode.jsonc",".pi/agent/settings.json",".hermes/config.yaml"]
            row={"tool":a.id,"kind":"configuration","installed":None,"evidence":"configuration contents deliberately not read","scope":"presence only","config_locations_present":sum((Path.home()/p).exists() for p in paths)}
        elif a.kind=="selected-repository":
            for i,path in enumerate(args.repo):
                rows.append({**git_repo(path),"asset_id":f"git-repository:{i}","adapter":a.id,"adapter_version":a.version})
            continue
        else:
            raise ValueError("unsupported built-in adapter kind")
        rows.append({**row,"asset_id":a.id,"adapter":a.id,"adapter_version":a.version})
    return rows

def rpm_ownership(tool,run):
    """Local database ownership of the resolved executable, never dnf refresh."""
    executable=shutil.which(tool)
    if not executable or not shutil.which("rpm"):return {"status":"UNAVAILABLE"}
    try:path=Path(executable).resolve(strict=True)
    except OSError:return {"status":"UNAVAILABLE"}
    raw=run(["rpm","-qf","--qf","%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n",str(path)])
    if raw is None:return {"status":"NO_OWNERSHIP_PROOF"}
    rows=[]
    for line in raw.splitlines():
        fields=line.split("\t")
        if len(fields)!=2 or not all(re.fullmatch(r"[A-Za-z0-9._:+~-]{1,180}",v) for v in fields):
            return {"status":"UNEXPECTED_NATIVE_OUTPUT"}
        rows.append({"package":fields[0],"evr":fields[1]})
    return {"status":"OBSERVED" if rows else "UNKNOWN","packages":rows,"scope":"local RPM database; no repository update check"}
