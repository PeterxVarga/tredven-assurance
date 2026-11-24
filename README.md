# Tredven Assurance — local self-service candidate

Linux x86-64, Python 3.11+, Node 22.19+, npm and bubblewrap (unprivileged namespaces enabled). No account, API token or paid model required. This is a local release candidate, not a published distribution. Unpack into a new private directory; inspect the source and verify the separately supplied archive digest, then run `./install.sh`. The installer verifies the pinned core and lockfile, installs fixed public npm dependencies with lifecycle scripts disabled; `./install.sh --offline-cache /path/to/prepared/npm-cache` supports offline installation. Checksums are not a publisher signature.

## Your first project

The executable is `./tredven-assurance`. Use a new owner-private workspace path. Discovery is read-only and offline; it reports known agent installations and structural OpenCode/Pi/Hermes MCP configuration, not running protocol connections. It never starts discovered servers. Only explicitly selected, sanitized, disposable Node stdio projects with their dependencies and package.json are accepted for replay; do not point the tool at your home, credentials, production data or a live service. No external network or host home is mounted into replay. The selected project and tool dependencies are read-only; the sandbox has a disposable /tmp. This is isolation, not a hostile-code security guarantee. Review candidate provenance yourself.

    ./tredven-assurance --workspace ./state init
    ./tredven-assurance --workspace ./state discover
    ./tredven-assurance --workspace ./state protect --server ./baseline --entry server.mjs --replay ./replay.json
    ./tredven-assurance --workspace ./state check --server ./candidate --entry server.mjs
    ./tredven-assurance --workspace ./state resolve --candidates ./candidates --entry server.mjs

Replay contract JSON: {"tool":"read_record","arguments":{"id":"test"},"expected_content":[{"type":"text","text":"record:test"}]}. Use a harmless read-only fixture call and non-secret expected content. The baseline is immutable. Each candidate is an immediate subdirectory of the explicitly supplied candidates directory (1–12), a prepared Node project with the same declared package identity and entry. A bounded project tree hash and native snapshot bind the observation. Candidate selection considers only supplied, stable, newer versions; the unique highest passing version is selected for review, not installed. No automatic registry search, dependency fetching, remote MCP/OAuth, production replay, live execution or rollback. CI exit 0 means scoped contract/replay success and unique candidate, 1 means all evaluated candidates blocked, 2 means unknown/review unavailable/error. Rust remains UNKNOWN for compatible fixture candidates. The private report.json, report.html and attempt.json belong together: consume report.json only when attempt.json is FINISHED with matching digest. Snapshot/tool descriptions may contain sensitive content; never upload the workspace without checking it. For cross-stack Pi/bridge/APM qualification see ASSURANCE_README.md in the source repository; that separate deeper lab is not required for this entry product.

## Example / CI

Run `./demo.sh ./new-demo` after installation. It creates three synthetic projects, a new workspace, baseline, failing candidate and fixed candidate, and verifies exit codes. Run the same shell commands in CI using a pre-provisioned runner with bubblewrap and a reviewed local package, no secrets. A CI run on GitHub's hosted runners has not been qualified. No cloud resources or automatic provider writes.

For the public SDK matrix see REALWORLD_README.md.

See MARKET_README.md for the reference catalogue, lookup, exact reproducibility and CI.
