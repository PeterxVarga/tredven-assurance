# Tredven Assurance — OSS release candidate

A local-first MCP compatibility tool, not a production updater. Start with the included reference catalogue and exact lockfiles. No account, telemetry service, or model API is required. Linux x86-64, Python 3.11+, Node 22.19+, npm, bubblewrap with user namespaces. Verify the archive SHA-256 from a trusted channel before extracting into a private directory. The included checksums are integrity checks, not a publisher signature. Review the source and third-party notices.

    ./install.sh
    ./tredven-assurance --workspace ./state init
    ./tredven-assurance --workspace ./state lookup --catalog ./catalog.json --sdk 1.25.0 --zod 3.25.76 --requires 1302

Open site/index.html via a local static server (bind loopback only). The catalogue includes ten examined SDK issues, nine observed SDK/Zod profiles and the reference runtime; untested profiles are unknown. Lookup selects the smallest tested non-older SDK version with the same dependency first, preserving every previously passing probe and satisfying all explicitly required probes. Dependency changes require --allow-dependency-change and human review; this is not an endorsement of downgrading Zod. A selected profile may fail other probes; the CLI lists those failures. A checksum validates consistency, not authenticity. The reference catalogue is a point-in-time snapshot, not a live security or compatibility database.

    ./tredven-assurance --workspace ./state reproduce --catalog ./catalog.json --locks ./reference-locks --allow-public-acquisition

Reproduce installs the nine exact public lockfiles using npm ci without lifecycle scripts and runs the authored probes in bubblewrap. Exit 0 means the reference lockfiles and Boolean probe outcomes agree, not that all checks pass. Exit 2 means incomplete or changed observations. Runtime identity is recorded separately. This is a trusted-upstream laboratory, not a general-purpose hostile-code sandbox. No production credentials, host mutation, or arbitrary issue code.

    ./tredven-assurance --workspace ./state catalog --evidence ./reference-evidence --locks ./reference-locks --discover-public

This builds a new private catalogue from the reference receipt and checks upstream issue metadata. The optional public discovery samples one recent GitHub page; unknown issues require review and are not automatically reproduced. Public rate limits can yield UNKNOWN. The output directory must not already exist. Existing self-service protect/check/resolve and corpus commands are documented in README.md and REALWORLD_README.md. The static site is a non-indexable preview, not a live product site.

CI: run ./ci-check.sh with a pre-provisioned Linux runner after installation. Add --reproduce to fetch and execute exact public reference locks. No GitHub workflow is installed or triggered automatically. No hosted runner qualification, customer adoption, or paid demand is claimed. Release publication and deployment require separate authorization.

## Release security review

The default tool runtime is SDK 1.32.2 (not the historical SDK 1.29.0). The reference corpus deliberately installs old public versions only for isolated compatibility tests; they may contain known vulnerabilities and must not be used in production. The public npm audit of the default lockfile reported zero findings at review time, not a security guarantee.
