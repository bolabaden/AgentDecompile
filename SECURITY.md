# Security

## Supported versions

Security fixes land on the default branch (`master`) and are included in the next tagged release. We do not maintain separate LTS branches.

| Version | Support |
|---------|---------|
| Latest release on GitHub | Yes |
| Older tagged releases | Best-effort backport if feasible |
| Unreleased `master` | Fix forward only |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Email the maintainers with:

- A description of the issue and impact
- Steps to reproduce (proof-of-concept if you have one)
- Affected versions or commits
- Your suggested fix, if any

We aim to acknowledge within a few business days and will work with you on disclosure timing. Credit reporters in the release notes when the fix ships unless you prefer to stay anonymous.

## Scope notes

AgentDecompile runs Ghidra analysis locally or against a Ghidra Server you configure. Typical risks:

- **MCP HTTP server** bound to `0.0.0.0` exposes Ghidra project operations to the network — use auth, firewall rules, or bind to localhost.
- **Ghidra Server credentials** in env vars or headers grant access to shared repositories — treat them like production secrets.
- **Arbitrary binary analysis** — importing untrusted binaries into Ghidra can trigger parser bugs in Ghidra itself; run in an isolated VM when analyzing malware.

We treat issues in this repo's Python MCP layer as in scope. Upstream Ghidra/JVM vulnerabilities should be reported to the [Ghidra project](https://github.com/NationalSecurityAgency/ghidra/security).
