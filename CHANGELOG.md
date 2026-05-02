# Changelog

All notable changes to `@yoda.digital/mycelium` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet. New entries land here between releases._

## [0.1.0] - 2026-05-XX

Initial public release on npm. Published as **`@yoda.digital/mycelium`**.

The repository previously carried an unpublished `1.0.0` git tag from
private development; the public package starts at `0.1.0` to signal
"first release with public-API and SemVer commitment."

### Added

- Bun-runtime package on npm with two binaries:
  - `mycelium-relay` — stateless authenticated router with Ed25519 relay
    identity and challenge-response auth.
  - `mycelium-peer` — MCP server for E2E encrypted peer messaging
    (Ed25519 identity + Curve25519 PFS + NaCl `crypto_box`).
- LICENSE (MIT, owner: Yoda Digital).
- SECURITY.md with private vulnerability reporting flow.
- CONTRIBUTING.md.
- OIDC trusted-publisher CI workflow (`.github/workflows/publish.yml`)
  — no `NPM_TOKEN`, no `provenance: true` flag, npm auto-attests via
  GitHub OIDC.
- README badge linking to the
  [Yoda Digital open-source portal](https://opensource.yoda.digital/projects/mycelium/).
