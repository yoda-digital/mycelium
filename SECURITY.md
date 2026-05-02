# Security policy

Mycelium is an end-to-end encrypted messaging layer for Claude Code instances.
The threat model assumes the relay is fully compromised; the design must hold
even when the router is hostile.

## Reporting a vulnerability

Report security vulnerabilities **privately** via GitHub's
[private vulnerability reporting](https://github.com/yoda-digital/mycelium/security/advisories/new),
**not** through public issues.

Expected response time: best-effort within 7 days. Coordinated disclosure
preferred.

## In scope

The following are explicit security goals — failures are vulnerabilities:

- **Plaintext leak through the relay** — Curve25519 ephemeral keys must
  never be reused; the shared secret never leaves either peer's process.
- **Identity-key MITM during first contact** — Ed25519 TOFU + STS
  (Station-to-Station) must protect the first key exchange. A flaw that
  lets an active attacker substitute a key during TOFU is a vulnerability.
- **Signature bypass** — every wire frame must carry an Ed25519 signature
  over canonical JSON (sorted keys, fixed field set including `msg_id` and
  `seq`). Any code path that accepts an unsigned or mis-signed frame is
  a vulnerability.
- **Replay** — `msg_id` and `seq` are inside the signature; the replay log
  must reject duplicates and out-of-order frames.
- **Permission spoofing** — permission-grant messages travel through the
  same E2E envelope as data messages. A path that lets a relay forge
  approvals is a vulnerability.
- **Name hijack** — peer names are bound to identity keys. Two different
  keys claiming the same name on the same room must not both succeed.
- **Silent drop** — encrypted delivery acknowledgements + 30-second
  timeouts must surface dropped messages to the sender.
- **Backward secrecy regressions** — ephemeral keys must remain
  process-memory-only and rotate per session.

## Out of scope

- Compromised peer endpoints. Mycelium protects the wire and the relay,
  not against an attacker who has root on either client machine.
- Denial of service from a hostile relay. The relay can refuse to route;
  it cannot read, forge, or silently corrupt — that is the goal.
- Vulnerabilities in `libsodium-wrappers-sumo`, the MCP SDK, or other
  upstream dependencies. Report those upstream; we'll bump and re-publish
  when fixes are available.

## Cryptography

If you find a flaw in the protocol design itself (not just an implementation
bug), please include a write-up of the attack scenario in your report.
Protocol-level fixes will involve a deliberately bumped major version.

## Public disclosure

Once a fix is merged and released, we publish a CVE through GitHub Security
Advisories where applicable.

## Listed at

[opensource.yoda.digital/projects/mycelium/](https://opensource.yoda.digital/projects/mycelium/)
