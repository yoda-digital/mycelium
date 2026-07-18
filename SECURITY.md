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
- **Replay** — `msg_id`, `seq`, `room`, and (for offline envelopes) `ts` are
  inside the signature; the replay log must reject exact duplicates and
  below-window stale frames (legitimately reordered frames inside the signed
  anti-replay window are delivered; verified duplicates are re-acked but
  never re-delivered). Offline envelopes must additionally be rejected
  outside their signed freshness window.
- **Offline-envelope confidentiality** — store-and-forward frames are sealed
  to the recipient's identity-derived key and are authenticated by the
  canonical signature against the TOFU-pinned sender. A path that delivers
  an offline envelope from an unpinned sender, or accepts one without a
  valid signature, is a vulnerability. (Offline envelopes deliberately trade
  PFS for deliverability — that tradeoff is documented, not a bug.)
- **Permission spoofing** — permission-grant messages travel through the
  same E2E envelope as data messages. A path that lets a relay forge
  approvals is a vulnerability.
- **Name hijack** — peer names are PERSISTENTLY bound to identity keys in
  the relay allow-list. A different key claiming a bound name must be
  rejected whether or not the owner is currently connected. Key rotation
  must require a continuity signature from the currently-bound key.
- **Silent drop** — encrypted delivery acknowledgements + automatic
  idempotent retransmission must recover or honestly surface every dropped
  message to the sender; a code path that loses a tracked message without a
  terminal notification is a vulnerability.
- **Backward secrecy regressions** — ephemeral keys must remain
  process-memory-only and rotate per session.

## Out of scope

- Compromised peer endpoints. Mycelium protects the wire and the relay,
  not against an attacker who has root on either client machine.
- Metadata / traffic analysis. The relay necessarily sees peer names, rooms,
  timing, frame sizes, and the messaging graph. This is documented in the
  README threat model and deliberately unmitigated — do not deploy Mycelium
  where the metadata itself is the secret.
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
