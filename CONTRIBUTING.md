# Contributing to mycelium

Mycelium is an E2E encrypted messaging layer for Claude Code instances.
Production-grade crypto, no decorative code, every change reviewed against
the threat model in [SECURITY.md](./SECURITY.md).

## Reporting bugs

Open an [Issue](https://github.com/yoda-digital/mycelium/issues/new) with
the steps to reproduce, expected vs. actual behavior, and the Bun version
(`bun --version`).

**Never paste private keys, identity keypairs, or contents of
`~/.mycelium-keys.json` / `~/.mycelium-tofu.json`.** If a bug repros only
with a specific keypair, include the public key only.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](./SECURITY.md) for the
private disclosure flow via GitHub Security Advisories.

## Suggesting features

Open a [Discussion](https://github.com/yoda-digital/mycelium/discussions)
for open-ended ideas. For concrete proposals, an issue with a written
threat-model impact is preferred.

## Development setup

Requires [Bun](https://bun.sh) >= 1.3.5.

```bash
git clone git@github.com:yoda-digital/mycelium.git
cd mycelium
bun install
bun test
```

Run the relay locally:

```bash
bun run relay.ts
```

In a second terminal, run a peer (it connects to the local relay by default):

```bash
bun run peer-channel.ts
```

## Pull request checklist

- One concern per PR. Avoid bundling unrelated changes.
- `bun test` passes.
- `bunx tsc --noEmit` clean.
- New protocol fields or wire-format changes require a writeup of the
  threat-model impact in the PR description.
- Changes to crypto code require an explicit reviewer requested from the
  maintainers — never self-merge crypto changes.

## Style

Strict TypeScript. Match the existing module style. The codebase keeps
crypto and protocol logic deliberately concentrated in `peer-channel.ts`
and `relay.ts`; resist splitting them into more files unless there is a
real boundary.

## License

By contributing you agree that your contributions will be licensed under
the project's [MIT license](./LICENSE).
