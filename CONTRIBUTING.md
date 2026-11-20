# Contributing to TsuDEV Sync (`tsusync`)

_Tiếng Việt: mọi đóng góp đều được chào đón. Bạn có thể viết issue và pull request bằng tiếng Việt hoặc tiếng Anh._

TsuDEV Sync is the shared end-to-end encrypted sync and backup service of the TsuDEV apps: a Cloudflare Worker
(`worker/`, D1 + R2) that only ever stores ciphertext, plus client libraries in TypeScript (`clients/ts`), Dart
(`clients/dart`), Rust (`clients/rust`) and .NET (`clients/dotnet`) that all produce the same `TS 01` ciphertext format.
See [README.md](README.md) for the API and [docs/adr/](docs/adr/) for the design decisions.

## Reporting bugs and requesting features

- **Bug**: open an issue with the *Bug report* form: <https://github.com/tsudev-org/tsusync/issues/new/choose>.
  Include the component (worker or which client), version (git tag or commit), platform and steps to reproduce.
- **Feature**: use the *Feature request* form. Changes to the ciphertext format or the key derivation need a new ADR
  and new conformance vectors first.
- **Security vulnerability**: never in a public issue - see [SECURITY.md](SECURITY.md) (private vulnerability
  reporting on the Security tab).

## Getting the source, building and testing

```bash
git clone https://github.com/tsudev-org/tsusync.git
cd tsusync

# Worker (TypeScript, Cloudflare Workers): typecheck, eslint (strict type-checked), Miniflare tests
cd worker && npx -y npm@11.21.2 ci --no-fund --no-audit && npm run check && cd ..

# TypeScript client: typecheck, vector + fuzz tests, build
cd clients/ts && npx -y npm@11.21.2 ci --no-fund --no-audit && npm run check && npm run build && cd ../..

# Dart client
cd clients/dart && dart pub get && dart analyze --fatal-infos && dart test && cd ../..

# Rust client
cd clients/rust && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && cd ../..

# .NET client (needs libsodium)
cd clients/dotnet && dotnet test test/Tsudev.Sync.Tests && cd ../..

# Independent check: ciphertext opens with the libsodium C library
python3 -I conformance/verify_libsodium.py conformance/vectors-v1.json
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs exactly these steps, and additionally checks that the
ciphertext each client produces right now opens with libsodium C.

## Pull request requirements

Every change goes through a pull request into `main` (direct pushes are blocked) and is squash-merged.

1. **One change per pull request**, with a description of what and why. Commit messages follow
   [Conventional Commits](https://www.conventionalcommits.org/) (`feat: ...`, `fix: ...`, `docs: ...`).
2. **Tests**: every change in behaviour comes with tests in the same pull request. A bug fix comes with a regression
   test that fails without the fix. Changes to authentication (entitlement JWS, DPoP), quotas or decryption also need
   a negative test (tampered, stale or malformed input is rejected).
3. **Same format everywhere**: a change to the ciphertext or key derivation updates all four clients and
   `conformance/vectors-v1.json` (or a new vectors file) in the same pull request.
4. **CI must be green**: worker typecheck + eslint + tests, every client job (format, strict analysis, tests, libsodium
   cross-check), gitleaks and the TsuDEV standards check.
5. **Cryptography**: only libsodium primitives (secretstream XChaCha20-Poly1305, Argon2id, `crypto_kdf`) and WebCrypto
   ECDSA P-256 for JWS; never implement a primitive yourself, never accept keys from a token header, never log tokens,
   keys or user data.
6. **Changelog**: user-visible changes get an entry in [CHANGELOG.md](CHANGELOG.md) (Keep a Changelog, SemVer).
7. Dependencies and GitHub Actions are pinned (lock files, Actions by commit SHA) and updated by Dependabot.

## Releases

Versions follow [Semantic Versioning](https://semver.org/). A release is an annotated tag `vX.Y.Z` on `main` whose
notes are the matching section of [CHANGELOG.md](CHANGELOG.md); apps pin the tag or commit.

## License

By contributing you agree that your work is licensed under the [GNU AGPL-3.0-only](LICENSE), like the rest of the
project. Everyone taking part follows the
[TsuDEV Code of Conduct](https://github.com/tsudev-org/.github/blob/main/CODE_OF_CONDUCT.md).
