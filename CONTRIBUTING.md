# Contributing to Tesseras DHT

Thank you for your interest in contributing! This document explains how to get
started.

## Getting Started

### Prerequisites

- **Rust 1.85+** (edition 2024) — see `rust-toolchain.toml`
- **just** — task runner ([just.systems](https://just.systems/))
- **dprint** — formatter for Rust, TOML, and Markdown
- **cargo-deny** — dependency policy checker (licenses, advisories)
- **git-cliff** — changelog generator (for releases)

### Building

```sh
# List all available tasks
just

# Build library only
just build

# Build with CLI binary (tessera-node)
just build-cli

# Run all tests
just test

# Full local CI: format check + lint + test + audit
just check
```

## Development Workflow

1. **Clone** the repository and create a feature branch from `main`.
2. **Write code** following the conventions below.
3. **Add tests** — unit tests in the same file (`#[cfg(test)] mod tests`),
   integration tests in `tests/`.
4. **Run checks** before submitting:
   ```sh
   just check
   ```
   This runs `dprint check` + `cargo clippy` + `cargo test` +
   `cargo deny check`.
5. **Submit your contribution** using one of the methods below.

### Submitting via Email (preferred)

The primary way to contribute is by sending a patch to the SourceHut mailing
list using `git send-email`:

```sh
# One-time setup
git config sendemail.to "~ijanc/tesseras-devel@lists.sr.ht"
git config sendemail.annotate true

# Send your commits as a patch series
git send-email --to="~ijanc/tesseras-devel@lists.sr.ht" origin/main
```

If you are new to `git send-email`, see the
[git-send-email tutorial](https://git-send-email.io/) for setup instructions.

Tips for email patches:

- Write a clear cover letter (`--cover-letter`) for multi-commit series.
- Ensure your patches apply cleanly on top of `main`.
- Respond to review feedback by sending a revised series with
  `git send-email -v2` (or `-v3`, etc.).

### Submitting via GitHub

You can also open a pull request on the
[GitHub mirror](https://github.com/tesseras-net/tesseras-dht). Fork the
repository, push your branch, and open a PR against `main`.

## Project Structure

Single-crate Tokio actor design. The entire system is one actor
(`NodeActor<T: Transport>`) that owns all mutable state, with `NodeHandle` as
the public API.

```
src/
  node.rs          # Actor + handle + iterative lookup + RPC handling (the core)
  lib.rs           # Crate root, public API re-exports
  error.rs         # TesseraError enum (thiserror)
  metrics.rs       # Metric name constants and helpers
  identity/        # Ed25519 keypair, NodeId (SHA-256 of pubkey), PoW anti-Sybil
  routing/         # KBucket + 256-bucket RoutingTable
  protocol/        # Message/Payload enums, MessagePack serialization
  transport/       # Transport trait, QuicTransport, InMemoryTransport, mDNS, DNS SRV, STUN/NAT
  storage/         # ChunkStore (content-addressed filesystem), MetadataStore (SQLite)
  erasure/         # Reed-Solomon encode/decode
  bin/
    tessera-node.rs   # CLI binary (requires --features cli)
    nat-test-helper.rs
tests/
  integration.rs      # Multi-node integration tests
  nat_integration.rs  # NAT traversal tests (requires root)
bench/                # Load test scripts
```

## Coding Conventions

- **Language**: all code, comments, and docs in English.
- **Architecture**: actor-based — domain logic lives in `node.rs`, transport is
  abstracted via the `Transport` trait, storage is behind `ChunkStore` and
  `MetadataStore`.
- **Errors**: `thiserror` with the `TesseraError` enum. No `unwrap()` in library
  code.
- **Async**: Tokio runtime. Blocking I/O (SQLite, filesystem) goes through
  `spawn_blocking`.
- **Generics over trait objects**: the `Transport` trait uses `impl Future` in
  methods (Rust 2024 edition) — no `dyn` dispatch.
- **Naming**: Rust conventions — `snake_case` for functions, `PascalCase` for
  types.
- **Formatting**: `dprint fmt` (wraps `rustfmt` for Rust, also formats TOML and
  Markdown). Config in `dprint.json`.
- **Linting**: `cargo clippy --all-targets` — zero warnings policy.
- **Dependencies**: additions must pass `cargo deny check` (see `deny.toml`).
- **License**: ISC — all contributions are licensed under the same terms.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/) with
[git-cliff](https://git-cliff.org/) for automated changelog generation.

```
feat: add parallel chunk retrieval for faster downloads

Race all K closest nodes concurrently per chunk, returning on the first
valid response and aborting the rest. Avoids serial timeouts from stale
peers.
```

Supported prefixes: `feat:`, `fix:`, `perf:`, `refactor:`, `doc:`, `test:`,
`audit:`, `style:`, `chore:`, `ci:`, `build:`.

Use scope when it adds clarity: `fix(transport):`, `feat(storage):`,
`test(nat):`.

## Testing

- **Unit tests**: alongside source code in `#[cfg(test)] mod tests`.
- **Integration tests**: in `tests/integration.rs` — multi-node scenarios using
  `InMemoryTransport`.
- **NAT tests**: in `tests/nat_integration.rs` — require root and Linux network
  namespaces. Run with `just test-nat`.
- **InMemoryTransport**: use `new_in_memory_network()` for in-process test
  networks.
- **`MetadataStore::in_memory()`**: in-memory SQLite for tests.
- **`tempfile::TempDir`**: for ChunkStore temp directories in tests.

Run specific tests:

```sh
just test-filter <pattern>     # tests matching a pattern
just test-unit                 # unit tests only
just test-integration          # integration tests only
```

## Reporting Issues

File issues on the
[SourceHut ticket tracker](https://todo.sr.ht/~ijanc/tesseras).

- Search existing issues before opening a new one.
- Include Rust version (`rustc --version`), OS, and steps to reproduce.
- For security issues, follow the process described in
  [SECURITY.md](SECURITY.md) — do not open a public issue.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating
you agree to abide by its terms.
