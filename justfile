# tessera-dht development automation
# Run `just` to see all available recipes

set shell := ["bash", "-euo", "pipefail", "-c"]

# Bench defaults
bench_nodes := "5"
bench_workers := "3"
bench_duration := "30"
bench_sizes := "1k,10k"
bench_pow := "1"

# List available recipes
default:
    @just --list

# ─── Development ──────────────────────────────────────────────

# Build library only
build:
    cargo build

# Build with CLI binary (tessera-node)
build-cli:
    cargo build --features cli

# Build release with CLI binary
build-release:
    cargo build --release --features cli

# Build CLI with Prometheus metrics exporter
build-cli-metrics:
    cargo build --features cli,prometheus

# Run all tests
test:
    cargo test

# Run integration tests only
test-integration:
    cargo test --test integration

# Run unit tests only
test-unit:
    cargo test --lib

# Run tests matching a filter
test-filter filter:
    cargo test {{ filter }}

# Run clippy lints on all targets
lint:
    cargo clippy --all-targets

# Format code with dprint
fmt:
    dprint fmt

# Check formatting without writing
fmt-check:
    dprint check

# Run cargo-deny checks (licenses, advisories, bans)
audit:
    cargo deny check

# Run full local CI: format check, lint, test, audit
check: fmt-check lint test audit

# ─── NAT Tests ────────────────────────────────────────────────

# Run all NAT integration tests (requires root)
test-nat:
    cargo build --features cli --bin nat-test-helper
    sudo TESSERA_NAT_TEST=1 CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        PATH="$HOME/.cargo/bin:$PATH" \
        cargo test --test nat_integration -- --test-threads=1 --nocapture

# Run a specific NAT test (requires root)
test-nat-filter filter:
    cargo build --features cli --bin nat-test-helper
    sudo TESSERA_NAT_TEST=1 CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        PATH="$HOME/.cargo/bin:$PATH" \
        cargo test --test nat_integration {{ filter }} -- --test-threads=1 --nocapture

# ─── Benchmarks ───────────────────────────────────────────────

# Run quick load test (configurable: just bench 5 3 30 "1k,10k" 1)
bench nodes=bench_nodes workers=bench_workers duration=bench_duration sizes=bench_sizes pow=bench_pow:
    cargo build --release --features cli
    bench/load-test.sh -n {{ nodes }} -w {{ workers }} -d {{ duration }} -s "{{ sizes }}" -p {{ pow }}

# Run full load test (20 nodes, 10 workers, 60s, all sizes)
bench-full:
    cargo build --release --features cli
    bench/load-test.sh -n 20 -w 10 -d 60 -s "1k,10k,100k" -p 16

# ─── Changelog & Versioning ──────────────────────────────────

# Show unreleased changelog preview
changelog:
    git cliff --unreleased

# Show what the next version would be
version:
    @git cliff --bumped-version

# Generate CHANGELOG.md (full history)
changelog-generate:
    git cliff -o CHANGELOG.md

# ─── Release ──────────────────────────────────────────────────

# Perform a full release: bump version, changelog, commit, tag, push, gh release
release: _require-clean _require-tools
    #!/usr/bin/env bash
    set -euo pipefail

    # 1. Calculate next version from conventional commits
    NEXT_VERSION=$(git cliff --bumped-version)
    VERSION_NUM=${NEXT_VERSION#v}
    echo "==> Next version: ${NEXT_VERSION} (${VERSION_NUM})"

    # 2. Update Cargo.toml
    echo "==> Updating Cargo.toml to ${VERSION_NUM}"
    cargo set-version "${VERSION_NUM}"

    # 3. Generate changelog
    echo "==> Generating CHANGELOG.md"
    git cliff --bump -o CHANGELOG.md

    # 4. Verify it builds
    echo "==> Verifying build"
    cargo build

    # 5. Commit and tag
    echo "==> Committing release"
    git add Cargo.toml Cargo.lock CHANGELOG.md
    git commit -m "chore(release): ${NEXT_VERSION}"
    git tag -a "${NEXT_VERSION}" -m "Release ${NEXT_VERSION}"

    # 6. Push to all remotes
    echo "==> Pushing to remotes"
    git push sr main --tags
    git push github main --tags

    # 7. Create GitHub release with changelog for this version
    echo "==> Creating GitHub release"
    RELEASE_NOTES=$(git cliff --unreleased --strip header)
    gh release create "${NEXT_VERSION}" \
        --title "${NEXT_VERSION}" \
        --notes "${RELEASE_NOTES}" \
        --repo tesseras-net/tesseras-dht

    echo "==> Release ${NEXT_VERSION} complete!"

# Show what release would do without executing
release-dry: _require-clean
    #!/usr/bin/env bash
    set -euo pipefail

    NEXT_VERSION=$(git cliff --bumped-version)
    echo "Next version: ${NEXT_VERSION}"
    echo ""
    echo "--- Changelog preview ---"
    git cliff --bump --unreleased
    echo ""
    echo "--- Actions ---"
    echo "1. cargo set-version ${NEXT_VERSION#v}"
    echo "2. git cliff --bump -o CHANGELOG.md"
    echo "3. cargo build"
    echo "4. git add Cargo.toml Cargo.lock CHANGELOG.md"
    echo "5. git commit -m 'chore(release): ${NEXT_VERSION}'"
    echo "6. git tag -a ${NEXT_VERSION}"
    echo "7. git push sr main --tags"
    echo "8. git push github main --tags"
    echo "9. gh release create ${NEXT_VERSION}"

# ─── Git Remotes ──────────────────────────────────────────────

# Push to all remotes (sr + github)
push:
    git push sr main
    git push github main

# Push with tags to all remotes
push-tags:
    git push sr main --tags
    git push github main --tags

# Setup github remote (run once)
setup-github:
    git remote add github git@github.com:tesseras-net/tesseras-dht.git

# ─── Internal helpers ─────────────────────────────────────────

# Ensure working tree is clean before release
[private]
_require-clean:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: working tree is not clean. Commit or stash changes first."
        git status --short
        exit 1
    fi

# Ensure required tools are installed
[private]
_require-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=()
    command -v git-cliff >/dev/null || missing+=("git-cliff")
    command -v cargo-set-version >/dev/null || { cargo set-version --help >/dev/null 2>&1 || missing+=("cargo-edit (cargo install cargo-edit)"); }
    command -v dprint >/dev/null || missing+=("dprint")
    command -v cargo-deny >/dev/null || { cargo deny --help >/dev/null 2>&1 || missing+=("cargo-deny"); }
    command -v gh >/dev/null || missing+=("gh (GitHub CLI)")
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: missing required tools:"
        printf '  - %s\n' "${missing[@]}"
        exit 1
    fi
