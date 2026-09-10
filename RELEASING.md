# Releasing

Releases are automated. Land Conventional Commits on `master` and
[release-plz](https://release-plz.dev) does the rest.

1. A push to `master` opens or updates a **release PR** that bumps the version
   in `Cargo.toml` and writes `CHANGELOG.md` from the commit messages.
2. Merging that PR cuts a **GitHub Release** and a `v{version}` tag.
3. The tag triggers the build job, which cross-compiles
   `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, and attaches
   each tarball **and its `.sha256`** to the Release.

`install.sh` refuses to install without verifying the checksum, so the `.sha256`
assets are required. If the build job fails, the Release exists but is not
installable — re-run the workflow rather than publishing by hand.

## Not on crates.io

`bx` is not published to a registry. `install.sh` fetching a static binary is
the only channel, because the machine `bx` is meant to set up does not have a
Rust toolchain on it yet. `release-plz.toml` therefore sets `publish = false`
with `git_only = true`, so versions are detected from git tags instead of the
registry.

## The first release

There is no `v0.1.0` tag yet, so nothing for release-plz to diff against. Run
the **Release-plz** workflow manually from the Actions tab to cut it.

## Optional secrets

Neither is required; both degrade to a working default.

| Secret | Effect when absent |
|---|---|
| `RELEASE_PLZ_TOKEN` | Falls back to `GITHUB_TOKEN`. CI will not run on the release PR, so branch protection cannot gate it, and the Release shows `github-actions` as author. |
