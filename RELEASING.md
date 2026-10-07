# Releasing

Releases are automated. Land Conventional Commits on `master` and
[release-plz](https://release-plz.dev) does the rest.

1. A push to `master` opens or updates a **release PR** that bumps the version
   in `Cargo.toml` and writes `CHANGELOG.md` from the commit messages.
2. Merging that PR cuts a **GitHub Release** and a `v{version}` tag.
3. When the release job reports that it cut a release, the same workflow run's
   `build` job cross-compiles `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl`, packaging each tarball with its `.sha256`, and
   the `upload-assets` job attaches them all to the Release.

`install.sh` refuses to install without verifying the checksum, so the `.sha256`
assets are required. If `build` or `upload-assets` fails, the Release exists but
is not installable — re-run that run's failed jobs rather than publishing by
hand.

## Not on crates.io

`bx` is not published to a registry. `install.sh` fetching a static binary is
the only channel, because the machine `bx` is meant to set up does not have a
Rust toolchain on it yet. `release-plz.toml` therefore sets `publish = false`
with `git_only = true`, so versions are detected from git tags instead of the
registry.

## Optional secret

`RELEASE_PLZ_TOKEN` is not required. Without it the workflow falls back to
`GITHUB_TOKEN`, so CI does not run on the release PR, branch protection cannot
gate it, and the Release shows `github-actions` as author.
