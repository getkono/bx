//! Build script: captures the commit bx was built from and exposes it as a
//! compile-time env var for `bx --version`.
//!
//! Every fact is best-effort. In a source tarball, or a checkout with no `.git`,
//! the value falls back to `"unknown"` rather than failing the build.

use std::process::Command;

fn main() {
    // A CI-provided hash wins over the local probe: the cross container that
    // builds the release binaries has no git, so the release workflow exports
    // BX_BUILD_SHA on the host and Cross.toml forwards it in.
    let commit = env_override("BX_BUILD_SHA").or_else(|| {
        git(&["rev-parse", "--short=12", "HEAD"]).map(|sha| {
            if is_dirty() {
                format!("{sha}-dirty")
            } else {
                sha
            }
        })
    });

    emit("BX_COMMIT_HASH", commit.as_deref().unwrap_or("unknown"));
    emit(
        "BX_COMMIT_DATE",
        git(&["log", "-1", "--format=%cI"])
            .as_deref()
            .unwrap_or("unknown"),
    );

    // Rebuild when HEAD moves so the embedded commit stays current. In a git
    // worktree `.git` is a file, so resolve the real git dir rather than
    // hard-coding `.git/HEAD`.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
    }
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=BX_BUILD_SHA");
}

/// A trimmed, non-empty environment variable, or `None`.
fn env_override(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn emit(key: &str, value: &str) {
    println!("cargo::rustc-env={key}={value}");
}

/// Runs `git` with `args`, returning trimmed stdout on success.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Whether the working tree has uncommitted changes.
fn is_dirty() -> bool {
    git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty())
}
