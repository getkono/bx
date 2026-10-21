use super::*;
use crate::sync::tests::{cloned, git, run};

#[test]
fn doctor_names_a_modified_file_and_an_unpushed_commit_and_is_pending() {
    let home = guarded_home();
    let repo = cloned(&home, "");
    run(
        home.path(),
        &repo,
        &["commit", "--quiet", "--allow-empty", "-m", "mine"],
    );
    std::fs::write(repo.join("bx.toml"), "# edited\n").expect("bx.toml");
    let before = crate::plan::tests::snapshot(home.path(), &[]);

    let mut out = Vec::new();
    let exit = doctor_with(
        &env(home.path()),
        &mut out,
        std::ffi::OsStr::new(""),
        &AllFailed,
        &git(home.path()),
    )
    .expect("doctor");

    assert_eq!(exit, Exit::Pending);
    assert_eq!(
        text(&out),
        "  ! ~/.config/bx has 1 uncommitted change(s) or untracked file(s), which only this \
         machine holds; `git -C ~/.config/bx status` shows them\n\
         \x20 ! ~/.config/bx is on master, with 1 commit(s) origin/master lacks as of the clone \
         or the last push, since nothing has fetched here, none of them a `bx update` lock \
         commit; `bx sync` pushes them\n\
         Doctor: 2 finding(s).\n"
    );
    assert_eq!(
        crate::plan::tests::snapshot(home.path(), &[]),
        before,
        "doctor writes nothing, the config repo's index included"
    );
}
