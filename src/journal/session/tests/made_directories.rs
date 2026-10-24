//! The directories a write makes on the way to its destination: the ones its
//! intent names, the ones its entry claims, and the ones a refused write
//! leaves behind.

use super::*;

#[test]
fn a_stage_that_made_other_directories_than_its_intent_named_is_refused() {
    // #119. The Intent names the parents read from disk before the stage;
    // a disk that changed in between makes the two differ, and the write
    // is refused rather than carried on with a ledger claim the journal
    // does not share. What the home or above adds is dropped from both
    // sides alike, so it alone is no difference.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let session = apply_session(&state, home.path());
    let dest = home.child(".config/app/x.conf");
    let (app, config) = (home.child(".config/app"), home.child(".config"));
    let announced = [app.clone(), config.clone()];

    session
        .refuse_unannounced(&dest, &announced, &announced)
        .expect("the same set");
    session
        .refuse_unannounced(
            &dest,
            &announced,
            &[app.clone(), config.clone(), home.path().to_path_buf()],
        )
        .expect("the home is claimed by neither");
    for made in [vec![app.clone()], vec![], vec![config.clone(), app.clone()]] {
        let err = session
            .refuse_unannounced(&dest, &announced, &made)
            .expect_err("a different set");
        assert!(
            matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
            "{made:?}: {err:?}"
        );
    }
}

/// Lose the parent of the destination's parent between the prediction
/// and the stage: `.config` existed when the Intent was written, so it
/// names only `.config/app`, and the stage then makes both.
fn lose_config(dest: &Path) {
    let config = dest
        .parent()
        .and_then(Path::parent)
        .expect("the destination's grandparent");
    std::fs::remove_dir(config).expect("the user removes it, empty");
}

#[test]
fn a_write_refused_for_an_unannounced_directory_removes_what_it_made() {
    // D2. The stage made `.config` again, which the Intent never named and
    // the refused write leaves in no ledger: no rollback or `rm` would ever
    // remove it, so the refusal itself does, with `.config/app` under it.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let config = home.child(".config");
    std::fs::create_dir(&config).expect("the user's, at prediction");
    let (portable, dest) = target(home.path(), ".config/app/x.conf");

    let mut session = apply_session(&state, home.path());
    session.after_intent = Some(lose_config);
    let err = session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the stage made a directory the Intent did not name");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
        "got {err}"
    );
    assert!(!config.exists(), "what the stage made is gone again");
    assert!(
        std::fs::read_dir(home.path())
            .expect("the home")
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".bx-")),
        "and so is the temporary file",
    );
}

#[test]
fn a_link_refused_for_an_unannounced_directory_removes_what_it_made() {
    // D2, the link path.
    let home = guarded_home();
    let state = StateDir::resolve(home.path());
    let config = home.child(".config");
    std::fs::create_dir(&config).expect("the user's, at prediction");
    let (portable, dest) = target(home.path(), ".config/app/link");

    let mut session = apply_session(&state, home.path());
    session.after_intent = Some(lose_config);
    let err = session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Link {
                text: PathBuf::from("elsewhere"),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::LINK,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the stage made a directory the Intent did not name");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { path, .. }) if *path == dest),
        "got {err}"
    );
    assert!(!config.exists(), "what the stage made is gone again");
}

#[test]
fn a_claim_that_appears_after_the_directory_is_lost_is_still_dropped() {
    // r3 round 7, CL1/COV1. The `r3 round 6` fix makes the home before
    // `fs::stage` looks, so `stage` stops inventing it and the claim
    // filter stops firing — and nothing constrained the filter at all:
    // mutating it left the suite green at 1064 passed, and the "pair"
    // witness only showed that deleting the fix *and* the filter together
    // fails, which deleting the fix alone already does.
    //
    // The filter's one live trigger is the race the fix created: the
    // directory going away between the two calls. `before_stage` produces
    // it, so the branch a race would take is taken here on purpose.
    let guard = guarded_home();
    let home = guard.child("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");

    let mut session = apply_session(&state, &home);
    session.before_stage = Some(|dir| {
        std::fs::remove_dir(dir).expect("lose the directory before stage looks");
    });
    session
        .apply(Request {
            target: portable.clone(),
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned: fs::observe(&dest).expect("plan's observation"),
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect("stage makes the directory again");
    assert!(home.is_dir(), "`stage` made it the second time");

    // `stage` invented the home this time, so the filter is the only thing
    // between that and an Intent the loader refuses.
    let intent = load(&state.journal())
        .expect("load")
        .intents()
        .next()
        .cloned()
        .expect("the Intent");
    assert!(
        intent.created_dirs.is_empty(),
        "the claim on the home was dropped, not recorded: {:?}",
        intent.created_dirs,
    );
    assert!(
        !matches!(
            load(&state.journal()).expect("load"),
            Loaded::Unreadable { .. }
        ),
        "so the journal is still one the loader believes",
    );
    session.finish().expect("finish");
    assert!(
        entry_created_dirs(&state, &home, &portable).is_empty(),
        "and the entry claims none of it either",
    );
}

#[test]
fn a_refused_write_makes_no_directory_at_all() {
    // r3 round 7, D1/COV3. The `create_dir_all` sat ahead of `fs::stage`'s
    // plan-verdict refusals, whose own comment is "before creating
    // anything, so a refusal leaves nothing behind" — so a write refused
    // because the destination changed since plan left the user's home
    // created. Nothing pinned what a refused write leaves on disk.
    let guard = guarded_home();
    let home = guard.child("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    std::fs::create_dir_all(&home).expect("the home, for now");
    plant_file(&dest, "theirs\n", Mode::DEFAULT_FILE);
    let planned = fs::observe(&dest).expect("plan's observation");
    // Everything plan looked at is gone by the time apply runs.
    std::fs::remove_dir_all(guard.child("account")).expect("the user removes the tree");

    let mut session = apply_session(&state, &home);
    let err = session
        .apply(Request {
            target: portable,
            dest: dest.clone(),
            content: Content::Bytes {
                bytes: b"bx\n".to_vec(),
                planned,
            },
            mode: Mode::DEFAULT_FILE,
            ownership: Ownership::Owned(Mechanism::Own),
        })
        .expect_err("the destination is not what plan observed");
    assert!(
        matches!(&err, Error::Write(fs::Error::Changed { detail, .. })
                if detail == "it has been removed"),
        "got {err}"
    );
    assert!(
        !guard.child("account").exists(),
        "a refusal leaves nothing behind — not the home, and not its parent",
    );
    drop(session);
    assert_eq!(
        load(&state.journal()).expect("load").intents().count(),
        0,
        "and nothing was announced",
    );
}

#[test]
fn a_shared_directory_that_cannot_be_made_is_the_write_that_names_it() {
    // r3 round 7, COV2. `create_dir_all`'s error mapping had no test.
    let guard = guarded_home();
    let under = guard.child("locked");
    std::fs::create_dir(&under).expect("mkdir");
    let home = under.join("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    fs::set_mode(&under, Mode::from_bits(0o555)).expect("make it read-only");
    if !permissions_refuse(&under) {
        fs::set_mode(&under, Mode::DEFAULT_DIR).expect("make it writable again");
        return cannot_build(
            "a_shared_directory_that_cannot_be_made_is_the_write_that_names_it",
            WRITES_THROUGH_PERMISSIONS,
        );
    }

    let mut session = apply_session(&state, &home);
    let applied = session.apply(Request {
        target: portable,
        dest: dest.clone(),
        content: Content::Bytes {
            bytes: b"bx\n".to_vec(),
            planned: fs::observe(&dest).expect("plan's observation"),
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Owned(Mechanism::Own),
    });
    // Before any assertion, so the tempdir can be removed whatever happens.
    fs::set_mode(&under, Mode::DEFAULT_DIR).expect("make it writable again");

    let err = applied.expect_err("the shared directory cannot be made");
    // The path named is the one bx asked for, not the component that
    // refused: `create_dir_all` does not say which that was, and
    // `state::dir::ensure_dir` maps its own the same way.
    assert!(
        matches!(&err, Error::Write(fs::Error::Write { path, .. }) if *path == home),
        "got {err}"
    );
}

#[test]
fn a_destination_behind_a_directory_bx_cannot_search_is_a_read_not_a_write() {
    // r3 round 7, D2. `shared_ancestor` read "cannot look" as "not there",
    // so an `EACCES` on the way up became a failed `create_dir_all` and
    // surfaced as `Error::Write` — where looking at the destination
    // surfaces the same permission as `Error::Read`. Since the verdict now
    // comes first, `fs::observe` walks that chain before anything is made,
    // so the read error is what a caller sees; the refined predicate keeps
    // that true if the order ever moves.
    let guard = guarded_home();
    let under = guard.child("sealed");
    std::fs::create_dir(&under).expect("mkdir");
    let home = under.join("account/home");
    let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
    let (portable, dest) = target(&home, ".bashrc");
    // No search bit, so nothing under it can be looked at at all.
    fs::set_mode(&under, Mode::from_bits(0o600)).expect("seal it");
    if std::fs::symlink_metadata(under.join("account"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        fs::set_mode(&under, Mode::DEFAULT_DIR).expect("unseal");
        return cannot_build(
            "a_destination_behind_a_directory_bx_cannot_search_is_a_read_not_a_write",
            WRITES_THROUGH_PERMISSIONS,
        );
    }

    let mut session = apply_session(&state, &home);
    let applied = session.apply(Request {
        target: portable,
        dest: dest.clone(),
        content: Content::Bytes {
            bytes: b"bx\n".to_vec(),
            planned: fs::Observed {
                path: dest.clone(),
                ..fs::observe(&guard.child("elsewhere")).expect("some observation")
            },
        },
        mode: Mode::DEFAULT_FILE,
        ownership: Ownership::Owned(Mechanism::Own),
    });
    // Before any assertion, so the tempdir can be removed whatever happens.
    fs::set_mode(&under, Mode::DEFAULT_DIR).expect("unseal");

    let err = applied.expect_err("bx cannot look at the destination");
    // `observe` reports the path it could not read, which is the deepest
    // one the walk reached — the home here, not the destination beyond it.
    assert!(
        matches!(&err, Error::Write(fs::Error::Read { path, .. }) if *path == home),
        "a permission bx cannot pass is a read, not a write: got {err}"
    );
}

#[test]
fn a_write_makes_the_home_it_needs_and_claims_none_of_it() {
    // r3 round 4 D2, repaired again in r3 round 5 (D1, COV3, CL4).
    //
    // `admit` sees `&[]` for a `Content::Bytes` request — a write's claims
    // do not exist until `fs::stage` has made the parents — so an Intent's
    // `created_dirs` never went through the `stray_created_dir` rule the
    // loader applies to it. At 8e0abc3 the write landed and left an
    // `Unreadable` journal. Round 4 refused it instead, which turned
    // silent corruption into a permanent refusal naming the user's own
    // home: the in-home case below is a *first write to `~/.bashrc`*, and
    // there is nothing the user could do about it.
    //
    // Neither is right. The directory is made — it has to be, to reach the
    // destination — and claimed by nobody: not by the Intent, so the
    // journal stays readable and a rollback's `prune_dirs` cannot reach
    // the home; not by the ledger entry, so a later `rm`'s `prune_claims`
    // cannot either.
    //
    // Both arms need the home absent when the write runs, which needs the
    // state directory elsewhere — `$XDG_STATE_HOME`, as a service account
    // with state under `/var/lib` would have it — since otherwise
    // `state.ensure()` makes the home on its way past.
    for (case, made) in [
        ("in the home", "account/home"),
        ("beside the home", "account"),
    ] {
        let guard = guarded_home();
        let home = guard.child("account/home");
        let state = StateDir::resolve_in(&home, Some(guard.child("elsewhere").as_os_str()));
        assert!(!home.exists(), "{case}: the home is not there yet");
        // In the home the target is `~`-rooted, which is the only spelling
        // the ledger's home check admits; beside it, it is absolute.
        let (portable, dest) = if case == "in the home" {
            target(&home, ".bashrc")
        } else {
            let dest = guard.child("account/beside.conf");
            (
                Portable::try_from(dest.to_str().expect("utf-8").to_string())
                    .expect("a well-formed absolute path"),
                dest,
            )
        };
        let made = guard.child(made);

        let mut session = apply_session(&state, &home);
        assert!(!made.exists(), "{case}: the write makes {}", made.display());
        session
            .apply(Request {
                target: portable.clone(),
                dest: dest.clone(),
                content: Content::Bytes {
                    bytes: b"bx\n".to_vec(),
                    planned: fs::observe(&dest).expect("plan's observation"),
                },
                mode: Mode::DEFAULT_FILE,
                ownership: Ownership::Owned(Mechanism::Own),
            })
            .unwrap_or_else(|e| panic!("{case}: a write bx can make: {e}"));
        assert!(made.is_dir(), "{case}: and it made it");
        assert_eq!(peek(&dest).expect("published").0, b"bx\n", "{case}");

        // The Intent claims none of it, so the journal is one bx believes
        // and a rollback prunes nothing.
        let intent = load(&state.journal())
            .expect("load")
            .intents()
            .next()
            .cloned()
            .unwrap_or_else(|| panic!("{case}: the Intent"));
        assert!(
            intent.created_dirs.is_empty(),
            "{case}: claimed {:?}",
            intent.created_dirs,
        );
        assert!(
            !matches!(
                load(&state.journal()).expect("load"),
                Loaded::Unreadable { .. }
            ),
            "{case}: the journal is one the loader believes",
        );
        session.finish().unwrap_or_else(|e| panic!("{case}: {e}"));

        // And neither does the ledger entry, so `rm` leaves the home.
        let claimed = entry_created_dirs(&state, &home, &portable);
        assert!(claimed.is_empty(), "{case}: the entry claimed {claimed:?}");
        let done = crate::restore::restore(&state, &home, std::slice::from_ref(&portable))
            .unwrap_or_else(|e| panic!("{case}: rm: {e}"));
        assert_eq!(done.len(), 1, "{case}: {done:?}");
        assert!(peek(&dest).is_none(), "{case}: bx's file is gone");
        assert!(made.is_dir(), "{case}: and {} still stands", made.display());
    }
}
