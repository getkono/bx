//! The ledger, read-only: loading it, judging what was stored, and the
//! queries every reader makes.

use std::collections::BTreeMap;
use std::collections::btree_map::Iter;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use super::Ledger;
use super::entry::{
    LedgerEntry, NewEntry, Withdrawal, check_created_dirs, is_ancestor, prior_conflict,
};
use super::{KIND, VERSION};
use crate::state::Error;
use crate::state::dir::StateDir;
use crate::state::lock::ExclusiveLock;
use crate::state::store::{self, Loaded, Loss, Rejected};

/// The ledger, read-only.
///
/// Takes no lock. Every state file is replaced by `rename`, so the worst a
/// reader can see is the previous whole file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerView {
    /// Keyed by target. A `BTreeMap`, never a `HashMap`: iteration order is the
    /// serialised order, and Invariant 3 forbids hash-map order in anything
    /// generated.
    #[serde(default)]
    pub(super) entries: BTreeMap<crate::paths::Portable, LedgerEntry>,
}

impl LedgerView {
    /// Read the ledger without taking a lock.
    ///
    /// A damaged `ledger.mpk` yields [`crate::state::Health::Damaged`] saying so, and
    /// is **left where it is**: a reader holding no lock cannot know that the
    /// path still names the bytes it read, so it renames nothing.
    /// [`Ledger::open`], under the lock, is what quarantines.
    ///
    /// The ledger returned is **what survived**, not always an empty one.
    /// Damage the decoder finds costs the whole file; damage confined to rows
    /// — a key that is not its entry's path, a `created_dirs` entry that is not
    /// above its target — costs those rows and keeps the rest.
    /// [`crate::state::Damage::is_partial`] is what tells the two apart, and a caller
    /// that means *nothing bx wrote is left* has to ask it.
    ///
    /// # Every stored path is checked against `home`
    ///
    /// Decoding a [`crate::paths::Portable`] refuses everything that needs no
    /// home to refuse. It cannot refuse `/var/home/me/.gitconfig`, which is
    /// well-formed and on this account a second key for `~/.gitconfig`: one file
    /// with two entries, two priors, and a `bx rm` that restores whichever it
    /// meets last. So every stored path — each key, each entry's `path`, and
    /// each of its `created_dirs` — goes through
    /// [`crate::paths::Portable::check_against`], and a ledger holding one that
    /// fails is **refused**, never believed and never discarded.
    ///
    /// Refused rather than degraded because the likeliest cause is not a
    /// damaged ledger but the same account with its home spelled another way —
    /// a `/home` → `/var/home` alias, or `HOME=/` — and resetting a good ledger
    /// for that would make the next apply record bx's own output as every prior.
    ///
    /// An entry stored under a key that is not its own `path` is different: bx
    /// never writes one, whatever the home, so that is
    /// [`crate::state::Damage::KeyMismatch`].
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if `ledger.mpk` exists and cannot be read. An unreadable
    /// ledger is not a damaged one: the reversibility record may be perfectly
    /// intact behind the failure, so it is neither quarantined nor replaced,
    /// and the caller must stop rather than proceed against an empty ledger.
    ///
    /// [`Error::ForeignPath`] if a stored path cannot be used with `home`. The
    /// ledger is left exactly as it is.
    ///
    /// [`Error::Home`] if `home` is not absolute or not UTF-8. That is checked
    /// before the file is touched, so a bad home never quarantines a ledger.
    ///
    /// [`Error::FutureVersion`] if a newer bx wrote `ledger.mpk`. The ledger is
    /// left exactly as it is; see [`Ledger::open`].
    pub fn read(dir: &StateDir, home: &Path) -> Result<Loaded<Self>, Error> {
        Self::load(dir, home, None)
    }

    /// Read the ledger, quarantining damage only when `lock` is held.
    pub(super) fn load(
        dir: &StateDir,
        home: &Path,
        lock: Option<&ExclusiveLock>,
    ) -> Result<Loaded<Self>, Error> {
        crate::paths::Portable::parse_in("~", home).map_err(|source| Error::Home {
            home: home.to_path_buf(),
            source,
        })?;
        let path = dir.ledger();
        store::load_checked(
            &path,
            KIND,
            VERSION,
            Loss::Permanent,
            lock,
            |view: &mut Self| view.check_paths(&path, home),
        )
    }

    /// Reject a ledger bx could not have written, or cannot use with `home`.
    ///
    /// The order is: key mismatches across every entry, then the home check,
    /// then directories that are not above their target. `home` has already
    /// been accepted, so the only home failure left is
    /// [`crate::paths::Error::AbsoluteUnderHome`].
    ///
    /// So a key mismatch is never reported as a home problem, but a stray
    /// directory can be: a ledger with a stray directory in one entry and a
    /// path spelled absolutely under the home in another is refused as a home
    /// problem, nothing is renamed or dropped, and the stray is reported only
    /// once the home problem is cleared (r5, C1). That is deliberate, not an
    /// oversight. A `created_dirs` entry spelled absolutely under the home is
    /// itself "not above its target" to the stray test, so running the stray
    /// test first would drop it as damage — quietly losing a directory the
    /// likeliest cause of which is the same account with its home spelled
    /// another way. Refusing the whole ledger loses nothing, and the stray is
    /// still there to be reported on the load after.
    ///
    /// # Damage is isolated to the rows that carry it
    ///
    /// A row stored under a key that is not its own `path` is removed, every
    /// one of them is named in the [`crate::state::Damage::KeyMismatch`], and the
    /// rows that do check out are kept — while the whole file is still moved
    /// aside under the lock, so nothing is lost and a human can see what
    /// happened to it.
    ///
    /// A `created_dirs` entry that is not an ancestor of its own target costs
    /// **that directory** and nothing else: it is dropped from the entry's
    /// list, the entry, its prior and its history are kept, and the loss is
    /// named in a [`crate::state::Damage::UnrelatedCreatedDirs`].
    /// [`check_created_dirs`] refuses one on the way in, so a stored one is
    /// not something bx wrote; left in place it would be sorted among real
    /// ancestors by a depth that says nothing about it, and `bx rm` would
    /// remove a directory it never created for that target. The rule was
    /// enforced on the write path and nowhere on the load path, which is the
    /// half that faces untrusted bytes (r4 round 2, D9).
    ///
    /// Dropping the whole entry for it would take the user's displaced bytes
    /// out of the index — the one thing recomputation cannot rebuild — to be
    /// rid of a bad directory name, which is a larger degradation than the
    /// damage and is what decision 52 forbids (r4 round 3, D2 and CL4).
    ///
    /// # One damage is reported, and it is the whole of what was lost
    ///
    /// The health carries one [`crate::state::Damage`], and
    /// [`crate::state::Damage::is_partial`] promises that what its rows name is the
    /// whole of what the load dropped. So when a file carries both kinds, the
    /// key mismatch is reported **and is the only thing acted on**: the stray
    /// directories are left exactly as they are, the file is quarantined whole
    /// so a human has them, and they are dropped by whichever comes first:
    /// a [`Ledger::save`], which warns, or the next load, which reports
    /// [`crate::state::Damage::UnrelatedCreatedDirs`]. Two passes to converge on a
    /// tampered file, and every report along the way is true. Acting on both while
    /// naming one was the round-2 shape, and it made `is_partial`'s promise
    /// false (r4 round 3, D1).
    ///
    /// **What that costs, and where it is paid.** Between the two loads the
    /// returned value holds a row bx has not yet reported anything about, and
    /// a caller may act on it or write through it before the second load ever
    /// happens. So **every** write refuses to carry it: [`Ledger::record`]
    /// through `merge_created_dirs`, before the entry is handed back, and
    /// [`Ledger::save`] before the bytes reach the file. bx therefore never
    /// writes a file it would go on to call damaged. Round 4 put the rule on
    /// `record` alone and said that was the whole exposure; it was not —
    /// opening a ledger and saving it without re-recording that row wrote the
    /// stray out, and the reread reported it (r4 round 5, D1 and CL1). The
    /// exposure that remains is the returned value itself, in memory, for the
    /// life of one run. `bx rm`, which removes the directories `created_dirs`
    /// names, opens the ledger through this same load, so it acts only on a
    /// ledger this rule has already been through.
    ///
    /// All-or-nothing was the wrong degradation for this file. `CLAUDE.md`
    /// requires a corrupt machine-owned file to degrade to recomputation, and
    /// the ledger is the one state file recomputation cannot rebuild: it holds
    /// the user's prior bytes. One bad row used to cost the restore index for
    /// every target bx manages, leaving the blobs in `restore/` with nothing
    /// naming them. So the degradation is as small as the damage.
    ///
    /// A path that cannot be used with `home` is *not* isolated this way. It
    /// says nothing about the bytes — the likeliest cause is the same account
    /// with its home spelled another way — so the whole ledger is refused and
    /// nothing is renamed or dropped.
    fn check_paths(&mut self, file: &Path, home: &Path) -> Result<(), Rejected> {
        let strip = |rows: Vec<(String, String, crate::paths::Portable)>| {
            rows.into_iter().map(|(a, b, _)| (a, b)).collect()
        };
        let mismatched: Vec<_> = self
            .entries
            .iter()
            .filter(|(key, entry)| **key != entry.path)
            .map(|(key, entry)| {
                (
                    key.as_str().to_string(),
                    entry.path.as_str().to_string(),
                    key.clone(),
                )
            })
            .collect();
        for (.., key) in &mismatched {
            self.entries.remove(key);
        }
        // Between the two damage scans, not after both: a `created_dirs` entry
        // spelled absolutely under the home is a home problem, not damage —
        // the likeliest cause is the same account with its home spelled
        // another way — and it would otherwise be read as a directory that is
        // not above its target and quietly dropped. A salvaged ledger must
        // also be one the next open would accept.
        self.check_against_home(file, home)?;
        // A key mismatch is the graver of the two and is reported alone: the
        // health carries one damage, and `Damage::is_partial` promises that
        // what the rows name is the whole of what was lost. Stripping stray
        // directories here as well would break that promise, because the
        // reported rows would then not be the whole of it. The stray
        // directories keep — the file is quarantined whole, so a human has
        // them — and the next load of the file this one saves strips them and
        // says so. Two loads to converge, and each one's report is true.
        if !mismatched.is_empty() {
            return Err(Rejected::PartialDamage(crate::state::Damage::KeyMismatch {
                rows: strip(mismatched),
            }));
        }
        // A directory that is not above its target costs **that directory**,
        // not the entry. The entry's prior is the user's displaced bytes and
        // the one thing recomputation cannot rebuild; dropping it to be rid of
        // a bad directory name would be a larger degradation than the damage,
        // which is exactly what decision 52 forbids (r4 round 3, D2/CL4).
        let stray = self.strip_unrelated_created_dirs();
        if !stray.is_empty() {
            return Err(Rejected::PartialDamage(
                crate::state::Damage::UnrelatedCreatedDirs { rows: stray },
            ));
        }
        Ok(())
    }

    /// Drop every `created_dirs` entry that is not above its own target,
    /// returning `(target, directory)` for each — ascending by target, and
    /// within a target in the entry's own list order.
    ///
    /// The one statement of the rule on the value, so that the load path,
    /// which reports it as [`crate::state::Damage::UnrelatedCreatedDirs`], and the
    /// write path, which refuses to put it on disk, cannot disagree about what
    /// a stray is (r4 round 5, D1).
    pub(super) fn strip_unrelated_created_dirs(&mut self) -> Vec<(String, String)> {
        let mut stray = Vec::new();
        for entry in self.entries.values_mut() {
            let LedgerEntry {
                path, created_dirs, ..
            } = entry;
            created_dirs.retain(|dir| {
                if is_ancestor(dir, path) {
                    return true;
                }
                stray.push((path.as_str().to_string(), dir.as_str().to_string()));
                false
            });
        }
        stray
    }

    /// Refuse the ledger if any path it stores cannot be used with `home`.
    fn check_against_home(&self, file: &Path, home: &Path) -> Result<(), Rejected> {
        for (key, entry) in &self.entries {
            for stored in std::iter::once(key).chain(&entry.created_dirs) {
                stored.check_against(home).map_err(|source| {
                    Rejected::Refused(Error::ForeignPath {
                        path: file.to_path_buf(),
                        home: home.to_path_buf(),
                        stored: stored.as_str().to_string(),
                        source: Box::new(source),
                    })
                })?;
            }
        }
        Ok(())
    }

    /// The entry for `path`, if bx has written it.
    #[must_use]
    pub fn get(&self, path: &crate::paths::Portable) -> Option<&LedgerEntry> {
        self.entries.get(path)
    }

    /// What [`Ledger::withdraw`] needs to undo the next record of `path`: the
    /// entry as it is now, or that there is none.
    #[must_use]
    pub fn withdrawal(&self, path: &crate::paths::Portable) -> Withdrawal {
        Withdrawal {
            path: path.clone(),
            before: self.entries.get(path).cloned(),
        }
    }

    /// Every entry, in ascending path order.
    pub fn iter(&self) -> Iter<'_, crate::paths::Portable, LedgerEntry> {
        self.entries.iter()
    }

    /// How many targets bx has written.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether bx has written anything.
    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove each of `dirs` that is empty and that no entry this ledger holds
    /// names, deepest first.
    ///
    /// `dirs` are claims — possibly several targets' — so unlike
    /// [`crate::fs::remove::prune_dirs`] a directory that is not empty does not
    /// stop the walk: it is skipped and the rest are tried. Its parents are
    /// not empty either, so they stay too. A claim that is no longer a
    /// directory is skipped the same way, and dropped with its target. A
    /// directory an entry names is somebody's target, whoever claimed it, and
    /// is never removed here.
    ///
    /// # Errors
    ///
    /// [`crate::fs::remove::Error`] for a failure that is neither "already
    /// gone", "not empty" nor "not a directory".
    pub(crate) fn prune_claims<'a>(
        &self,
        home: &Path,
        dirs: impl IntoIterator<Item = &'a PathBuf>,
    ) -> Result<(), crate::fs::remove::Error> {
        let named: std::collections::HashSet<PathBuf> =
            self.iter().map(|(path, _)| path.render(home)).collect();
        let mut dirs: Vec<&PathBuf> = dirs.into_iter().collect();
        dirs.sort_by(|a, b| {
            b.components()
                .count()
                .cmp(&a.components().count())
                .then_with(|| a.cmp(b))
        });
        dirs.dedup();
        for dir in dirs {
            if !named.contains(dir) {
                crate::fs::remove::remove_if_empty(dir)?;
            }
        }
        Ok(())
    }
}

impl LedgerView {
    /// The refusal [`Ledger::record`] would give `entry`, decided without
    /// storing or changing anything.
    ///
    /// For a caller that must not act before it knows the record will be
    /// accepted: a journalled session before it publishes, and a rebuild
    /// before it reports. [`Ledger::record`] applies the same rule.
    ///
    /// # Errors
    ///
    /// [`Error::UnrelatedCreatedDir`] for a `created_dirs` entry that is not
    /// an ancestor of the target, and [`Error::PriorConflict`] for a changed
    /// file bx shares with the user.
    pub fn check_record(&self, entry: &NewEntry) -> Result<(), Error> {
        check_created_dirs(entry)?;
        self.entries.get(&entry.path).map_or(Ok(()), |existing| {
            prior_conflict(existing, &entry.mechanism, &entry.prior)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    use crate::fs::Mode;
    use crate::hash::ContentHash;
    use crate::paths::Portable;
    use crate::state::ledger::fixtures::*;
    use crate::state::ledger::*;
    use crate::state::{Damage, Fingerprints, Health};
    use crate::testing::guarded_home;

    #[test]
    fn a_flipped_version_bit_names_a_way_out_and_says_the_version_looks_damaged() {
        // Review round 5: one flipped bit in the envelope's version byte made
        // an intact ledger `FutureVersion` forever, and the only remedy named
        // — run a newer bx — does not exist.
        #[derive(Serialize)]
        struct Newer<T> {
            kind: &'static str,
            version: u16,
            payload: T,
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry("~/.gitconfig", b"bx").with_prior(prior(b"mine", 0o644)))
            .expect("record");
        ledger.save().expect("save");
        let mut bytes = std::fs::read(dir.ledger()).expect("read");
        let field = b"\xa7version\x01";
        let at = bytes
            .windows(field.len())
            .position(|window| window == field)
            .expect("the version field")
            + field.len()
            - 1;
        bytes[at] ^= 0b10;
        std::fs::write(dir.ledger(), &bytes).expect("flip one bit");
        let aside = format!("{}.corrupt", dir.ledger().display());

        let errors = [
            LedgerView::read(&dir, home.path()).expect_err("the reader refuses"),
            Ledger::open(&dir, &lock, home.path()).expect_err("open refuses"),
        ];
        for err in errors {
            assert!(
                matches!(&err, Error::FutureVersion { found: 3, .. }),
                "got {err}"
            );
            let message = err.to_string();
            for needle in [
                "version number itself may be damaged",
                "move it aside",
                aside.as_str(),
                "empty ledger",
                "can no longer restore",
            ] {
                assert!(message.contains(needle), "missing {needle:?}: {message}");
            }
        }
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), bytes);
        assert!(!StateDir::quarantine(&dir.ledger()).exists());

        // A newer bx's reshaped payload is not called damaged, and the way out
        // is still named.
        let reshaped = rmp_serde::to_vec_named(&Newer {
            kind: KIND,
            version: VERSION + 1,
            payload: ["entries", "reshaped"],
        })
        .expect("encode");
        std::fs::write(dir.ledger(), reshaped).expect("seed");
        let message = Ledger::open(&dir, &lock, home.path())
            .expect_err("open refuses")
            .to_string();
        assert!(!message.contains("may be damaged"), "{message}");
        assert!(message.contains("move it aside"), "{message}");
    }

    #[test]
    fn a_ledger_link_that_loops_or_runs_through_a_file_is_still_refused() {
        // Review round 5 made those degrade for the cache. The ledger is the
        // file nothing rebuilds, so it refuses, as for a link to nothing.
        for looped in [true, false] {
            let home = guarded_home();
            let (dir, lock) = locked(&home);
            let far = if looped {
                dir.ledger()
            } else {
                home.write("a-file", "not a directory");
                home.child("a-file/ledger.mpk")
            };
            std::os::unix::fs::symlink(&far, dir.ledger()).expect("symlink");
            let dangling =
                |err: &Error| matches!(err, Error::DanglingLink { path } if *path == dir.ledger());

            let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
            assert!(dangling(&err), "looped {looped}: got {err}");
            let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
            assert!(dangling(&err), "looped {looped}: got {err}");
            assert_eq!(std::fs::read_link(dir.ledger()).expect("still a link"), far);
            assert!(!StateDir::quarantine(&dir.ledger()).exists());
        }
    }

    #[test]
    fn entries_iterate_in_ascending_portable_order() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        assert_eq!(ledger.len(), 0);
        assert!(ledger.is_empty());
        for name in ["~/z", "~/a", "~/m"] {
            ledger.record(entry(name, b"x")).expect("record");
        }
        assert_eq!(ledger.len(), 3);
        let order: Vec<_> = ledger.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(order, vec!["~/a", "~/m", "~/z"]);
    }

    #[test]
    fn a_read_only_view_opens_with_no_lock_held() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger.record(entry("~/a", b"x")).expect("record");
        ledger.save().expect("save");

        // The exclusive lock is still held, and the reader is unaffected.
        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Loaded);
        assert_eq!(view.value.len(), 1);
    }

    #[test]
    fn a_corrupt_ledger_degrades_to_an_empty_one() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        dir.ensure().expect("ensure");
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");

        let loaded = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(loaded.health, Health::Reset(Damage::Malformed));
        assert!(loaded.value.is_empty());
        assert!(dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_damaged_ledger_that_cannot_be_moved_aside_stops_bx_and_is_never_saved_over() {
        // r3 round 1 (L1b): `Ledger::open` reported `Health::Reset` when the
        // rename failed, a caller that kept only the value saved, and the save
        // replaced the damaged ledger — possibly the only index to the user's
        // restore blobs — that `Reset` said had been kept.
        if rustix::process::geteuid().is_root() {
            // Mode bits deny nothing to root, so the condition cannot be staged.
            // `state::store`'s 255-byte-name test pins the same rule for root.
            return;
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");
        // Readable and searchable, so the ledger is read and judged; not
        // writable, so it cannot be renamed.
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod");
        let result = Ledger::open(&dir, &lock, home.path());
        std::fs::set_permissions(dir.root(), std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        // What a caller that keeps only the value does next. `save` takes
        // `&mut self` since r4 round 5, so the value is moved out of the
        // result and the error is kept beside it.
        let err = match result {
            Ok(loaded) => {
                let mut ledger = loaded.value;
                ledger.save().expect("save");
                panic!("a ledger that cannot be moved aside stops bx");
            }
            Err(err) => err,
        };

        assert_eq!(
            std::fs::read(dir.ledger()).expect("in place"),
            b"not messagepack",
            "the damaged ledger is never replaced",
        );
        assert!(
            matches!(
                &err,
                Error::CannotQuarantine { path, damage: Damage::Malformed, source }
                    if *path == dir.ledger()
                        && source.kind() == std::io::ErrorKind::PermissionDenied
            ),
            "got {err}",
        );
        assert!(err.to_string().contains("by hand"), "{err}");
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_dangling_ledger_symlink_stops_bx_instead_of_reading_as_fresh() {
        // Review round 3: a `ledger.mpk` link to storage that is not mounted
        // read as `Health::Fresh`, and the next save replaced the link.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let far = home.child("unmounted/ledger.mpk");
        std::os::unix::fs::symlink(&far, dir.ledger()).expect("symlink");

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        assert!(
            matches!(&err, Error::DanglingLink { path } if *path == dir.ledger()),
            "got {err}",
        );
        assert!(err.to_string().contains("does not exist"), "{err}");
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::DanglingLink { .. }), "got {err}");
        assert_eq!(std::fs::read_link(dir.ledger()).expect("still a link"), far);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_ledger_from_a_newer_bx_is_refused_and_left_exactly_where_it_is() {
        // Review round 4: a newer format version was damage, so after a
        // rollback to an older bx `Ledger::open` moved an intact ledger aside,
        // the next apply recorded bx's output as every prior, and each rollback
        // added another `.corrupt.N`.
        #[derive(Serialize)]
        struct Newer<T> {
            kind: &'static str,
            version: u16,
            payload: T,
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let newer = VERSION + 1;
        // A payload this build could decode, and one a newer format reshaped.
        let seeds = [
            rmp_serde::to_vec_named(&Newer {
                kind: KIND,
                version: newer,
                payload: LedgerView::default(),
            })
            .expect("encode"),
            rmp_serde::to_vec_named(&Newer {
                kind: KIND,
                version: newer,
                payload: ["entries", "reshaped"],
            })
            .expect("encode"),
        ];
        for seed in seeds {
            std::fs::write(dir.ledger(), &seed).expect("seed");
            let refused = |err: &Error| {
                matches!(
                    err,
                    Error::FutureVersion { path, found, supported, .. }
                        if *path == dir.ledger() && *found == newer && *supported == VERSION
                )
            };

            let err = LedgerView::read(&dir, home.path()).expect_err("the reader refuses");
            assert!(refused(&err), "got {err}");
            // Every rollback opens the ledger again; none of them moves it.
            for _ in 0..3 {
                let err = Ledger::open(&dir, &lock, home.path()).expect_err("open refuses");
                assert!(refused(&err), "got {err}");
                assert!(err.to_string().contains("newer bx"), "{err}");
            }
            assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seed);
            let quarantines: Vec<_> = std::fs::read_dir(dir.root())
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("ledger.mpk."))
                .collect();
            assert!(quarantines.is_empty(), "{quarantines:?}");
        }
    }

    #[test]
    fn a_lockless_view_of_a_damaged_ledger_leaves_it_for_the_lock_holder() {
        // Review round 3: `LedgerView::read` renamed by path with no lock, so a
        // writer's save between the read and the rename lost its ledger.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Damaged(Damage::Malformed));
        assert!(view.value.is_empty());
        assert_eq!(
            std::fs::read(dir.ledger()).expect("left in place"),
            b"not messagepack",
        );
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Reset(Damage::Malformed));
        assert!(!dir.ledger().exists());
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            b"not messagepack",
        );
    }

    #[test]
    fn a_lock_on_another_state_directory_opens_nothing_and_quarantines_nothing() {
        // Review round 4: `Ledger::open` and `Fingerprints::open` accepted any
        // `ExclusiveLock`, so A's lock quarantined B's damaged ledger while B's
        // own bx, holding B's lock, could be saving it.
        let a = guarded_home();
        let b = guarded_home();
        let (dir_a, lock_a) = locked(&a);
        let dir_b = StateDir::resolve(b.path());
        dir_b.ensure().expect("ensure");
        std::fs::write(dir_b.ledger(), b"not messagepack").expect("seed");
        std::fs::write(dir_b.fingerprints(), b"not messagepack").expect("seed");
        let wrong = |err: &Error| {
            matches!(
                err,
                Error::WrongLock { held, needed }
                    if *held == dir_a.lock() && *needed == dir_b.lock()
            )
        };

        let err = Ledger::open(&dir_b, &lock_a, b.path()).expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");
        assert!(err.to_string().contains("Take the lock"), "{err}");
        let err = Fingerprints::open(&dir_b, &lock_a).expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");
        let err = Fingerprints::default()
            .save(&dir_b, &lock_a)
            .expect_err("A's lock is not B's");
        assert!(wrong(&err), "got {err}");

        for file in [dir_b.ledger(), dir_b.fingerprints()] {
            assert_eq!(std::fs::read(&file).expect("in place"), b"not messagepack");
            assert!(!StateDir::quarantine(&file).exists());
        }
    }

    #[test]
    fn a_quarantine_orphaned_by_a_crash_before_the_save_stays_visible() {
        // Review round 4's falsifier: `Ledger::open` quarantined a damaged
        // ledger, bx stopped before `save`, and the next reader and writer saw
        // `Health::Fresh` with the `.corrupt` file reported nowhere.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"not messagepack").expect("seed");
        let first = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert!(first.health.is_reset());
        let aside = vec![StateDir::quarantine(&dir.ledger())];
        assert_eq!(first.quarantined, aside);
        drop(first);

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Fresh);
        assert_eq!(view.quarantined, aside);
        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Fresh);
        assert_eq!(opened.quarantined, aside);
    }

    #[test]
    fn a_second_damaged_ledger_never_replaces_the_first_quarantine() {
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        std::fs::write(dir.ledger(), b"first damaged ledger").expect("seed");
        Ledger::open(&dir, &lock, home.path()).expect("first open");
        std::fs::write(dir.ledger(), b"second damaged ledger").expect("seed again");
        Ledger::open(&dir, &lock, home.path()).expect("second open");

        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("first kept"),
            b"first damaged ledger",
        );
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt.1")).expect("second kept"),
            b"second damaged ledger",
        );
    }

    /// A one-entry ledger for `key`, saved without going through `record`.
    fn seed_ledger(dir: &StateDir, key: Portable, created_dirs: Vec<Portable>) -> Vec<u8> {
        let mut entries = BTreeMap::new();
        entries.insert(
            key.clone(),
            LedgerEntry {
                path: key,
                written: ContentHash::of(b"bx wrote this"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
                created_dirs,
                superseded: Vec::new(),
                superseded_absent: false,
            },
        );
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
        std::fs::read(dir.ledger()).expect("read the seed")
    }

    #[test]
    fn a_ledger_keyed_by_an_absolute_path_under_the_home_is_refused_not_reset() {
        // Decision R3-1 of #4: `/…/home/.gitconfig` decodes, because a decoder
        // has no home, and on this account it is a second key for
        // `~/.gitconfig`. The loader is where the home is, so the loader
        // refuses — and, since review round 3, renames nothing.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let key = absolute_under(&home, ".gitconfig");
        assert!(key.as_str().starts_with('/'), "{key}");
        let seeded = seed_ledger(&dir, key.clone(), Vec::new());

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        let Error::ForeignPath {
            path,
            home: checked,
            stored,
            source,
        } = &err
        else {
            panic!("a foreign key must be refused, got {err}");
        };
        assert_eq!(path, &dir.ledger());
        assert_eq!(checked, home.path());
        assert_eq!(stored, key.as_str());
        assert!(source.to_string().contains("~/.gitconfig"), "{source}");
        assert!(err.to_string().contains(key.as_str()), "names the path");
        assert!(err.to_string().contains("Nothing was changed"), "{err}");

        // Opening for writing goes through the same check, and refuses too.
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");

        // Neither call touched the ledger.
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_home_spelled_through_an_alias_stops_bx_and_leaves_the_ledger_in_place() {
        // Review round 3's falsifier. An apply under one spelling of the home —
        // `/var/home/me`, reached through a `/home/me` alias — records a target
        // named by the other spelling as an absolute path. The next run, under
        // the other spelling, folds that path into its home. That used to
        // quarantine a good ledger, after which the next apply recorded bx's own
        // output as every prior.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let alias = home.child("alias");
        std::os::unix::fs::symlink(home.path(), &alias).expect("alias");

        let mut ledger = Ledger::open(&dir, &lock, &alias).expect("open").value;
        let key = Portable::from_path(&home.child(".foo"), &alias).expect("portable");
        assert!(key.as_str().starts_with('/'), "{key}");
        ledger
            .record(NewEntry::new(
                key,
                ContentHash::of(b"bx"),
                Mode::DEFAULT_FILE,
                Mechanism::Own,
                prior(b"the user wrote this", 0o644),
            ))
            .expect("record");
        ledger.save().expect("save");
        let seeded = std::fs::read(dir.ledger()).expect("read");

        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());

        // The ledger is intact: under the spelling it was written with, it loads.
        let reopened = Ledger::open(&dir, &lock, &alias).expect("reopen");
        assert_eq!(reopened.health, Health::Loaded);
        assert_eq!(reopened.value.len(), 1);
    }

    #[test]
    fn a_root_home_refuses_rather_than_resetting() {
        // `HOME=/` folds every absolute path into the home.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        let seeded = seed_ledger(&dir, outside, Vec::new());

        let err = Ledger::open(&dir, &lock, Path::new("/")).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
    }

    #[test]
    fn a_created_directory_spelled_absolutely_under_the_home_is_refused() {
        // Every stored Portable, not only the keys: `bx rm` removes these.
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        let seeded = seed_ledger(
            &dir,
            target("~/.config/tool/x.conf"),
            vec![target("~/.config/tool"), absolute_under(&home, ".config")],
        );

        let err = LedgerView::read(&dir, home.path()).expect_err("must refuse");
        assert!(
            matches!(
                &err,
                Error::ForeignPath { stored, .. }
                    if *stored == absolute_under(&home, ".config").as_str()
            ),
            "got {err}",
        );
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
    }

    #[test]
    fn a_home_problem_in_one_entry_is_reported_before_a_stray_directory_in_another() {
        // r5 (C1): the order `check_paths` documents. The home check runs
        // before the stray test, so a stray in one entry is not reported while
        // another entry has a home problem — and nothing is renamed or
        // dropped, so the stray is still there for the load after.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut entries = BTreeMap::new();
        for (key, dirs) in [
            (target("~/.aaaa/x.conf"), vec![target("~/.bbbb")]),
            (
                target("~/.config/tool/y.conf"),
                vec![absolute_under(&home, ".config")],
            ),
        ] {
            entries.insert(
                key.clone(),
                LedgerEntry {
                    path: key,
                    written: ContentHash::of(b"x"),
                    mode: Mode::DEFAULT_FILE,
                    mechanism: Mechanism::Own,
                    prior: Prior::Absent,
                    created_dirs: dirs,
                    superseded: Vec::new(),
                    superseded_absent: false,
                },
            );
        }
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
        let seeded = std::fs::read(dir.ledger()).expect("read the seed");

        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must refuse");
        assert!(matches!(err, Error::ForeignPath { .. }), "got {err}");
        assert_eq!(std::fs::read(dir.ledger()).expect("in place"), seeded);
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
    }

    #[test]
    fn a_stored_duplicate_directory_is_not_recorded_again() {
        // r5 (C2): `merge_created_dirs` promised a deduplicated result, and
        // deduplicated only the incoming list. A stored duplicate — which bx
        // never writes — was carried through every re-record.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let file = "~/.config/tool/x.conf";
        seed_ledger(
            &dir,
            target(file),
            vec![target("~/.config/tool"), target("~/.config/tool")],
        );
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(entry(file, b"v2").with_created_dirs(vec![target("~/.config")]))
            .expect("record");
        assert_eq!(
            ledger.get(&target(file)).expect("entry").created_dirs,
            vec![target("~/.config/tool"), target("~/.config")],
        );
    }

    /// A one-entry ledger whose entry names `path` but is stored under `key`.
    fn seed_mismatched(dir: &StateDir, key: Portable, path: Portable) -> Vec<u8> {
        seed_rows(dir, vec![(key, path)])
    }

    /// A ledger of `rows`, each entry stored under the key it is paired with
    /// whether or not that is its own path.
    fn seed_rows(dir: &StateDir, rows: Vec<(Portable, Portable)>) -> Vec<u8> {
        let mut entries = BTreeMap::new();
        for (key, path) in rows {
            entries.insert(
                key,
                LedgerEntry {
                    path,
                    written: ContentHash::of(b"x"),
                    mode: Mode::DEFAULT_FILE,
                    mechanism: Mechanism::Own,
                    prior: Prior::Absent,
                    created_dirs: Vec::new(),
                    superseded: Vec::new(),
                    superseded_absent: false,
                },
            );
        }
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
        std::fs::read(dir.ledger()).expect("read the seed")
    }

    #[test]
    fn a_mismatched_row_costs_its_own_target_and_no_other() {
        // r4 round 1 (CL7): one `KeyMismatch` row rejected the whole ledger, so
        // a single corrupted key in a ledger of fifty targets cost the restore
        // index for all fifty — and left their blobs in `restore/` with
        // nothing naming them. The ledger is the one state file recomputation
        // cannot rebuild, so the degradation has to be as small as the damage.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        // r4 round 2 (COV5): the rows are seeded *out* of storage order, so
        // "in the order the file stores them" — what `rows`' own documentation
        // promises, and what the rendered damage message shows a user — is
        // constrained rather than satisfied by an accident of the fixture.
        let seeded = seed_rows(
            &dir,
            vec![
                (target("~/.dddd"), target("~/.yyyy")),
                (target("~/.cccc"), target("~/.cccc")),
                (target("~/.bbbb"), target("~/.zzzz")),
                (target("~/.aaaa"), target("~/.aaaa")),
            ],
        );
        let damage = Damage::KeyMismatch {
            rows: vec![
                ("~/.bbbb".to_string(), "~/.zzzz".to_string()),
                ("~/.dddd".to_string(), "~/.yyyy".to_string()),
            ],
        };
        assert!(damage.is_partial(), "the rows named are the whole loss");
        assert_eq!(
            damage.to_string(),
            "its entry for ~/.bbbb names a different path, ~/.zzzz; its entry for ~/.dddd names \
             a different path, ~/.yyyy",
            "rendered in storage order, not insertion order",
        );

        for view in [
            LedgerView::read(&dir, home.path()).expect("read"),
            Ledger::open(&dir, &lock, home.path())
                .expect("open")
                .map(|ledger| (*ledger).clone()),
        ] {
            assert_eq!(view.health.damage(), Some(&damage), "every damaged key");
            let kept: Vec<_> = view.value.iter().map(|(path, _)| path.as_str()).collect();
            assert_eq!(kept, vec!["~/.aaaa", "~/.cccc"], "the rows that check out");
        }

        // And the whole file is still kept, so a human can see what happened.
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            seeded,
        );
    }

    #[test]
    fn an_entry_stored_under_a_key_that_is_not_its_path_is_damage() {
        // Review round 3: `check_paths` never compared the two, so an entry for
        // `~/.bbbb` filed under `~/.aaaa` loaded, and `get(~/.aaaa)` answered
        // with another target's record.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let seeded = seed_mismatched(&dir, target("~/.aaaa"), target("~/.bbbb"));
        let damage = Damage::KeyMismatch {
            rows: vec![("~/.aaaa".to_string(), "~/.bbbb".to_string())],
        };

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Damaged(damage.clone()));
        // The one row it had was the damaged one, so nothing is left.
        assert!(view.value.is_empty());
        assert!(damage.to_string().contains("~/.bbbb"), "{damage}");

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Reset(damage));
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            seeded,
        );
    }

    #[test]
    fn a_mismatched_entry_is_damage_before_it_is_a_home_problem() {
        // A key under the home and an entry path spelled absolutely under it:
        // both wrong, and the mismatch is what bx never writes.
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        seed_mismatched(
            &dir,
            target("~/.gitconfig"),
            absolute_under(&home, ".gitconfig"),
        );

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert!(
            matches!(view.health, Health::Damaged(Damage::KeyMismatch { .. })),
            "{:?}",
            view.health,
        );
    }

    #[test]
    fn a_stored_created_dir_that_is_not_above_its_target_is_damage() {
        // r4 round 2 (D9): `check_created_dirs` enforced the ancestor rule on
        // the write path and nothing enforced it on the load path, so a
        // tampered or corrupted `ledger.mpk` could carry a directory that is
        // not above its target. `merge_created_dirs` then sorts it among real
        // ancestors by a depth that means nothing about it, and `bx rm` would
        // remove a directory it never created for that target.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut entries = BTreeMap::new();
        for (key, dirs) in [
            (target("~/.config/tool/x.conf"), vec![target("~/.config")]),
            // Not above it, and not caught by a prefix test alone: `~/.conf`
            // is a string prefix of `~/.config/…` without being a component.
            (target("~/.config/other/y.conf"), vec![target("~/.conf")]),
            // Two strays around a real ancestor, seeded out of sorted order:
            // the rows for one target come back in the entry's own list order,
            // which round 2's COV5 pinned for `KeyMismatch.rows` and the
            // per-directory retain reopened here (r4 round 4, COV4).
            (
                target("~/.cache/z"),
                vec![
                    target("~/.local/share"),
                    target("~/.cache"),
                    target("~/.aaaa"),
                ],
            ),
        ] {
            entries.insert(
                key.clone(),
                LedgerEntry {
                    path: key,
                    written: ContentHash::of(b"x"),
                    mode: Mode::DEFAULT_FILE,
                    mechanism: Mechanism::Own,
                    prior: Prior::Absent,
                    created_dirs: dirs,
                    superseded: Vec::new(),
                    superseded_absent: false,
                },
            );
        }
        let seeded = {
            store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");
            std::fs::read(dir.ledger()).expect("read the seed")
        };

        let damage = Damage::UnrelatedCreatedDirs {
            rows: vec![
                // Ascending by target; within a target, the entry's own list
                // order — `~/.local/share` before `~/.aaaa`, which is neither
                // sorted nor reverse-sorted.
                ("~/.cache/z".to_string(), "~/.local/share".to_string()),
                ("~/.cache/z".to_string(), "~/.aaaa".to_string()),
                ("~/.config/other/y.conf".to_string(), "~/.conf".to_string()),
            ],
        };
        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Damaged(damage.clone()));
        assert!(damage.is_partial(), "the rows named are the whole loss");
        // r4 round 3 (D2, CL4): the entry is **kept** and only the directory is
        // dropped. Losing the entry would take the user's displaced bytes out
        // of the index to be rid of a bad directory name.
        let kept: Vec<_> = view.value.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            kept,
            vec![
                "~/.cache/z",
                "~/.config/other/y.conf",
                "~/.config/tool/x.conf"
            ],
            "every entry survives; only the stray directories go",
        );
        let dirs = |view: &LedgerView, name: &str| {
            view.get(&target(name))
                .expect("entry")
                .created_dirs
                .iter()
                .map(|d| d.as_str().to_string())
                .collect::<Vec<_>>()
        };
        assert!(dirs(&view.value, "~/.config/other/y.conf").is_empty());
        assert_eq!(
            dirs(&view.value, "~/.cache/z"),
            vec!["~/.cache".to_string()],
            "the real ancestor between the two strays survives",
        );
        assert_eq!(
            dirs(&view.value, "~/.config/tool/x.conf"),
            vec!["~/.config".to_string()],
            "a real ancestor is untouched",
        );
        assert!(
            damage.to_string().contains("which is not above it"),
            "{damage}"
        );

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(opened.health, Health::Reset(damage));
        assert_eq!(
            std::fs::read(dir.root().join("ledger.mpk.corrupt")).expect("quarantined"),
            seeded,
        );
    }

    #[test]
    fn recording_through_a_partially_damaged_survivor_never_writes_the_stray_back() {
        // r4 round 4 (D2, COV2): round 3 made a key-mismatch load leave a
        // stray `created_dirs` entry in a surviving row, for the next load to
        // strip. Nothing recorded through such a survivor, and `record` merged
        // the stored list **past** `check_created_dirs` — which validates the
        // incoming entry only — so bx wrote the stray back and the next read
        // reported `UnrelatedCreatedDirs` on a file bx had just written. A
        // file bx produces and then refuses.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut entries = BTreeMap::new();
        // The key mismatch, which is what makes the load leave the stray.
        entries.insert(
            target("~/.aaaa"),
            LedgerEntry {
                path: target("~/.zzzz"),
                written: ContentHash::of(b"x"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
                created_dirs: Vec::new(),
                superseded: Vec::new(),
                superseded_absent: false,
            },
        );
        // The survivor, carrying one real ancestor and one stray.
        entries.insert(
            target("~/.config/tool/x.conf"),
            LedgerEntry {
                path: target("~/.config/tool/x.conf"),
                written: ContentHash::of(b"x"),
                mode: Mode::DEFAULT_FILE,
                mechanism: Mechanism::Own,
                prior: Prior::Absent,
                created_dirs: vec![target("~/.config/tool"), target("~/.cache")],
                superseded: Vec::new(),
                superseded_absent: false,
            },
        );
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");

        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert!(matches!(
            opened.health,
            Health::Reset(Damage::KeyMismatch { .. })
        ));
        let mut ledger = opened.value;
        assert_eq!(
            ledger
                .get(&target("~/.config/tool/x.conf"))
                .expect("survivor")
                .created_dirs
                .len(),
            2,
            "the stray is still there, because the load reported only the key mismatch",
        );

        // A re-record of the survivor. The merge drops the stray and says so.
        let (_, said) = crate::state::store::capture::capturing(|| {
            ledger
                .record(
                    entry("~/.config/tool/x.conf", b"again")
                        .with_created_dirs(vec![target("~/.config/tool")]),
                )
                .expect("record");
        });
        assert!(said.contains("is not above"), "{said}");
        assert!(said.contains("~/.cache"), "{said}");
        ledger.save().expect("save");

        // And the file bx just wrote loads clean.
        let reread = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(
            reread.health,
            Health::Loaded,
            "bx must not write a file it would then report as damaged",
        );
        assert_eq!(
            reread
                .value
                .get(&target("~/.config/tool/x.conf"))
                .expect("entry")
                .created_dirs
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>(),
            vec!["~/.config/tool"],
        );
    }

    #[test]
    fn a_ledger_damaged_both_ways_reports_and_acts_on_the_graver_only() {
        // r4 round 3 (D1, COV1): with both kinds of row damage present the
        // round-2 code dropped both row sets and named only the key mismatch,
        // which makes `Damage::is_partial`'s promise — that what the rows name
        // is the whole of what was lost — false. And no test staged both, so
        // the "graver of the two" selection was reached by nothing.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut entries = BTreeMap::new();
        for (key, path, dirs) in [
            // A key that is not its entry's path: the graver damage.
            (target("~/.aaaa"), target("~/.zzzz"), Vec::<Portable>::new()),
            // A stray `created_dirs` entry, in a row whose key is its path.
            (
                target("~/.config/tool/x.conf"),
                target("~/.config/tool/x.conf"),
                vec![target("~/.config/tool"), target("~/.cache")],
            ),
        ] {
            entries.insert(
                key,
                LedgerEntry {
                    path,
                    written: ContentHash::of(b"x"),
                    mode: Mode::DEFAULT_FILE,
                    mechanism: Mechanism::Own,
                    prior: Prior::Absent,
                    created_dirs: dirs,
                    superseded: Vec::new(),
                    superseded_absent: false,
                },
            );
        }
        store::save(&dir.ledger(), KIND, VERSION, &LedgerView { entries }).expect("seed");

        // The first load names the key mismatch, and *only* the key mismatch
        // is acted on: the stray directory is still there.
        let first = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(
            first.health,
            Health::Damaged(Damage::KeyMismatch {
                rows: vec![("~/.aaaa".to_string(), "~/.zzzz".to_string())],
            }),
            "the graver of the two",
        );
        let survivor = first
            .value
            .get(&target("~/.config/tool/x.conf"))
            .expect("kept");
        assert_eq!(
            survivor
                .created_dirs
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>(),
            vec!["~/.config/tool", "~/.cache"],
            "untouched, because the reported rows do not name it",
        );

        // Under the lock the same verdict, and the file is quarantined.
        let opened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert!(matches!(
            opened.health,
            Health::Reset(Damage::KeyMismatch { .. })
        ));
        let mut ledger = opened.value;

        // r4 round 5 (D1): the save the caller makes **strips the stray** and
        // warns, rather than writing it out for a second load to find. Round 4
        // put that rule on `record` only, so a save without a re-record of
        // that row put the stray on disk and the reread reported it — bx
        // writing a file it then called damaged.
        let (saved, said) = crate::state::store::capture::capturing(|| ledger.save());
        saved.expect("save the survivors");
        assert!(said.contains("is not above"), "{said}");
        assert!(said.contains("~/.cache"), "{said}");

        // So the file bx just wrote loads clean, with the entry intact.
        let second = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(
            second.health,
            Health::Loaded,
            "bx must not write a file it would then report as damaged",
        );
        let entry = second
            .value
            .get(&target("~/.config/tool/x.conf"))
            .expect("the entry survives");
        assert_eq!(
            entry
                .created_dirs
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>(),
            vec!["~/.config/tool"],
            "the real ancestor stays, the stray goes",
        );
    }

    #[test]
    fn an_absolute_path_outside_the_home_is_still_trusted() {
        let home = guarded_home();
        let (dir, _lock) = locked(&home);
        let outside = Portable::try_from("/etc/bx-example.conf".to_string()).expect("absolute");
        let above = Portable::try_from("/etc".to_string()).expect("absolute");
        seed_ledger(&dir, outside.clone(), vec![above]);

        let view = LedgerView::read(&dir, home.path()).expect("read");
        assert_eq!(view.health, Health::Loaded);
        assert!(view.value.get(&outside).is_some());
    }

    #[test]
    fn a_home_the_ledger_cannot_be_checked_against_quarantines_nothing() {
        // A bad home is the caller's defect. Reading it as damage would move an
        // intact ledger aside and let the next apply record over nothing.
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let seeded = seed_ledger(&dir, target("~/.gitconfig"), Vec::new());

        let err = LedgerView::read(&dir, Path::new("relative/home")).expect_err("must fail");
        assert!(matches!(err, Error::Home { .. }), "got {err}");
        assert!(err.to_string().contains("relative/home"), "{err}");
        let err = Ledger::open(&dir, &lock, Path::new("relative/home")).expect_err("must fail");
        assert!(matches!(err, Error::Home { .. }), "got {err}");
        assert!(!dir.root().join("ledger.mpk.corrupt").exists());
        assert_eq!(std::fs::read(dir.ledger()).expect("intact"), seeded);
    }

    #[test]
    fn an_unreadable_ledger_stops_bx_instead_of_resetting_it() {
        if rustix::process::geteuid().is_root() {
            // `0000` denies nothing to root; see the note in `state::store`.
            return;
        }
        let home = guarded_home();
        let (dir, lock) = locked(&home);
        let mut ledger = Ledger::open(&dir, &lock, home.path()).expect("open").value;
        ledger
            .record(
                entry("~/.bashrc", b"bx wrote this").with_prior(PriorBytes::Bytes {
                    bytes: b"the user wrote this".to_vec(),
                    mode: Mode::DEFAULT_FILE,
                }),
            )
            .expect("record");
        ledger.save().expect("save");
        let intact = std::fs::read(dir.ledger()).expect("read");

        std::fs::set_permissions(dir.ledger(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");

        // Opening for writing must fail. Degrading here would record bx's own
        // output as every target's prior on the next apply, and `bx rm` would
        // then write bx's generated content over the user's files.
        let err = Ledger::open(&dir, &lock, home.path()).expect_err("must fail");
        assert!(matches!(err, Error::Read { .. }), "got {err}");
        assert!(
            LedgerView::read(&dir, home.path()).is_err(),
            "the reader must fail too"
        );
        assert!(
            !dir.root().join("ledger.mpk.corrupt").exists(),
            "an unreadable ledger must never be quarantined",
        );

        std::fs::set_permissions(dir.ledger(), std::fs::Permissions::from_mode(0o600))
            .expect("restore");
        assert_eq!(std::fs::read(dir.ledger()).expect("read"), intact);
        let reopened = Ledger::open(&dir, &lock, home.path()).expect("open");
        assert_eq!(reopened.health, Health::Loaded);
        let stored = reopened.value.get(&target("~/.bashrc")).expect("entry");
        let Prior::Existed(reference) = &stored.prior else {
            panic!("the user's prior must have survived");
        };
        assert_eq!(reference.digest, ContentHash::of(b"the user wrote this"));
    }
}
