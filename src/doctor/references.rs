//! Check 8: a path a target declares in `references` that is not on disk.
//!
//! A target's `references` name paths its own content points at — the
//! `~/.gitconfig.local` a `~/.gitconfig` includes, the hook script a settings
//! file runs. bx never infers one by reading the content: a reference is only
//! ever what the configuration declares, and this check only asks whether each
//! is there.
//!
//! A reference is looked at only once the target that declares it has been
//! written by bx — the ledger holds an entry for it. Before that the content
//! naming the reference is not on disk, so nothing is broken yet, and `plan`
//! is what shows the target to come. A target held back by an unanswered value
//! is not looked at either: [`super::values`] already names the value, and
//! the reference built from it has no path to look for.
//!
//! Existence is asked the way the content's reader would reach the path,
//! following a link, so a dangling link is as missing as no file. Whether the
//! path needs to be executable is not asked. A path that cannot be looked at
//! at all — a directory on the way denies search — is a finding of its own,
//! since nothing says the reference is there.

use std::path::Path;

use super::Finding;
use crate::config::resolve::Resolution;
use crate::config::target::Target;
use crate::paths::Portable;
use crate::state::LedgerView;

/// A finding for every declared reference of a target bx has written that is
/// not on disk, target by target in configuration order and each target's in
/// the order it declares them.
///
/// `exists` is asked of each reference's rendered path, and answers whether
/// something is there, or why it could not be looked at.
#[must_use]
pub fn check(
    targets: &[Resolution<Target>],
    ledger: &LedgerView,
    home: &Path,
    exists: &dyn Fn(&Path) -> std::io::Result<bool>,
) -> Vec<Finding> {
    targets
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(target) => Some(target),
            Resolution::Blocked(_) => None,
        })
        .filter(|target| !target.references.is_empty() && ledger.get(&target.path).is_some())
        .flat_map(|target| missing(target, home, exists))
        .collect()
}

/// Whether anything is at `path`, following a link.
///
/// # Errors
///
/// Why `path` could not be looked at, when it could not.
pub fn exists(path: &Path) -> std::io::Result<bool> {
    path.try_exists()
}

/// The findings for one written target's references, one per missing path.
fn missing(
    target: &Target,
    home: &Path,
    exists: &dyn Fn(&Path) -> std::io::Result<bool>,
) -> Vec<Finding> {
    let mut seen: Vec<&Portable> = Vec::new();
    let mut findings = Vec::new();
    for reference in &target.references {
        // A path declared twice is one path to look for, and one finding.
        if seen.contains(&reference) {
            continue;
        }
        seen.push(reference);
        let note = match exists(&reference.render(home)) {
            Ok(true) => continue,
            Ok(false) => format!(
                "references {}, which does not exist; create it, or drop it from `references`",
                reference.as_str()
            ),
            Err(error) => format!(
                "references {}, which could not be looked at: {error}",
                reference.as_str()
            ),
        };
        findings.push(Finding {
            subject: target.path.as_str().to_string(),
            origin: Some(target.origin.clone()),
            note,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::inputs;
    use crate::plan::{Mode, run};
    use crate::testing::guarded_home;

    const GITCONFIG: &str = "\
[[target]]
path = \"~/.gitconfig\"
content = \"[include]\\n\\tpath = ~/.gitconfig.local\\n\"
references = [\"~/.gitconfig.local\", \"~/.config/git/hooks\", \"~/.gitconfig.local\"]
";

    fn apply(inputs: &crate::plan::Inputs) {
        run(inputs, Mode::Apply, &mut |_| Ok(true)).expect("apply runs");
    }

    fn ledger(home: &Path) -> LedgerView {
        let state = crate::state::StateDir::resolve(home);
        LedgerView::read(&state, home).unwrap().value
    }

    fn notes(findings: &[Finding]) -> Vec<(&str, &str)> {
        findings
            .iter()
            .map(|f| (f.subject.as_str(), f.note.as_str()))
            .collect()
    }

    #[test]
    fn a_target_not_yet_applied_is_not_looked_at() {
        let home = guarded_home();
        let inputs = inputs(&home, GITCONFIG);
        // On disk, but not bx's: a user's own file is not an applied target.
        home.write(".gitconfig", "[user]\n");

        let findings = check(inputs.targets(), &ledger(home.path()), home.path(), &exists);

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn each_missing_reference_of_an_applied_target_is_its_own_finding() {
        let home = guarded_home();
        let inputs = inputs(&home, GITCONFIG);
        apply(&inputs);

        let findings = check(inputs.targets(), &ledger(home.path()), home.path(), &exists);

        assert_eq!(
            notes(&findings),
            [
                (
                    "~/.gitconfig",
                    "references ~/.gitconfig.local, which does not exist; create it, or drop it \
                     from `references`"
                ),
                (
                    "~/.gitconfig",
                    "references ~/.config/git/hooks, which does not exist; create it, or drop \
                     it from `references`"
                ),
            ]
        );
        assert_eq!(findings[0].origin.as_ref().map(|o| o.line), Some(1));
    }

    #[test]
    fn a_reference_that_exists_is_no_finding_and_a_dangling_link_is_one() {
        let home = guarded_home();
        let inputs = inputs(&home, GITCONFIG);
        apply(&inputs);
        home.write(".gitconfig.local", "[user]\n");
        std::fs::create_dir_all(home.child(".config/git")).unwrap();
        std::os::unix::fs::symlink(home.child("nowhere"), home.child(".config/git/hooks")).unwrap();

        let findings = check(inputs.targets(), &ledger(home.path()), home.path(), &exists);

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .note
                .starts_with("references ~/.config/git/hooks,")
        );

        std::fs::create_dir_all(home.child("nowhere")).unwrap();
        let findings = check(inputs.targets(), &ledger(home.path()), home.path(), &exists);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_reference_that_cannot_be_looked_at_says_why() {
        let home = guarded_home();
        let inputs = inputs(&home, GITCONFIG);
        apply(&inputs);
        let denied = |path: &Path| {
            if path.ends_with(".gitconfig.local") {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(true)
            }
        };

        let findings = check(inputs.targets(), &ledger(home.path()), home.path(), &denied);

        assert_eq!(
            notes(&findings),
            [(
                "~/.gitconfig",
                "references ~/.gitconfig.local, which could not be looked at: permission denied"
            )]
        );
    }

    #[test]
    fn a_target_held_back_by_an_unanswered_value_is_left_to_the_values_check() {
        let home = guarded_home();
        let layer = "[[value]]\nname = \"leaf\"\nkind = \"string\"\nrequired = true\n\
                     [[target]]\npath = \"~/.a\"\ncontent = \"a\\n\"\n\
                     references = [\"~/{{leaf}}\"]\n";
        // Written once with no reference, so the ledger holds its path: even
        // then a target held back is not asked.
        apply(&inputs(
            &home,
            "[[target]]\npath = \"~/.a\"\ncontent = \"a\\n\"\n",
        ));
        let blocked = inputs(&home, layer);
        assert!(matches!(blocked.targets()[0], Resolution::Blocked(_)));

        let findings = check(
            blocked.targets(),
            &ledger(home.path()),
            home.path(),
            &|_| Ok(false),
        );

        assert!(findings.is_empty(), "{findings:?}");
    }
}
