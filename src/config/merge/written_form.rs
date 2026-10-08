//! Reducing a target's spelling with its placeholders left unanswered.
//!
//! [`written_form`] is the lexical reduction, and [`one_path_as_written`] the
//! comparison built on it: two spellings with one form name one file for every
//! answer, so a layer naming both is the repo's defect rather than the
//! account's. What the reduction does not decide is registered under *Shapes
//! the written form does not decide* in the [`merge` module](super).

use crate::config::values::{Piece, ResolvedValues, ValueKind, scan};

/// Whether two spellings name one file whatever is answered.
///
/// When their [`written_form`]s are identical. The same answers put into one
/// form give one text, so identical forms name one file for every answer, or no
/// file for any: the comparison is sound. It is complete over the shapes the
/// fixed-seed property test generates: there, forms that differ are parted by
/// some answer, so the collision is one the account can clear. It is not
/// complete over every spelling. The shapes it is known not to decide are
/// registered and executed as `UNDECIDED`, under *Shapes the written form does
/// not decide* in the [module documentation](super).
///
/// [`clash`](super::target_key) compares only spellings whose keys are one
/// `TargetKey::File`, so every placeholder in either is declared, enabled and
/// answered: a substitution that failed would have keyed the spelling as
/// written. `anchored` also compares a toggle with every declared spelling,
/// whatever its key. Soundness does not rest on the keys, so the verdict holds
/// there too, and a spelling with no form counts as not one path, which errs
/// toward the removal hint, every act of which can be followed.
pub(super) fn one_path_as_written(first: &str, second: &str, values: &ResolvedValues) -> bool {
    written_form(first, values).is_some_and(|form| Some(form) == written_form(second, values))
}

/// A spelling reduced by the lexical rule, with its placeholders unanswered.
#[derive(Debug, PartialEq, Eq)]
struct WrittenForm<'a> {
    root: Root<'a>,
    segments: Vec<Segment<'a>>,
}

/// Where a [`WrittenForm`] is rooted.
///
/// Part of the form [`one_path_as_written`] compares, which is sound and
/// complete over the shapes the fixed-seed property test generates; the known
/// shapes it does not decide are listed under *Shapes the written form does not
/// decide* in the [module documentation](self).
#[derive(Debug, PartialEq, Eq)]
enum Root<'a> {
    /// `/`, or a `path` value opening the spelling, alone or with text glued
    /// after it. Every `path` answer is absolute, so a `path` value starts its
    /// own segment (see [`written_form`]).
    Absolute,
    /// `~`, whether a `/` or a `path` value follows it.
    Home,
    /// Whatever the answers make of the first segment, which the lexical rule
    /// cannot see into: an answer may root it at `~`, at `/`, or not at all.
    /// Whether anything follows it matters as well, since an empty answer makes
    /// the segment nothing, and the segment with a separator after it `/`,
    /// but only when every piece of the segment is a `string` placeholder: any
    /// other piece is never empty, and a text that is not empty is one path
    /// with a separator after it or without, so `followed` is then `false`.
    Opening {
        first: Vec<Piece<'a>>,
        followed: bool,
    },
}

/// One segment of a [`WrittenForm`].
#[derive(Debug, PartialEq, Eq)]
enum Segment<'a> {
    /// One ordinary segment whatever is answered: literal text, or text whose
    /// only placeholders are `bool`s, whose answers are never empty and never
    /// hold a `/`. A `..` cancels it.
    Fixed(Vec<Piece<'a>>),
    /// A segment holding a placeholder an answer may make empty, `.`, `..`, or
    /// several segments. Nothing cancels it.
    Opaque(Vec<Piece<'a>>),
    /// A `..` that nothing written before it can be shown to cancel.
    Up,
}

/// `spelling` reduced by the lexical rule, deciding nothing an answer decides.
///
/// The form is sound: identical forms name one file for every answer, or none.
/// It is complete over the shapes the fixed-seed property test generates; the
/// shapes it is known not to decide are registered and executed as `UNDECIDED`,
/// under *Shapes the written form does not decide* in the [module
/// documentation](self).
///
/// A `path` value starts its own segment wherever it sits, as though a `/` were
/// written before it. That changes no file. A `path` answer is absolute and
/// normalised, so its text begins with exactly one `/`, and substituting it
/// after text `x` gives `x/…`, where the spelling with the `/` written gives
/// `x//…`. The two texts differ only by one doubled separator, and keying a
/// path reads a doubled separator as one wherever it falls. At the start, `/…`
/// and `//…` both have the root `/` and a rest with its leading `/` stripped.
/// After a text that is exactly `~`, `~/…` and `~//…` both have the root `~`.
/// After a text that starts with `/` or `~/`, the doubled separator is inside
/// the path and folds. After any other text, neither is a portable path. So the
/// rule holds for
/// every `path` answer, including `/`, `~`, `~/…` and `//srv/`, which are
/// stored as `/`, the home, a path under the home and `/srv`.
///
/// A `.` and an empty segment fold, and a `..` cancels the [`Segment::Fixed`]
/// before it. A `..` after anything else stays in the form, except at `/`, where
/// there is nothing above to climb to; under `~` it is the climb out of the home
/// that no answer rescues.
///
/// A segment is compared by its pieces. A new literal piece starts only after a
/// `{{{{` escape, so a segment spelled `.` or `..` is always one literal piece.
///
/// `None` when `spelling` is not a well-formed template. That is defensive: a
/// spelling keyed as a file substituted, and substitution scans the same text.
fn written_form<'a>(spelling: &'a str, values: &ResolvedValues) -> Option<WrittenForm<'a>> {
    // A name no layer declares is taken as the widest kind. That too is
    // defensive, for the reason `None` is.
    let is = |piece: &Piece<'_>, kind: ValueKind| {
        matches!(piece, Piece::Name(name)
            if values.decl(name).is_some_and(|decl| decl.kind == kind))
    };
    // Only a `string` answer may be empty; a literal piece never is.
    let may_be_empty = |piece: &Piece<'_>| {
        matches!(piece, Piece::Name(name)
            if values.decl(name).is_none_or(|decl| decl.kind == ValueKind::String))
    };

    let mut split: Vec<Vec<Piece<'a>>> = Vec::new();
    let mut current: Vec<Piece<'a>> = Vec::new();
    for piece in scan(spelling).ok()? {
        match piece {
            Piece::Literal(text) => {
                for (index, chunk) in text.split('/').enumerate() {
                    if index > 0 {
                        split.push(std::mem::take(&mut current));
                    }
                    if !chunk.is_empty() {
                        current.push(Piece::Literal(chunk));
                    }
                }
            }
            name @ Piece::Name(_) => {
                // A `path` answer begins with `/`, so the value starts a
                // segment wherever it sits: `x{{r}}` is split as `x/{{r}}` is.
                // What was before it ends there, as an empty segment when
                // nothing was, which folds, or at the start roots the spelling
                // at `/`.
                if is(&name, ValueKind::Path) {
                    split.push(std::mem::take(&mut current));
                }
                current.push(name);
            }
        }
    }
    split.push(current);

    let mut split = split.into_iter();
    // Never the default: the scan loop above is always followed by a final
    // push, so `split` holds at least one segment, even for an empty spelling.
    let first = split.next().unwrap_or_default();
    let followed = !split.as_slice().is_empty();
    let root = if first.is_empty() && followed {
        Root::Absolute
    } else if first == [Piece::Literal("~")] {
        Root::Home
    } else {
        // An empty spelling lands here too, as an empty opening segment with
        // nothing after it. That is defensive: `Portable::parse_in("")` refuses
        // it, so it is never keyed as a file and never reaches `clash`'s
        // comparison.
        //
        // What follows the opening segment parts two spellings only when an
        // answer can make that segment nothing: a non-empty text is one path
        // with a separator after it or without.
        let followed = followed && first.iter().all(may_be_empty);
        Root::Opening { first, followed }
    };

    let mut segments = Vec::new();
    for segment in split {
        if segment.is_empty() || segment == [Piece::Literal(".")] {
            continue;
        }
        if segment == [Piece::Literal("..")] {
            match segments.last() {
                Some(Segment::Fixed(_)) => {
                    segments.pop();
                }
                None if root == Root::Absolute => {}
                _ => segments.push(Segment::Up),
            }
            continue;
        }
        let fixed = segment
            .iter()
            .all(|piece| matches!(piece, Piece::Literal(_)) || is(piece, ValueKind::Bool));
        segments.push(if fixed {
            Segment::Fixed(segment)
        } else {
            Segment::Opaque(segment)
        });
    }
    Some(WrittenForm { root, segments })
}

#[cfg(test)]
mod tests {
    use super::super::target_key::TargetKey;
    use super::super::tests::{failure, global, home, local, merge, target_toml};
    use super::*;
    use crate::config::values::{ValueAssignment, ValueDecl};
    use crate::config::{Origin, parse_str};
    use std::path::{Path, PathBuf};

    /// The homes the written-form properties are asserted over.
    ///
    /// The home is one of the axes, not a fixture detail: `Portable::parse_in`
    /// folds against it and can refuse an absolute path under it, so which file
    /// a spelling names is home-dependent. `/` is the degenerate one — `~` and
    /// `/` coincide there and a `..` under the home has no parent to climb to —
    /// and a pair that is one file under one home and two under another is a
    /// property of that account rather than of the rule.
    fn homes() -> [PathBuf; 2] {
        [home(), PathBuf::from("/")]
    }

    /// Every answer set drawn against `at`, each labelled with its answers.
    fn answer_sets_at(at: &Path) -> Vec<(String, ResolvedValues)> {
        use crate::config::values::AssignedValue;

        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let decls = || {
            vec![
                decl("p", ValueKind::String),
                decl("q", ValueKind::String),
                decl("f", ValueKind::Bool),
                decl("r", ValueKind::Path),
                decl("e", ValueKind::Email),
            ]
        };
        let assign = |name: &str, value: AssignedValue| ValueAssignment {
            name: name.into(),
            value,
            origin: Origin::unknown(Path::new("local.toml")),
        };
        // Deep answers first: they part most pairs, so most pairs stop early.
        let strings = [
            "a/b/c/d/e/f/g/h",
            "/a/b/c/d/e/f/g/h",
            "a",
            "a/b",
            "",
            ".",
            "..",
            "../..",
            "/a",
            "~",
            "~/a",
            "a/",
            "a/..",
        ];
        let others = ["b/c/d/e/f/g/h/i", "b", ""];
        let roots = ["/srv/d/e/f/g/h/i/j", "/srv", "/", "/var/home/example"];
        // An address may hold a `/`, so it too can root a spelling or climb.
        let emails = ["/a@b/c/d/e/f/g/h", "~/m@n"];
        let mut answers = Vec::new();
        for p in strings {
            for q in others {
                for r in roots {
                    for e in emails {
                        for f in [true, false] {
                            let given = [
                                assign("p", AssignedValue::String(p.into())),
                                assign("q", AssignedValue::String(q.into())),
                                assign("f", AssignedValue::Bool(f)),
                                assign("r", AssignedValue::String(r.into())),
                                assign("e", AssignedValue::String(e.into())),
                            ];
                            if let Ok(values) = ResolvedValues::resolve(decls(), &given, at) {
                                answers.push((
                                    format!(
                                        "home={} p={p:?} q={q:?} f={f} r={r:?} e={e:?}",
                                        at.display()
                                    ),
                                    values,
                                ));
                            }
                        }
                    }
                }
            }
        }
        answers
    }

    /// Every answer set, over every home.
    ///
    /// The fuzz asserts over all of them at once, which is the strict
    /// direction: more answers can only part more pairs, so soundness is
    /// checked harder and completeness is never weakened.
    fn answer_sets() -> Vec<(String, ResolvedValues)> {
        homes().iter().flat_map(|at| answer_sets_at(at)).collect()
    }

    /// How `first` and `second` key across `answers`: whether some answer gives
    /// them one file, and the first answer that gives them different keys.
    ///
    /// This decides nothing on its own: it reports over whatever `answers` it
    /// is handed. A pair is **undecided** when some answer met, none parted,
    /// and [`one_path_as_written`] says false — for `answers` **drawn against
    /// one home**, which is the only set over which that conjunction is the
    /// account's experience. `UNDECIDED`'s test is what applies it that way;
    /// handing this the union of every home asks a different and stricter
    /// question, and one registered pair does not survive it.
    fn keying(
        first: &str,
        second: &str,
        answers: &[(String, ResolvedValues)],
    ) -> (bool, Option<String>) {
        let mut met = false;
        for (label, values) in answers {
            let (key_a, key_b) = (TargetKey::of(first, values), TargetKey::of(second, values));
            match (&key_a, &key_b) {
                (TargetKey::File(x), TargetKey::File(y)) if x == y => met = true,
                (TargetKey::AsWritten(_), TargetKey::AsWritten(_)) => {}
                _ => return (met, Some(format!("{label}: {key_a:?} against {key_b:?}"))),
            }
        }
        (met, None)
    }

    #[test]
    fn one_path_as_written_agrees_with_every_answer_in_a_fuzzed_set() {
        // Soundness: a pair the rule calls one path has one key, or no key, under
        // every answer below. Completeness over that set: a pair it does not call
        // one path, which some answer gives one key, is parted by another answer,
        // so the block its hint describes is one an answer can clear. The pairs
        // come from a fixed seed, so every run tries the same ones.
        use std::collections::HashSet;

        let answers = answer_sets();

        let segments = [
            "x",
            "y",
            ".",
            "..",
            "..",
            "..",
            "",
            "~",
            "{{p}}",
            "{{q}}",
            "a{{p}}",
            "{{p}}b",
            "{{p}}{{q}}",
            "{{f}}",
            "x{{f}}",
            "{{r}}",
            "x{{r}}",
            "..{{r}}",
        ];
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut pick = move |n: usize| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(seed >> 33).expect("a 31-bit value fits") % n
        };

        let (mut proven, mut parted) = (0, 0);
        let mut unsound: Vec<String> = Vec::new();
        let mut incomplete: Vec<String> = Vec::new();
        let mut tried = HashSet::new();
        for _ in 0..3000 {
            let root = ["~/", "/", ""][pick(3)];
            let len = 1 + pick(5);
            let mut first: Vec<&str> = (0..len).map(|_| segments[pick(segments.len())]).collect();
            // A spelling with no root opens with a placeholder: alone, with text
            // glued on, after a `~`, of a kind no answer makes empty, or with a
            // second placeholder beside it.
            if root.is_empty() {
                let openers = [
                    "{{r}}",
                    "{{p}}",
                    "{{r}}.d",
                    "{{r}}x",
                    "~{{r}}",
                    "~{{p}}",
                    "{{e}}",
                    "{{r}}{{p}}",
                    "{{p}}{{r}}",
                ];
                first[0] = openers[pick(openers.len())];
            }
            let mut second: Vec<String> = first.iter().map(|s| (*s).to_string()).collect();
            for _ in 0..=pick(3) {
                let at = if second.len() > 1 {
                    (1 + pick(second.len())).min(second.len())
                } else {
                    second.len()
                };
                match pick(8) {
                    0 => second.insert(at, ".".into()),
                    1 => second.insert(at, "..".into()),
                    2 if second.len() > 1 && at < second.len() => {
                        second.remove(at);
                    }
                    3 if at < second.len() => second[at] = segments[pick(segments.len())].into(),
                    4 => {
                        second.insert(at, "..".into());
                        second.insert(at, "x".into());
                    }
                    // Glue: a `path` value that starts a segment is joined onto
                    // the text before it, taking the `/` between them away.
                    5 => {
                        let led: Vec<usize> = (1..second.len())
                            .filter(|&i| second[i].starts_with("{{r}}"))
                            .collect();
                        if !led.is_empty() {
                            let i = led[pick(led.len())];
                            let glued = second.remove(i);
                            second[i - 1].push_str(&glued);
                        }
                    }
                    // Unglue: a `path` value glued after other text is split off
                    // into its own segment, putting a `/` before it.
                    6 => {
                        let glued: Vec<usize> = (0..second.len())
                            .filter(|&i| second[i].find("{{r}}").is_some_and(|at| at > 0))
                            .collect();
                        if !glued.is_empty() {
                            let i = glued[pick(glued.len())];
                            let split = second[i].find("{{r}}").expect("found above");
                            let rest = second[i].split_off(split);
                            second.insert(i + 1, rest);
                        }
                    }
                    _ => second.insert(at, String::new()),
                }
            }
            let a = format!("{root}{}", first.join("/"));
            let mut b = format!("{root}{}", second.join("/"));
            // A leading `/` before a placeholder that opens the spelling.
            if root.is_empty() && pick(4) == 0 {
                b.insert(0, '/');
            }
            // A `/` before a `path` value taken away, a root's own included:
            // `/{{r}}` becomes `{{r}}` and `~/{{r}}` becomes `~{{r}}`.
            let slashed: Vec<usize> = b.match_indices("/{{r}}").map(|(at, _)| at).collect();
            if !slashed.is_empty() && pick(3) == 0 {
                b.remove(slashed[pick(slashed.len())]);
            }
            if a == b || !tried.insert((a.clone(), b.clone())) {
                continue;
            }

            let one_path = one_path_as_written(&a, &b, &answers[0].1);
            let (met, apart) = keying(&a, &b, &answers);
            match (one_path, apart) {
                (true, Some(why)) => unsound.push(format!("{a:?} and {b:?}, parted by {why}")),
                (true, None) => proven += 1,
                (false, Some(_)) => parted += 1,
                (false, None) if met => incomplete.push(format!("{a:?} and {b:?}")),
                (false, None) => {}
            }
        }

        assert!(
            unsound.is_empty(),
            "{} pairs called one path were parted by an answer:\n{}",
            unsound.len(),
            unsound[..unsound.len().min(10)].join("\n")
        );
        // Completeness is asserted **over the shapes generated above**, not
        // over every spelling. The `segments` and `openers` arrays are what
        // bounds it, and that exclusion is load-bearing: the pairs `UNDECIDED`
        // holds are known to be undecided and are deliberately not generated.
        // Widening either array will turn one of them red — the same fact
        // `every_pair_the_written_form_is_known_to_miss_is_still_missed`
        // records, not a second obligation. The repair is to decide the shape
        // in `written_form`, then move the pair out of `UNDECIDED` and into
        // these arrays — never to weaken this assertion.
        assert!(
            incomplete.is_empty(),
            "{} pairs no answer parts were not called one path:\n{}",
            incomplete.len(),
            incomplete[..incomplete.len().min(10)].join("\n")
        );
        assert!(
            proven >= 100 && parted >= 100,
            "the set must exercise both verdicts: {proven} one path, {parted} parted"
        );
    }

    /// The pairs the written form is known **not** to decide.
    ///
    /// For each, there is **some home** under which every answer
    /// [`answer_sets_at`] draws keys the two spellings as one file, and the two
    /// written forms differ anyway. Per home, and not over the union of them:
    /// one entry below is one file for every answer only under a home of `/`,
    /// and an account under that home has the unclearable block just the same.
    /// That is the criterion
    /// `every_pair_the_written_form_is_known_to_miss_is_still_missed`
    /// executes — stated here in the words it executes, because a header
    /// asserting the broader "under every answer" is the exact failure this
    /// register replaced prose to end.
    ///
    /// This is the register the module
    /// documentation points at, kept here rather than in prose so that it is
    /// re-derived on every run: a pair that stops being undecided fails
    /// `every_pair_the_written_form_is_known_to_miss_is_still_missed`, and a
    /// pair nobody can reproduce cannot be added.
    ///
    /// Every entry is an **open defect**, registered rather than repaired, and
    /// that is a decision: the pair loads `Ok` and the file it names is blocked
    /// as a [`Conflict`] no answer clears. Its hint does not ask for one: a
    /// toggle the written form cannot anchor to a declared spelling is named
    /// for removal instead. Deciding one means
    /// widening the reduction, and every rule proposed for these shapes so far
    /// has been refuted — `REFUTED` holds each with the answers that killed it,
    /// which is why no general rule is claimed and why adding a pair here is a
    /// disposition rather than a delay. The repair for one is to decide it in
    /// [`written_form`], prove the decision against
    /// `one_path_as_written_agrees_with_every_answer_in_a_fuzzed_set`, and then
    /// move the pair out of here and into that test's generators — never to
    /// weaken either assertion.
    const UNDECIDED: [(&str, &str, &str); 9] = [
        (
            "{{p}}",
            "{{p}}/",
            "under a home of `/` alone: a trailing separator after an opening \
             placeholder, where the home is the root the empty answer names",
        ),
        (
            "~/{{p}}x/..",
            "~/{{p}}y/..",
            "literal text glued after a placeholder, ending the segment the \
             following `..` cancels",
        ),
        (
            "{{r}}./..",
            "{{r}}/..",
            "glue after a `path` value where nothing but the root `/` stands above it",
        ),
        ("{{r}}x/..", "{{r}}/..", "the same, with the glue not a dot"),
        (
            "/opt/{{r}}../../conf",
            "/opt/{{r}}/../conf",
            "a `..` glued after a `path` value that climbs through every fixed \
             segment above it to `/`",
        ),
        (
            "/opt/{{r}}x/../../conf",
            "/opt/{{r}}/../../conf",
            "the same climb, with the glue not a dot",
        ),
        (
            "/a/b/{{r}}../../..",
            "/a/b/{{r}}/../..",
            "the same climb, from two fixed segments",
        ),
        (
            "~/{{p}}{{f}}/..",
            "~/{{p}}x/..",
            "a glued tail holding a `bool`, whose answer is never empty, never \
             only dots and never holds a `/`, so the `..` cancels the segment \
             either way",
        ),
        (
            "~{{p}}/.{{p}}",
            "~{{p}}/{{p}}",
            "an opening occurrence limits which answers name a file at all, and \
             each occurrence is read on its own",
        ),
    ];

    #[test]
    fn every_pair_the_written_form_is_known_to_miss_is_still_missed() {
        // The register, executed. A pair belongs in it when, under **some**
        // home, every answer keys it as one file and the two written forms
        // differ anyway — which is exactly the account that gets a `Conflict`
        // no answer clears. Judged per home rather than over the union,
        // because a pair one home parts is still an unclearable block for an
        // account under the home that does not.
        //
        // The list is therefore a measurement at this head, not a claim carried
        // forward from an earlier one. A pair a repair to `written_form`
        // decides turns this red and must move into the fuzz's `segments` and
        // `openers` arrays, which is the one instruction this register gives.
        let by_home: Vec<(PathBuf, Vec<(String, ResolvedValues)>)> = homes()
            .into_iter()
            .map(|at| {
                let sets = answer_sets_at(&at);
                (at, sets)
            })
            .collect();
        let declarations = &by_home[0].1[0].1;

        let mut decided: Vec<String> = Vec::new();
        for (first, second, why) in UNDECIDED {
            if one_path_as_written(first, second, declarations) {
                decided.push(format!(
                    "{first:?} and {second:?} ({why}): now one path as written"
                ));
                continue;
            }
            let mut per_home = Vec::new();
            for (at, answers) in &by_home {
                match keying(first, second, answers) {
                    (true, None) => per_home.clear(),
                    (_, Some(apart)) => {
                        per_home.push(format!("{}: parted by {apart}", at.display()))
                    }
                    (false, None) => per_home.push(format!(
                        "{}: no answer keys it as a file at all",
                        at.display()
                    )),
                }
                if per_home.is_empty() {
                    break;
                }
            }
            if !per_home.is_empty() {
                decided.push(format!(
                    "{first:?} and {second:?} ({why}): undecided under no home — {}",
                    per_home.join("; ")
                ));
            }
        }
        assert!(
            decided.is_empty(),
            "{} registered pairs no longer describe a miss:\n{}",
            decided.len(),
            decided.join("\n")
        );
    }

    /// Rules for deciding a pair that were proposed and refuted, each with the
    /// two spellings, the answers to `p` and `r` that part them, and the rule
    /// the parting kills.
    ///
    /// Kept so that none is re-adopted, and kept executable so that a refutation
    /// cannot outlive the behaviour it rests on.
    const REFUTED: [(&str, &str, &str, &str, &str); 5] = [
        (
            "{{r}}{{p}}/..",
            "{{r}}/..",
            "~/a",
            "//srv/",
            "treat any glued placeholder tail like literal text",
        ),
        (
            "{{r}}x/conf",
            "{{r}}/conf",
            "",
            "/srv",
            "treat glue with no following `..` as one path",
        ),
        (
            "/opt/{{r}}./conf",
            "/opt/{{r}}/conf",
            "",
            "/srv",
            "treat a dot glued after a `path` value as one path",
        ),
        (
            "/a/b/{{r}}../..",
            "/a/b/{{r}}/..",
            "",
            "/",
            "treat a `..` glued after a `path` value as always undecided",
        ),
        (
            "/opt/{{r}}x/../conf",
            "/opt/{{r}}/../conf",
            "",
            "/",
            "the same, with one fixed segment above the value",
        ),
    ];

    /// The classifier's declarations, with `p` and `r` answered.
    fn answered(p: &str, r: &str) -> ResolvedValues {
        use crate::config::values::AssignedValue;

        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let assign = |name: &str, text: &str| ValueAssignment {
            name: name.into(),
            value: AssignedValue::String(text.into()),
            origin: Origin::unknown(Path::new("local.toml")),
        };
        ResolvedValues::resolve(
            classifier_kinds()
                .into_iter()
                .map(|(name, kind)| decl(name, kind))
                .collect(),
            &[assign("p", p), assign("r", r)],
            &home(),
        )
        .expect("the answers resolve")
    }

    #[test]
    fn every_rule_the_written_form_refused_is_still_refuted() {
        // A proposed rule is dead when one answer gives its two spellings
        // different keys, because a rule calling them one path would refuse a
        // whole load an account could have cleared. Executed rather than
        // recited, so a refutation is re-measured at the head it is published
        // against instead of being carried forward.
        for (first, second, p, r, rule) in REFUTED {
            let values = answered(p, r);
            assert!(
                !one_path_as_written(first, second, &values),
                "{rule}: {first:?} and {second:?} are called one path today"
            );
            assert_ne!(
                TargetKey::of(first, &values),
                TargetKey::of(second, &values),
                "{rule}: {first:?} and {second:?} with p={p:?} r={r:?}"
            );
        }
    }

    #[test]
    fn no_registered_pair_reaches_the_comparison_as_full_entries() {
        // The half of the reachability argument that generalises, executed over
        // **every** entry rather than one worked example. Written as a pair of
        // `[[target]]`s, each registered spelling is refused before `merge`
        // runs at all — by whichever rule catches it, which differs between
        // them: a spelling that opens with a placeholder, one that opens with a
        // `~` glued to one, one that reduces to a root, and two whose
        // normalised spellings coincide are four different refusals. The point
        // is not which one fires but that none of these pairs ever reaches the
        // comparison this way, so the register's consequence is a toggle's.
        const VALUES: &str = "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                              [[value]]\nname = \"f\"\nkind = \"bool\"\n\
                              [[value]]\nname = \"r\"\nkind = \"path\"\n";

        let mut loaded: Vec<String> = Vec::new();
        for (first, second, why) in UNDECIDED {
            let text = format!(
                "{VALUES}{}{}",
                target_toml(first, "ONE"),
                target_toml(second, "TWO")
            );
            if parse_str(&text, Path::new("bx.toml"), &home()).is_ok() {
                loaded.push(format!("{first:?} and {second:?} ({why})"));
            }
        }
        assert!(
            loaded.is_empty(),
            "{} registered pairs parse as full entries, so the register's \
             toggle-only reachability no longer holds for them:\n{}",
            loaded.len(),
            loaded.join("\n")
        );
    }

    #[test]
    fn an_opening_placeholder_an_answer_may_empty_is_parted_by_what_follows_it() {
        // `{{p}}` and `{{p}}/.` are one file, `/srv`, for `p = "/srv"`, but
        // `p = ""` makes the first nothing and the second `/`. Some answer parts
        // them, so meeting is the account's doing: a conflict, not a refusal.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n{}\
                     [[target]]\npath = \"{{{{p}}}}\"\nenabled = false\n\
                     [[target]]\npath = \"{{{{p}}}}/.\"\nenabled = true\n",
                    target_toml("/srv", "S")
                ),
            ),
            local("[values]\np = \"/srv\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "/srv");

        let decl = ValueDecl {
            name: "p".into(),
            description: None,
            kind: ValueKind::String,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let empty = ValueAssignment {
            name: "p".into(),
            value: crate::config::values::AssignedValue::String(String::new()),
            origin: Origin::unknown(Path::new("local.toml")),
        };
        let values = ResolvedValues::resolve(vec![decl], &[empty], &home()).unwrap();
        assert_ne!(
            TargetKey::of("{{p}}", &values),
            TargetKey::of("{{p}}/.", &values),
            "`p = \"\"` parts the pair"
        );
    }

    #[test]
    fn a_path_value_after_a_placeholder_is_not_rooted_at_home() {
        // Only a literal `~` before a `path` value roots a spelling at `~`.
        // `{{p}}{{r}}/s` and `~/{{r}}/s` are one file, `~/srv/s`, for `p = "~"`,
        // but `p = ""` makes the first `/srv/s`. Some answer parts them, so
        // meeting is the account's doing: a conflict, not a refusal.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"r\"\nkind = \"path\"\n{}\
                     [[target]]\npath = \"{{{{p}}}}{{{{r}}}}/s\"\nenabled = false\n\
                     [[target]]\npath = \"~/{{{{r}}}}/s\"\nenabled = true\n",
                    target_toml("~/srv/s", "S")
                ),
            ),
            local("[values]\np = \"~\"\nr = \"/srv\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "~/srv/s");
    }

    #[test]
    fn two_toggles_that_each_cancel_a_placeholder_meet_for_one_answer_only() {
        // `~/.config/{{p}}/../s` and `~/.config/{{q}}/../s` are `~/.config/s`
        // while `p` and `q` each hold one segment, and two files once either
        // holds a `/`. Meeting for these answers is the account's doing, so the
        // file is recorded as a conflict rather than failing the merge.
        let config = merge(&[
            global(
                "bx.toml",
                &format!(
                    "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                     [[value]]\nname = \"q\"\nkind = \"string\"\n{}\
                     [[target]]\npath = \"~/.config/{{{{p}}}}/../s\"\nenabled = false\n\
                     [[target]]\npath = \"~/.config/{{{{q}}}}/../s\"\nenabled = true\n",
                    target_toml("~/.config/s", "S")
                ),
            ),
            local("[values]\np = \"a\"\nq = \"b\"\n"),
        ])
        .unwrap_or_else(|e| panic!("an answer that names one file twice failed the merge: {e}"));
        assert_eq!(config.conflicts.len(), 1);
        assert_eq!(config.conflicts[0].file, "~/.config/s");
    }

    #[test]
    fn toggles_one_path_past_a_placeholder_are_the_layer_s_defect_whatever_climbs() {
        // `~/{{p}}/../../s` and `~/{{p}}/.././../s` differ only by a `.`, so
        // whatever `p` holds they name one file, or both climb out of the home
        // and name none. No answer can part them: it is the layer's defect, even
        // though a one-segment `p` makes neither a portable path. The second pair
        // spreads the climb over two placeholders.
        for (first, second) in [
            ("~/{{p}}/../../s", "~/{{p}}/.././../s"),
            ("~/{{p}}/{{q}}/../../../s", "~/{{p}}/{{q}}/../.././../s"),
        ] {
            let message = failure(&[
                global(
                    "bx.toml",
                    &format!(
                        "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                         [[value]]\nname = \"q\"\nkind = \"string\"\n{}\
                         [[target]]\npath = \"{first}\"\nenabled = false\n\
                         [[target]]\npath = \"{second}\"\nenabled = true\n",
                        target_toml("~/s", "S")
                    ),
                ),
                local("[values]\np = \"a/b\"\nq = \"c\"\n"),
            ]);
            assert!(
                message.contains(&format!("names the same file as `{first}`")),
                "{second}: {message}"
            );
            assert!(
                message.contains("in this same layer"),
                "{second}: {message}"
            );
        }
    }

    #[test]
    fn a_dotdot_past_the_root_is_the_layer_s_defect_whatever_is_answered() {
        // At `/` there is nothing above to climb to, so a `..` left with nothing
        // written before it to cancel is dropped. `/a/../../{{p}}` and
        // `/a/../../../{{p}}` both name `/{{p}}`, as `/../{{p}}` and
        // `/../../{{p}}` do, whatever `p` holds. A `path` value glued after the
        // climb starts its own segment and clamps the same way (`/..{{r}}`
        // against `/../../{{r}}`). No answer parts any pair, so each is the
        // layer's defect rather than a block an answer could clear.
        for (file, first, second) in [
            ("/s", "/a/../../{{p}}", "/a/../../../{{p}}"),
            ("/s", "/../{{p}}", "/../../{{p}}"),
            ("/srv", "/..{{r}}", "/../../{{r}}"),
        ] {
            let message = failure(&[
                global(
                    "bx.toml",
                    &format!(
                        "[[value]]\nname = \"p\"\nkind = \"string\"\n\
                         [[value]]\nname = \"r\"\nkind = \"path\"\n{}\
                         [[target]]\npath = \"{first}\"\nenabled = false\n\
                         [[target]]\npath = \"{second}\"\nenabled = true\n",
                        target_toml(file, "S")
                    ),
                ),
                local("[values]\np = \"s\"\nr = \"/srv\"\n"),
            ]);
            assert!(
                message.contains(&format!("names the same file as `{first}`")),
                "{second}: {message}"
            );
            assert!(
                message.contains("in this same layer"),
                "{second}: {message}"
            );
        }
    }

    #[test]
    fn a_literal_tilde_is_rooted_at_home_not_absolute() {
        // `written_form`'s `Root::Home` arm — the one that reads a first
        // segment of exactly `[Piece::Literal("~")]` — is what parts a pair
        // that climbs above the home and what keeps `~` from meeting `/`.
        // Cited by name rather than by line, which is the convention the rest
        // of this file follows and the only citation a refactor cannot rot.
        // At `/` nothing is above the root, so a bare `..` clamps away (see
        // `a_dotdot_past_the_root_is_the_layer_s_defect_whatever_is_answered`
        // above); under `~` the home's own parent is unknown, so it does not.
        //
        // The root is pinned directly, and not only through a pair's verdict:
        // a mutant that folds `~` into `Root::Opening` gives it the same first
        // segment and the same `followed` (a literal piece is never
        // `may_be_empty`) as any other pure-`~` spelling, so no pair of
        // spellings moves `one_path_as_written`'s verdict at all — the
        // fixed-seed property test above would not catch it either.
        let decl = ValueDecl {
            name: "p".into(),
            description: None,
            kind: ValueKind::String,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        let values = ResolvedValues::resolve(vec![decl], &[], &home()).unwrap();

        for spelling in ["~", "~/{{p}}", "~/../{{p}}"] {
            let form = written_form(spelling, &values).expect("well-formed");
            assert_eq!(form.root, Root::Home, "{spelling}: {form:?}");
        }

        // (a) A pair that climbs above `~` does not prove one path: the extra
        // `..` stays in the form instead of clamping the way it does at `/`,
        // so the pair is judged after substitution rather than refused as the
        // layer's defect.
        assert!(
            !one_path_as_written("~/../{{p}}", "~/../../{{p}}", &values),
            "a climb above the home is not proof of one path"
        );

        // (b) `~/{{p}}` and `/{{p}}` are not one path: `~` is not `/`.
        assert!(
            !one_path_as_written("~/{{p}}", "/{{p}}", &values),
            "`~` is not `/`"
        );

        // This test is the branch's only pin, and deliberately so: the two
        // `one_path_as_written` assertions above hold with the branch deleted.
        // A refactor that folds `Root::Home` away while keeping every verdict
        // fails exactly the `form.root` assertions, and must re-decide the
        // branch rather than delete the assertions.
    }

    /// Declarations of every kind the classifier reads, plus a name the set
    /// deliberately omits.
    fn classifier_values() -> ResolvedValues {
        let decl = |name: &str, kind: ValueKind| ValueDecl {
            name: name.into(),
            description: None,
            kind,
            required: false,
            is_root: false,
            default: None,
            enabled: true,
            origin: Origin::unknown(Path::new("bx.toml")),
        };
        ResolvedValues::resolve(
            classifier_kinds()
                .into_iter()
                .map(|(name, kind)| decl(name, kind))
                .collect(),
            &[],
            &home(),
        )
        .expect("the declarations resolve")
    }

    /// Every kind a value may be declared with, under the name the classifier
    /// tests declare it as.
    ///
    /// One list, so a kind cannot be declared for these fixtures without
    /// `every_kind_but_a_string_fills_an_opening_segment` deciding it, and that
    /// test's match is exhaustive, so a new [`ValueKind`] does not compile
    /// until someone has.
    fn classifier_kinds() -> [(&'static str, ValueKind); 6] {
        [
            ("p", ValueKind::String),
            ("f", ValueKind::Bool),
            ("r", ValueKind::Path),
            ("e", ValueKind::Email),
            ("k", ValueKind::SshKey),
            ("g", ValueKind::AgeRecipient),
        ]
    }

    #[test]
    fn every_kind_but_a_string_fills_an_opening_segment() {
        // `may_be_empty` is the one place `written_form` reads a kind, and it
        // names `String` alone. Every other kind therefore makes a separator
        // after an opening placeholder change no file, which is what
        // `followed = false` records. Asserted over the kinds themselves rather
        // than over the four a spelling happened to use, because the
        // discrimination is on the kind axis.
        let values = classifier_values();

        for (name, kind) in classifier_kinds() {
            let spelling = format!("{{{{{name}}}}}/a");
            let opening = |followed| Root::Opening {
                first: vec![Piece::Name(name)],
                followed,
            };
            let root = form_of(&spelling, &values).root;
            match kind {
                // A `path` answer is absolute, so it roots the spelling instead
                // of opening a segment and `may_be_empty` never reaches it.
                ValueKind::Path => assert_eq!(root, Root::Absolute, "{spelling}"),
                ValueKind::String => assert_eq!(root, opening(true), "{spelling}"),
                ValueKind::Bool
                | ValueKind::Email
                | ValueKind::SshKey
                | ValueKind::AgeRecipient => assert_eq!(root, opening(false), "{spelling}"),
            }
        }
    }

    /// `written_form`, for a spelling the caller knows is well-formed.
    fn form_of<'a>(spelling: &'a str, values: &ResolvedValues) -> WrittenForm<'a> {
        written_form(spelling, values).expect("well-formed")
    }

    #[test]
    fn written_form_classifies_each_root() {
        // The four roots, read off directly rather than through a pair's
        // verdict, so a change to the classification is a change to this test.
        let values = classifier_values();

        assert_eq!(
            form_of("/a/b", &values).root,
            Root::Absolute,
            "a written `/`"
        );
        assert_eq!(
            form_of("{{r}}/b", &values).root,
            Root::Absolute,
            "a `path` answer is absolute, so it roots the spelling at `/`"
        );
        assert_eq!(form_of("~/a", &values).root, Root::Home);
        assert_eq!(
            form_of("{{p}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("p")],
                followed: true,
            },
            "a `string` may be emptied, so what follows the opening segment parts it"
        );
        assert_eq!(
            form_of("{{e}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("e")],
                followed: false,
            },
            "an `email` answer is never empty, so a separator after it changes no file"
        );
        assert_eq!(
            form_of("{{p}}", &values).root,
            Root::Opening {
                first: vec![Piece::Name("p")],
                followed: false,
            },
            "nothing follows it"
        );
    }

    #[test]
    fn written_form_classifies_each_segment() {
        // `Fixed` is what a `..` cancels and `Opaque` is what it does not, so
        // the split between them is the whole of the reduction's strength.
        let values = classifier_values();

        assert_eq!(
            form_of("/a/x{{f}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Fixed(vec![Piece::Literal("x"), Piece::Name("f")]),
            ],
            "a `bool` answer is never empty, never a dot and never holds a `/`"
        );
        assert_eq!(
            form_of("/a/{{p}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Opaque(vec![Piece::Name("p")]),
            ],
            "a `string` answer may be anything, so nothing cancels it"
        );
        assert_eq!(
            form_of("/a/./b/..", &values).segments,
            [Segment::Fixed(vec![Piece::Literal("a")])],
            "a `.` folds and a `..` cancels the `Fixed` before it"
        );
        assert_eq!(
            form_of("/{{p}}/..", &values).segments,
            [Segment::Opaque(vec![Piece::Name("p")]), Segment::Up],
            "nothing cancels an `Opaque`"
        );
        assert_eq!(
            form_of("/..", &values).segments,
            [],
            "at `/` there is nothing above to climb to"
        );
        assert_eq!(
            form_of("~/..", &values).segments,
            [Segment::Up],
            "under `~` the climb out of the home is no answer's doing"
        );
    }

    #[test]
    fn written_form_takes_a_name_no_layer_declares_as_the_widest_kind() {
        // Defensive: a spelling keyed as a file substituted, so every name in
        // one is declared. Exercised directly so the fallback is constrained
        // rather than merely commented — `cargo mutants` generates no mutant
        // for either closure.
        let values = classifier_values();

        // Not a `path`, so it does not start its own segment or root at `/`.
        assert_eq!(
            form_of("/a/x{{nowhere}}", &values).segments,
            [
                Segment::Fixed(vec![Piece::Literal("a")]),
                Segment::Opaque(vec![Piece::Literal("x"), Piece::Name("nowhere")]),
            ],
            "the widest kind: not a `bool`, so the segment is opaque"
        );
        // Widest means it may be empty, so what follows an opening one parts it.
        assert_eq!(
            form_of("{{nowhere}}/a", &values).root,
            Root::Opening {
                first: vec![Piece::Name("nowhere")],
                followed: true,
            }
        );
    }

    #[test]
    fn written_form_refuses_a_spelling_that_is_not_a_template() {
        // Defensive in the same way: substitution scans the same text, so a
        // spelling keyed as a file is well-formed. `None` rather than a panic,
        // and `one_path_as_written` then answers `false` rather than claiming
        // a proof it does not have.
        let values = classifier_values();

        assert!(written_form("~/{{unclosed", &values).is_none());
        assert!(!one_path_as_written(
            "~/{{unclosed",
            "~/{{unclosed",
            &values
        ));
    }

    #[test]
    fn written_form_of_an_empty_spelling_is_an_empty_opening_segment() {
        // The `unwrap_or_default` on the first segment is unreachable — the
        // scan loop always pushes a final segment — and an empty spelling is
        // the closest a caller gets to it. `Portable::parse_in("")` refuses it,
        // so it is never keyed as a file and never reaches `clash`.
        let values = classifier_values();
        let form = written_form("", &values).expect("an empty template is well-formed");

        assert_eq!(
            form.root,
            Root::Opening {
                first: Vec::new(),
                followed: false,
            }
        );
        assert!(form.segments.is_empty());
    }
}
