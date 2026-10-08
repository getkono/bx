//! A managed region: the delimited span bx owns inside a file the user writes.
//!
//! ```text
//! # >>> bx >>>
//! …bx's lines…
//! # <<< bx <<<
//! ```
//!
//! The delimiters are whole lines, spelled with the target's comment
//! character, and a file holds at most one region. Everything outside it is the
//! user's and is carried through byte for byte: [`splice`] replaces the region
//! in place, or appends one to a file that has none, and never touches another
//! byte. A file whose delimiters cannot be read as one region is damaged, and
//! is left for the user rather than guessed at.
//!
//! This is only the grammar. What bx may do to a region — whose bytes they
//! are, and when a rewrite would undo the user's edit — is the plan's to
//! decide, against the ledger.

/// The line a region opens with.
fn begin(comment: char) -> String {
    format!("{comment} >>> bx >>>")
}

/// The line a region closes with.
fn end(comment: char) -> String {
    format!("{comment} <<< bx <<<")
}

/// The region holding `body`, delimiters included.
///
/// `body` gains a final newline when it lacks one, so the closing delimiter is
/// always a line of its own.
#[must_use]
pub(super) fn block(comment: char, body: &[u8]) -> Vec<u8> {
    let mut out = begin(comment).into_bytes();
    out.push(b'\n');
    out.extend_from_slice(body);
    if !body.is_empty() && !body.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(end(comment).as_bytes());
    out.push(b'\n');
    out
}

/// Where the region is in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Found {
    /// The file holds no delimiter.
    Absent,
    /// Exactly one region, spanning these bytes: its opening delimiter's first
    /// byte to just past its closing delimiter's line end.
    At(std::ops::Range<usize>),
    /// Delimiters that do not make exactly one region, and why.
    Damaged(&'static str),
}

/// Find the region in `file`.
#[must_use]
pub(super) fn find(file: &[u8], comment: char) -> Found {
    let (begin, end) = (begin(comment), end(comment));
    let mut opens = Vec::new();
    let mut closes = Vec::new();
    let mut at = 0;
    for line in file.split_inclusive(|byte| *byte == b'\n') {
        let text = line.strip_suffix(b"\n").unwrap_or(line);
        if text == begin.as_bytes() {
            opens.push(at);
        } else if text == end.as_bytes() {
            closes.push(at + line.len());
        }
        at += line.len();
    }
    match (opens.as_slice(), closes.as_slice()) {
        ([], []) => Found::Absent,
        ([open], [close]) if open < close => Found::At(*open..*close),
        ([_], [_]) => Found::Damaged("its closing delimiter comes before its opening one"),
        ([], _) => Found::Damaged("it has a closing delimiter and no opening one"),
        (_, []) => Found::Damaged("it has an opening delimiter and no closing one"),
        _ => Found::Damaged("it has more than one opening or closing delimiter"),
    }
}

/// `file` with its region holding `body`: replaced in place when it has one,
/// appended when it has none, and the whole file when there is no file.
///
/// # Errors
///
/// The [`Found::Damaged`] reason when `file`'s delimiters do not make one
/// region.
pub(super) fn splice(
    file: Option<&[u8]>,
    comment: char,
    body: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let region = block(comment, body);
    let Some(file) = file else {
        return Ok(region);
    };
    match find(file, comment) {
        Found::Absent => {
            let mut out = file.to_vec();
            if !out.is_empty() && !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            out.extend_from_slice(&region);
            Ok(out)
        }
        Found::At(span) => {
            let mut out = file[..span.start].to_vec();
            out.extend_from_slice(&region);
            out.extend_from_slice(&file[span.end..]);
            Ok(out)
        }
        Found::Damaged(why) => Err(why),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const BODY: &[u8] = b"[[ -r ~/.f ]] && source ~/.f\n";

    #[test]
    fn a_region_is_three_lines_for_a_one_line_body() {
        assert_eq!(
            block('#', BODY),
            b"# >>> bx >>>\n[[ -r ~/.f ]] && source ~/.f\n# <<< bx <<<\n".to_vec()
        );
        // A body with no final newline still leaves the delimiter its own line.
        assert_eq!(
            block(';', b"x"),
            b"; >>> bx >>>\nx\n; <<< bx <<<\n".to_vec()
        );
        assert_eq!(block('#', b""), b"# >>> bx >>>\n# <<< bx <<<\n".to_vec());
    }

    #[test]
    fn no_file_becomes_the_region_alone() {
        assert_eq!(splice(None, '#', BODY), Ok(block('#', BODY)));
    }

    #[test]
    fn a_file_without_a_region_gains_one_after_every_byte_the_user_wrote() {
        let user = b"alias ll='ls -l'\nexport X=1";
        let spliced = splice(Some(user), '#', BODY).expect("splices");
        assert!(spliced.starts_with(b"alias ll='ls -l'\nexport X=1\n# >>> bx >>>\n"));
        assert!(spliced.ends_with(&block('#', BODY)));
        // An empty file is just the region.
        assert_eq!(splice(Some(b""), '#', BODY), Ok(block('#', BODY)));
    }

    #[test]
    fn a_region_is_replaced_in_place_and_nothing_around_it_moves() {
        let before = b"top\n# >>> bx >>>\nold\nlines\n# <<< bx <<<\nbottom\n";
        let spliced = splice(Some(before), '#', BODY).expect("splices");
        let mut expected = b"top\n".to_vec();
        expected.extend(block('#', BODY));
        expected.extend(b"bottom\n");
        assert_eq!(spliced, expected);
        // Splicing what is already there changes nothing: idempotent.
        assert_eq!(splice(Some(&expected), '#', BODY), Ok(expected.clone()));
        // A closing delimiter with no final newline is still found.
        let unterminated = b"# >>> bx >>>\nold\n# <<< bx <<<";
        assert_eq!(splice(Some(unterminated), '#', BODY), Ok(block('#', BODY)));
    }

    #[test]
    fn delimiters_are_whole_lines_in_the_targets_comment_character() {
        // Indented, trailing text, or another comment character is not a
        // delimiter, so each of these files has no region and gains one.
        for text in [
            &b"  # >>> bx >>>\n# <<< bx <<< \n"[..],
            b"; >>> bx >>>\n; <<< bx <<<\n",
            b"echo '# >>> bx >>>'\n",
        ] {
            assert_eq!(find(text, '#'), Found::Absent, "{text:?}");
        }
        assert_eq!(find(b"; >>> bx >>>\n; <<< bx <<<\n", ';'), Found::At(0..26));
    }

    #[test]
    fn delimiters_that_do_not_make_one_region_are_damaged_and_never_spliced() {
        for (text, why) in [
            (&b"# <<< bx <<<\n"[..], "no opening one"),
            (b"# >>> bx >>>\n", "no closing one"),
            (b"# <<< bx <<<\n# >>> bx >>>\n", "comes before"),
            (
                b"# >>> bx >>>\n# <<< bx <<<\n# >>> bx >>>\n# <<< bx <<<\n",
                "more than one",
            ),
            (
                b"# >>> bx >>>\n# >>> bx >>>\n# <<< bx <<<\n",
                "more than one",
            ),
        ] {
            match find(text, '#') {
                Found::Damaged(reason) => assert!(reason.contains(why), "{reason}"),
                other => panic!("{text:?}: {other:?}"),
            }
            assert!(splice(Some(text), '#', BODY).is_err());
        }
    }

    /// The comment characters the properties draw from.
    const COMMENTS: [char; 3] = ['#', ';', '"'];

    /// One line of a generated file, without its newline: ordinary text, a
    /// line that resembles a delimiter and is not one, or an exact delimiter in
    /// some comment character.
    fn line() -> impl Strategy<Value = String> {
        let comment = proptest::sample::select(COMMENTS.to_vec());
        prop_oneof![
            6 => "[ -~]{0,12}",
            2 => (comment.clone(), "[ \t]{1,2}", any::<bool>()).prop_map(|(c, pad, open)| {
                let marker = if open { begin(c) } else { end(c) };
                // Indented, or trailing text: never a delimiter.
                if pad.len() == 1 { format!("{pad}{marker}") } else { format!("{marker}{pad}") }
            }),
            1 => (comment, any::<bool>())
                .prop_map(|(c, open)| if open { begin(c) } else { end(c) }),
        ]
    }

    /// A file of generated lines, with or without a final newline.
    fn text() -> impl Strategy<Value = Vec<u8>> {
        (proptest::collection::vec(line(), 0..8), any::<bool>()).prop_map(|(lines, newline)| {
            let mut text = lines.join("\n");
            if newline && !text.is_empty() {
                text.push('\n');
            }
            text.into_bytes()
        })
    }

    /// Text with no delimiter in `comment`.
    fn plain(comment: char) -> impl Strategy<Value = Vec<u8>> {
        text().prop_filter("holds a delimiter", move |text| {
            find(text, comment) == Found::Absent
        })
    }

    /// A comment character and a region body that is not itself a region.
    fn comment_and_body() -> impl Strategy<Value = (char, Vec<u8>)> {
        proptest::sample::select(COMMENTS.to_vec())
            .prop_flat_map(|comment| (Just(comment), plain(comment)))
    }

    proptest! {
        #[test]
        fn splicing_keeps_every_user_byte_and_finds_its_region_again(
            (comment, body) in comment_and_body(),
            file in text(),
        ) {
            let spliced = splice(Some(&file), comment, &body);
            let (kept_before, kept_after) = match find(&file, comment) {
                Found::Damaged(why) => {
                    prop_assert_eq!(spliced, Err(why));
                    return Ok(());
                }
                // Appended after every byte, with a newline added only when
                // the file's last line lacked one.
                Found::Absent => (file.clone(), Vec::new()),
                Found::At(span) => (file[..span.start].to_vec(), file[span.end..].to_vec()),
            };
            let spliced = spliced.expect("one region or none splices");
            let region = block(comment, &body);
            let start = spliced.len() - kept_after.len() - region.len();
            prop_assert!(spliced.starts_with(&kept_before));
            prop_assert!(spliced.ends_with(&kept_after));
            prop_assert_eq!(&spliced[start..spliced.len() - kept_after.len()], &region[..]);
            let gap = &spliced[kept_before.len()..start];
            prop_assert!(gap.is_empty() || (gap == b"\n" && !kept_before.ends_with(b"\n")));
            prop_assert_eq!(find(&spliced, comment), Found::At(start..start + region.len()));
            // Splicing again is a no-op: idempotent.
            prop_assert_eq!(splice(Some(&spliced), comment, &body), Ok(spliced.clone()));
        }

        #[test]
        fn a_region_rewritten_and_rewritten_back_restores_the_file(
            (comment, body, other, before, after) in comment_and_body().prop_flat_map(
                |(comment, body)| (Just(comment), Just(body), plain(comment), plain(comment), plain(comment))
            ),
        ) {
            let mut file = before;
            if !file.is_empty() && !file.ends_with(b"\n") {
                file.push(b'\n');
            }
            let at = file.len();
            file.extend(block(comment, &body));
            file.extend(&after);
            prop_assert_eq!(find(&file, comment), Found::At(at..at + block(comment, &body).len()));

            let rewritten = splice(Some(&file), comment, &other).expect("splices");
            prop_assert_eq!(&rewritten[..at], &file[..at]);
            prop_assert!(rewritten.ends_with(&after));
            prop_assert_eq!(splice(Some(&rewritten), comment, &body), Ok(file));
        }
    }

    #[test]
    fn the_mechanism_attaches_to_a_bashrc_as_it_does_to_a_zshrc() {
        // The same grammar serves every shell's rc file: nothing in it is zsh's.
        let bashrc = b"# ~/.bashrc\n[ -z \"$PS1\" ] && return\nHISTSIZE=1000\n";
        let spliced = splice(Some(bashrc), '#', BODY).expect("splices");
        assert!(spliced.starts_with(bashrc));
        assert_eq!(find(&spliced, '#'), Found::At(bashrc.len()..spliced.len()));
        assert_eq!(splice(Some(&spliced), '#', BODY), Ok(spliced.clone()));
    }
}
