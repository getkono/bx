//! Declared shell history: one `[history]` table, rendered for zsh and for
//! bash in each shell's own names.
//!
//! # The `[history]` schema
//!
//! ```toml
//! [history]
//! size         = 10000            # the in-memory list and the file, both
//! duplicates   = "all"            # keep | adjacent | all
//! ignore_space = true             # a line typed with a leading space is not kept
//! share        = true             # zsh only: every session reads every other's lines
//!
//! [history.file]                  # each shell's file, only for the shell it names
//! zsh  = "~/.zsh_history"
//! bash = "~/.bash_history"
//! ```
//!
//! Every key is optional, and a key left out is left to the shell: bx writes
//! nothing for it. An empty `[history]`, or none, renders nothing in either
//! shell.
//!
//! # One declaration, each shell's names
//!
//! | key            | zsh                                      | bash                            |
//! |----------------|------------------------------------------|---------------------------------|
//! | `size`         | `HISTSIZE` and `SAVEHIST`                | `HISTSIZE` and `HISTFILESIZE`   |
//! | `file.zsh`     | `HISTFILE`                               | —                               |
//! | `file.bash`    | —                                        | `HISTFILE`                      |
//! | `duplicates`   | `HIST_IGNORE_DUPS`, `HIST_IGNORE_ALL_DUPS` | `ignoredups` / `erasedups` in `HISTCONTROL` |
//! | `ignore_space` | `HIST_IGNORE_SPACE`                      | `ignorespace` in `HISTCONTROL`  |
//! | `share`        | `SHARE_HISTORY`                          | — (bash has no equivalent)      |
//!
//! `size` is one number because the list a shell keeps in memory and the file
//! it saves are, for every configuration this models, meant to be the same
//! length; each shell spells the two differently, and the renderer writes both.
//! A file path is per shell because the two shells' files are not
//! interchangeable, and declaring one never writes the other: leaving
//! `file.bash` out leaves bash on its own default, `~/.bash_history`, whatever
//! `file.zsh` says.
//!
//! # Layers
//!
//! `[history]` is one table, not a keyed list, so it merges key by key, the
//! last layer that sets a key winning, as `[secrets]` does. `file.zsh` and
//! `file.bash` are separate keys.
//!
//! # Where it lands
//!
//! zsh reads it from the generated interactive file's `options` phase, which
//! every interactive zsh sources through `~/.zshrc`, login or not.
//! [`History::render_bash`] is the same declaration in bash's names, and lands
//! in the `options` phase of bash's generated interactive file, which
//! `~/.bashrc` sources ([`crate::shell::bash`]).
//!
//! # Invariant 2
//!
//! The history settings are shell parameters the shell reads for itself, never
//! exported — the rendered text unexports each one it assigns, because a shell
//! keeps the export flag on a parameter it inherited from its environment —
//! and none moves another tool's file. A history file is a file the
//! shell itself keeps, and zsh has no default one at all, so declaring it
//! relocates nothing; it is still refused inside a directory bx owns or bx's
//! config repo, which the plan judges with
//! [`crate::env_guard::refuses_bx_location`]. The tests run the rendered bytes
//! in zsh and bash and hold them to changing only the parameters named above
//! and exporting nothing, including when a parent exported them first.

use std::path::Path;

use toml_edit::{Item, Table, TableLike};

use super::{Ctx, Error, Origin};
use crate::paths::Portable;

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[history]";

/// The file table's header, as messages spell it.
const FILE_SECTION: &str = "[history.file]";

/// Every key a `[history]` table may carry.
const KEYS: [&str; 5] = ["size", "file", "duplicates", "ignore_space", "share"];

/// Every key `[history.file]` may carry: one per shell.
const FILE_KEYS: [&str; 2] = ["zsh", "bash"];

/// The largest `size`: the largest count both shells read back exactly.
const MAX_SIZE: i64 = 2_147_483_647;

/// What one layer's `[history]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct History {
    /// How many lines are kept, in memory and in the file.
    pub size: Option<u32>,
    /// zsh's history file.
    pub zsh_file: Option<Portable>,
    /// bash's history file.
    pub bash_file: Option<Portable>,
    /// Which repeated lines are dropped.
    pub duplicates: Option<Duplicates>,
    /// Whether a line typed with a leading space is dropped.
    pub ignore_space: Option<bool>,
    /// Whether every zsh session reads the lines every other one writes.
    pub share: Option<bool>,
    /// Where the table that last set a key was written.
    pub origin: Option<Origin>,
}

/// Which repeated history lines a shell drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicates {
    /// Every line is kept.
    Keep,
    /// A line identical to the one before it is dropped.
    Adjacent,
    /// An earlier copy of a line is dropped when it is entered again.
    All,
}

impl Duplicates {
    /// Every spelling, with what it means.
    const SPELLINGS: [(&'static str, Self); 3] = [
        ("keep", Self::Keep),
        ("adjacent", Self::Adjacent),
        ("all", Self::All),
    ];
}

/// One zsh option, set or unset.
type ZshOption = (&'static str, bool);

impl History {
    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        fn take<T: Clone>(mine: &mut Option<T>, theirs: Option<&T>) {
            if let Some(value) = theirs {
                *mine = Some(value.clone());
            }
        }
        take(&mut self.size, later.size.as_ref());
        take(&mut self.zsh_file, later.zsh_file.as_ref());
        take(&mut self.bash_file, later.bash_file.as_ref());
        take(&mut self.duplicates, later.duplicates.as_ref());
        take(&mut self.ignore_space, later.ignore_space.as_ref());
        take(&mut self.share, later.share.as_ref());
        take(&mut self.origin, later.origin.as_ref());
    }

    /// The declaration in zsh's names, or nothing when it says nothing zsh
    /// reads.
    ///
    /// `HISTFILE` first, then the sizes, then one `typeset -g +x` line naming
    /// every parameter assigned, then one `setopt` line and one `unsetopt`
    /// line, each option in a fixed order.
    ///
    /// The `typeset` line is what keeps the parameters unexported: zsh
    /// exports a parameter it inherited from its environment, and assigning
    /// one keeps that flag, so without it a `HISTFILE` an exported parent set
    /// would carry the declared value to every child. `-g` keeps it from
    /// declaring a local when the file is sourced inside a function.
    #[must_use]
    pub fn render_zsh(&self) -> String {
        let mut out = String::new();
        let mut assigned: Vec<&str> = Vec::new();
        if let Some(file) = &self.zsh_file {
            out.push_str(&format!("HISTFILE={}\n", spell(file)));
            assigned.push("HISTFILE");
        }
        if let Some(size) = self.size {
            out.push_str(&format!("HISTSIZE={size}\nSAVEHIST={size}\n"));
            assigned.extend(["HISTSIZE", "SAVEHIST"]);
        }
        if !assigned.is_empty() {
            out.push_str(&format!("typeset -g +x {}\n", assigned.join(" ")));
        }
        let mut options: Vec<ZshOption> = Vec::new();
        match self.duplicates {
            None => {}
            Some(Duplicates::Keep) => {
                options.extend([("HIST_IGNORE_DUPS", false), ("HIST_IGNORE_ALL_DUPS", false)]);
            }
            Some(Duplicates::Adjacent) => {
                options.extend([("HIST_IGNORE_DUPS", true), ("HIST_IGNORE_ALL_DUPS", false)]);
            }
            Some(Duplicates::All) => options.push(("HIST_IGNORE_ALL_DUPS", true)),
        }
        if let Some(on) = self.ignore_space {
            options.push(("HIST_IGNORE_SPACE", on));
        }
        if let Some(on) = self.share {
            options.push(("SHARE_HISTORY", on));
        }
        for (builtin, wanted) in [("setopt", true), ("unsetopt", false)] {
            let names: Vec<&str> = options
                .iter()
                .filter(|(_, on)| *on == wanted)
                .map(|(name, _)| *name)
                .collect();
            if !names.is_empty() {
                out.push_str(&format!("{builtin} {}\n", names.join(" ")));
            }
        }
        out
    }

    /// The declaration in bash's names, or nothing when it says nothing bash
    /// reads.
    ///
    /// `HISTFILE` comes before `HISTFILESIZE`, because bash truncates the file
    /// `HISTFILE` names at the moment `HISTFILESIZE` is assigned: the other
    /// order would truncate bash's default file rather than the declared one.
    /// `HISTCONTROL` is written whole whenever `duplicates` or `ignore_space`
    /// is declared, from exactly what is declared. `share` has no bash
    /// equivalent and writes nothing. A last `export -n` line names every
    /// variable assigned, for the reason [`History::render_zsh`] gives: an
    /// assignment keeps the export flag a variable inherited from the
    /// environment carries.
    #[must_use]
    pub fn render_bash(&self) -> String {
        let mut out = String::new();
        let mut assigned: Vec<&str> = Vec::new();
        if let Some(file) = &self.bash_file {
            out.push_str(&format!("HISTFILE={}\n", spell(file)));
            assigned.push("HISTFILE");
        }
        if let Some(size) = self.size {
            out.push_str(&format!("HISTSIZE={size}\nHISTFILESIZE={size}\n"));
            assigned.extend(["HISTSIZE", "HISTFILESIZE"]);
        }
        if self.duplicates.is_some() || self.ignore_space.is_some() {
            let mut control = Vec::new();
            if self.ignore_space == Some(true) {
                control.push("ignorespace");
            }
            match self.duplicates {
                Some(Duplicates::Adjacent) => control.push("ignoredups"),
                Some(Duplicates::All) => control.push("erasedups"),
                Some(Duplicates::Keep) | None => {}
            }
            out.push_str(&format!("HISTCONTROL={}\n", control.join(":")));
            assigned.push("HISTCONTROL");
        }
        if !assigned.is_empty() {
            out.push_str(&format!("export -n {}\n", assigned.join(" ")));
        }
        out
    }
}

/// A history file as a shell is given it: double-quoted, `~` spelled
/// `${HOME}`. The allowlist [`unwritable`] enforces is what makes the quotes
/// sufficient.
fn spell(file: &Portable) -> String {
    let raw = file.as_str();
    raw.strip_prefix('~').map_or_else(
        || format!("\"{raw}\""),
        |rest| format!("\"${{HOME}}{rest}\""),
    )
}

/// Parse a `[history]` table.
///
/// `text` is the whole layer file, because spans index into it; `home` is
/// what a history file is parsed against, so it has one spelling.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key this version does not know, here or in
/// `[history.file]`, [`Error::WrongType`] for a value of the wrong type, and
/// [`Error::BadValue`] for a size out of range, an unknown `duplicates`
/// spelling, or a file that is not a usable path.
pub fn parse_history(
    table: &Table,
    file: &Path,
    text: &str,
    home: &Path,
) -> Result<History, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    ctx.reject_unknown_keys(table, &KEYS)?;

    let size = match table.get("size") {
        None => None,
        Some(item) => {
            let raw = item
                .as_integer()
                .ok_or_else(|| ctx.wrong_type(table, "size", "an integer", item))?;
            if !(1..=MAX_SIZE).contains(&raw) {
                return Err(ctx.bad(
                    table,
                    "size",
                    format!(
                        "`size` is how many history lines are kept, from 1 to {MAX_SIZE}; \
                         {raw} is not, and 0 would keep none and empty the history file — \
                         remove the key to keep each shell's default"
                    ),
                ));
            }
            Some(u32::try_from(raw).expect("checked against the range above"))
        }
    };

    let duplicates = match ctx.str_at(table, "duplicates")? {
        None => None,
        Some(raw) => Some(
            Duplicates::SPELLINGS
                .iter()
                .find(|(spelling, _)| *spelling == raw)
                .map(|(_, duplicates)| *duplicates)
                .ok_or_else(|| {
                    ctx.bad(
                        table,
                        "duplicates",
                        format!(
                            "`duplicates` must be one of \"keep\", \"adjacent\", \"all\"; \
                             found {raw:?}"
                        ),
                    )
                })?,
        ),
    };

    let (zsh_file, bash_file) = match table.get("file") {
        None => (None, None),
        Some(item) => {
            let files = item
                .as_table_like()
                .ok_or_else(|| ctx.wrong_type(table, "file", "a table `[history.file]`", item))?;
            parse_files(files, &ctx, table, home)?
        }
    };

    let history = History {
        size,
        zsh_file,
        bash_file,
        duplicates,
        ignore_space: ctx.bool_at(table, "ignore_space")?,
        share: ctx.bool_at(table, "share")?,
        origin: None,
    };
    Ok(History {
        origin: (history != History::default()).then(|| ctx.origin().clone()),
        ..history
    })
}

/// Parse `[history.file]`: one optional path per shell.
fn parse_files(
    files: &dyn TableLike,
    ctx: &Ctx<'_>,
    table: &Table,
    home: &Path,
) -> Result<(Option<Portable>, Option<Portable>), Error> {
    // A key's own span, when the file table has one; the `file` key's
    // otherwise.
    let origin = |key: &str| {
        files.key(key).and_then(toml_edit::Key::span).map_or_else(
            || ctx.key_origin(table, "file"),
            |s| Origin::at(ctx.file, ctx.text, &s),
        )
    };
    for (key, _) in files.iter() {
        if !FILE_KEYS.contains(&key) {
            return Err(Error::UnknownKey {
                origin: origin(key),
                section: FILE_SECTION,
                key: key.to_string(),
            });
        }
    }
    let path = |shell: &str| -> Result<Option<Portable>, Error> {
        let Some(item) = files.get(shell) else {
            return Ok(None);
        };
        let raw = match item {
            Item::Value(value) => value.as_str(),
            _ => None,
        }
        .ok_or_else(|| Error::WrongType {
            origin: origin(shell),
            key: shell.to_string(),
            expected: "a string",
            found: item.type_name(),
        })?;
        let bad = |message: String| Error::BadValue {
            origin: origin(shell),
            message: format!("{FILE_SECTION} `{shell}`: {message}"),
        };
        let portable = Portable::parse_in(raw, home).map_err(|error| bad(error.to_string()))?;
        if let Some(problem) = unwritable(&portable) {
            return Err(bad(problem));
        }
        Ok(Some(portable))
    };
    Ok((path("zsh")?, path("bash")?))
}

/// Why `file` cannot be a history file bx writes, or `None` when it can.
///
/// It names a file, not the home or the root, and holds only the characters
/// a path `[path]` admits — so one double-quoted word means it exactly.
fn unwritable(file: &Portable) -> Option<String> {
    let raw = file.as_str();
    if raw == "~" || raw == "/" {
        return Some(format!(
            "{raw:?} is a directory; name the history file itself"
        ));
    }
    let rest = raw.strip_prefix('~').unwrap_or(raw);
    rest.chars()
        .find(|&c| !(c.is_ascii_alphanumeric() || "._-+/".contains(c)))
        .map(|c| {
            format!(
                "{raw:?} holds {c:?}; a history file holds only ASCII letters, digits and \
                 `._-+/`"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};

    const HOME: &str = "/var/home/example";

    fn parse(text: &str) -> Result<History, Error> {
        parse_str(text, Path::new("/repo/bx.toml"), Path::new(HOME)).map(|config| config.history)
    }

    fn message(text: &str) -> String {
        parse(text).expect_err(text).to_string()
    }

    fn portable(raw: &str) -> Portable {
        Portable::parse_in(raw, Path::new(HOME)).expect("portable")
    }

    /// The source configuration's history, as one declaration.
    fn declared() -> History {
        History {
            size: Some(10000),
            zsh_file: Some(portable("~/.zsh_history")),
            bash_file: None,
            duplicates: Some(Duplicates::All),
            ignore_space: None,
            share: Some(true),
            origin: None,
        }
    }

    #[test]
    fn every_key_parses_with_the_header_as_its_origin() {
        let history = parse(
            "[history]\nsize = 10000\nduplicates = \"adjacent\"\nignore_space = true\n\
             share = false\n[history.file]\nzsh = \"~/./.zsh_history\"\nbash = \"/srv/h\"\n",
        )
        .expect("parses");
        assert_eq!(
            history,
            History {
                size: Some(10000),
                zsh_file: Some(portable("~/.zsh_history")),
                bash_file: Some(portable("/srv/h")),
                duplicates: Some(Duplicates::Adjacent),
                ignore_space: Some(true),
                share: Some(false),
                origin: Some(Origin {
                    file: "/repo/bx.toml".into(),
                    line: 1,
                }),
            }
        );
        // The inline spelling of the file table is the same declaration.
        let inline = parse("[history]\nfile = { zsh = \"~/.zsh_history\" }\n").expect("parses");
        assert_eq!(inline.zsh_file, Some(portable("~/.zsh_history")));
        assert_eq!(inline.bash_file, None);
    }

    #[test]
    fn declaring_nothing_renders_nothing_in_either_shell() {
        for text in ["", "[history]\n", "[history]\n[history.file]\n"] {
            let history = parse(text).expect(text);
            assert_eq!(history, History::default(), "{text}");
            assert_eq!(history.render_zsh(), "", "{text}");
            assert_eq!(history.render_bash(), "", "{text}");
        }
    }

    #[test]
    fn a_malformed_history_is_refused_naming_why_and_where() {
        for (text, needle) in [
            ("history = 1\n", "a table `[history]`"),
            ("[history]\nsize = \"10\"\n", "`size` must be an integer"),
            ("[history]\nsize = 0\n", "from 1 to 2147483647"),
            ("[history]\nsize = -1\n", "from 1 to 2147483647"),
            ("[history]\nsize = 2147483648\n", "from 1 to 2147483647"),
            (
                "[history]\nduplicates = \"some\"\n",
                "\"keep\", \"adjacent\", \"all\"",
            ),
            (
                "[history]\nduplicates = true\n",
                "`duplicates` must be a string",
            ),
            ("[history]\nshare = \"yes\"\n", "a boolean"),
            ("[history]\nignore_space = 1\n", "a boolean"),
            (
                "[history]\nlength = 1\n",
                "unknown key `length` in [history]",
            ),
            ("[history]\nfile = \"~/.h\"\n", "a table `[history.file]`"),
            (
                "[history.file]\nfish = \"~/.h\"\n",
                "unknown key `fish` in [history.file]",
            ),
            ("[history.file]\nzsh = 1\n", "`zsh` must be a string"),
            ("[history.file]\nzsh = \"h\"\n", "[history.file] `zsh`"),
            ("[history.file]\nzsh = \"~\"\n", "is a directory"),
            ("[history.file]\nbash = \"/\"\n", "is a directory"),
            ("[history.file]\nzsh = \"~/a b\"\n", "holds ' '"),
            ("[history.file]\nzsh = \"~/$x\"\n", "holds '$'"),
            ("[history.file]\nzsh = \"~/a\\\"b\"\n", "holds '\"'"),
            ("[history.file]\nzsh = \"/var/home/example/.h\"\n", "~/.h"),
        ] {
            let err = message(text);
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{text}: {err}");
        }
    }

    #[test]
    fn one_size_is_both_lengths_in_each_shells_own_names() {
        let history = History {
            size: Some(10000),
            ..History::default()
        };
        assert_eq!(
            history.render_zsh(),
            "HISTSIZE=10000\nSAVEHIST=10000\ntypeset -g +x HISTSIZE SAVEHIST\n"
        );
        assert_eq!(
            history.render_bash(),
            "HISTSIZE=10000\nHISTFILESIZE=10000\nexport -n HISTSIZE HISTFILESIZE\n"
        );
    }

    #[test]
    fn a_history_file_is_written_only_for_the_shell_it_names() {
        let zsh_only = History {
            zsh_file: Some(portable("~/.zsh_history")),
            ..History::default()
        };
        assert_eq!(
            zsh_only.render_zsh(),
            "HISTFILE=\"${HOME}/.zsh_history\"\ntypeset -g +x HISTFILE\n"
        );
        assert_eq!(zsh_only.render_bash(), "");
        let bash_only = History {
            bash_file: Some(portable("/srv/history/bash")),
            ..History::default()
        };
        assert_eq!(bash_only.render_zsh(), "");
        assert_eq!(
            bash_only.render_bash(),
            "HISTFILE=\"/srv/history/bash\"\nexport -n HISTFILE\n"
        );
    }

    #[test]
    fn each_option_is_rendered_in_a_fixed_order_as_declared() {
        assert_eq!(
            declared().render_zsh(),
            "HISTFILE=\"${HOME}/.zsh_history\"\nHISTSIZE=10000\nSAVEHIST=10000\n\
             typeset -g +x HISTFILE HISTSIZE SAVEHIST\n\
             setopt HIST_IGNORE_ALL_DUPS SHARE_HISTORY\n"
        );
        assert_eq!(
            declared().render_bash(),
            "HISTSIZE=10000\nHISTFILESIZE=10000\nHISTCONTROL=erasedups\n\
             export -n HISTSIZE HISTFILESIZE HISTCONTROL\n"
        );
        let cases = [
            (
                Some(Duplicates::Keep),
                None,
                "unsetopt HIST_IGNORE_DUPS HIST_IGNORE_ALL_DUPS\n",
                "HISTCONTROL=\nexport -n HISTCONTROL\n",
            ),
            (
                Some(Duplicates::Adjacent),
                Some(true),
                "setopt HIST_IGNORE_DUPS HIST_IGNORE_SPACE\nunsetopt HIST_IGNORE_ALL_DUPS\n",
                "HISTCONTROL=ignorespace:ignoredups\nexport -n HISTCONTROL\n",
            ),
            (
                None,
                Some(false),
                "unsetopt HIST_IGNORE_SPACE\n",
                "HISTCONTROL=\nexport -n HISTCONTROL\n",
            ),
            (
                None,
                Some(true),
                "setopt HIST_IGNORE_SPACE\n",
                "HISTCONTROL=ignorespace\nexport -n HISTCONTROL\n",
            ),
        ];
        for (duplicates, ignore_space, zsh, bash) in cases {
            let history = History {
                duplicates,
                ignore_space,
                ..History::default()
            };
            assert_eq!(history.render_zsh(), zsh, "{history:?}");
            assert_eq!(history.render_bash(), bash, "{history:?}");
        }
        // `share` is zsh's alone.
        let share = History {
            share: Some(false),
            ..History::default()
        };
        assert_eq!(share.render_zsh(), "unsetopt SHARE_HISTORY\n");
        assert_eq!(share.render_bash(), "");
    }

    #[test]
    fn a_later_layer_wins_key_by_key() {
        let mut merged = declared();
        merged.absorb(&History {
            size: Some(5),
            bash_file: Some(portable("~/.bash_history")),
            origin: Some(Origin {
                file: "/repo/modules/a.toml".into(),
                line: 3,
            }),
            ..History::default()
        });
        assert_eq!(
            merged,
            History {
                size: Some(5),
                bash_file: Some(portable("~/.bash_history")),
                origin: Some(Origin {
                    file: "/repo/modules/a.toml".into(),
                    line: 3,
                }),
                ..declared()
            }
        );
        // A layer that says nothing changes nothing.
        let before = merged.clone();
        merged.absorb(&History::default());
        assert_eq!(merged, before);
    }

    /// Every parameter a shell does not maintain itself, with its value and
    /// whether it is exported, before and after `body` runs.
    fn dumps(shell: &Path, flags: &[&str], dump: &str, body: &str) -> (String, String) {
        let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
        let got = String::from_utf8(run(shell, flags, &script)).expect("utf-8");
        let (before, after) = got.split_once("---\n").expect("two dumps");
        (
            before.to_string(),
            after.trim_end_matches("---\n").to_string(),
        )
    }

    /// The lines of `after` that are not in `before`.
    fn changed(before: &str, after: &str) -> Vec<String> {
        let before: Vec<&str> = before.lines().collect();
        after
            .lines()
            .filter(|line| !before.contains(line))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn zsh_reads_the_declaration_and_it_changes_only_its_own_parameters() {
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let history = History {
            ignore_space: Some(true),
            ..declared()
        };
        let probe = "print -r -- \"$HISTFILE $HISTSIZE $SAVEHIST\"\n\
                     for o in histignorealldups histignorespace sharehistory histignoredups; do \
                     [[ -o $o ]] && print -r -- \"$o on\" || print -r -- \"$o off\"; done\n";
        let got = run(&zsh, &["-f"], &format!("{}{probe}", history.render_zsh()));
        let home = std::str::from_utf8(&got)
            .expect("utf-8")
            .lines()
            .next()
            .expect("a line");
        assert!(home.ends_with("/.zsh_history 10000 10000"), "{home}");
        assert!(!home.starts_with("${HOME}"), "{home}");
        assert_eq!(
            String::from_utf8(got)
                .expect("utf-8")
                .lines()
                .skip(1)
                .collect::<Vec<_>>(),
            [
                "histignorealldups on",
                "histignorespace on",
                "sharehistory on",
                "histignoredups off",
            ]
        );

        // Invariant 2: only the three history parameters change, and nothing
        // is exported. `typeset +x` lists the unexported ones, `typeset -x`
        // the exported.
        let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                    [[ ${parameters[$n]} == *special* ]] || print -r -- \"$n=${(P)n}\"; \
                    done; print -r -- \"exported: ${(ok)parameters[(R)*export*]}\"; \
                    print -r -- ---; }\n";
        let (before, after) = dumps(&zsh, &["-f"], dump, &history.render_zsh());
        let mut names: Vec<String> = changed(&before, &after)
            .iter()
            .map(|line| line.split('=').next().expect("a name").to_string())
            .collect();
        names.sort();
        // `HISTSIZE` and `SAVEHIST` are special parameters in zsh, so the dump
        // leaves them out; the probe above reads them back.
        assert_eq!(names, ["HISTFILE"], "{before}\n---\n{after}");
        let exported = |dump: &str| {
            dump.lines()
                .find(|line| line.starts_with("exported: "))
                .expect("the exported line")
                .to_string()
        };
        assert_eq!(exported(&after), exported(&before));
    }

    #[test]
    fn bash_reads_the_declaration_and_it_changes_only_its_own_variables() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let history = History {
            bash_file: Some(portable("~/.bash_history")),
            ignore_space: Some(true),
            ..declared()
        };
        let body = history.render_bash();
        let got = run(
            &bash,
            &["--norc", "--noprofile"],
            &format!(
                "{body}printf '%s|' \"$HISTFILE\" \"$HISTSIZE\" \"$HISTFILESIZE\" \"$HISTCONTROL\"\n"
            ),
        );
        let got = String::from_utf8(got).expect("utf-8");
        assert!(
            got.ends_with("/.bash_history|10000|10000|ignorespace:erasedups|"),
            "{got}"
        );
        assert!(!got.contains("${HOME}"), "{got}");

        // Invariant 2: only the four history variables change, and nothing
        // is exported.
        let dump = "__bx_dump() { local n; for n in $(compgen -v); do case $n in \
                    BASH_*|FUNCNAME|_|n|LINENO|RANDOM|SECONDS|SRANDOM|EPOCH*|PIPESTATUS) continue;; \
                    esac; printf '%s=%s\\n' \"$n\" \"${!n}\"; done; \
                    printf 'exported: %s\\n' $(compgen -e); \
                    printf -- '---\\n'; }\n";
        let (before, after) = dumps(&bash, &["--norc", "--noprofile"], dump, &body);
        let mut names: Vec<String> = changed(&before, &after)
            .iter()
            .map(|line| line.split('=').next().expect("a name").to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["HISTCONTROL", "HISTFILE", "HISTFILESIZE", "HISTSIZE"],
            "{before}\n---\n{after}"
        );
    }

    #[test]
    fn bash_truncates_the_declared_file_not_its_default_one() {
        // `HISTFILE` is written before `HISTFILESIZE`, which truncates the
        // file `HISTFILE` names the moment it is assigned.
        let Some(bash) = installed("bash") else {
            return;
        };
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let default = scratch.path().join(".bash_history");
        let declared = scratch.path().join("declared");
        std::fs::write(&default, "a\nb\nc\n").expect("write");
        std::fs::write(&declared, "a\nb\nc\n").expect("write");
        let history = History {
            size: Some(1),
            bash_file: Some(Portable::from_path(&declared, Path::new(HOME)).expect("portable")),
            ..History::default()
        };
        let script = scratch.path().join("script");
        std::fs::write(&script, history.render_bash()).expect("write");
        let status = std::process::Command::new(bash)
            .args(["--norc", "--noprofile"])
            .arg(&script)
            .env_clear()
            .env("HOME", scratch.path())
            .env("HISTFILE", &default)
            .status()
            .expect("bash runs");
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(&default).expect("read"),
            "a\nb\nc\n"
        );
        assert_eq!(std::fs::read_to_string(&declared).expect("read"), "c\n");
    }

    #[test]
    fn zsh_unexports_history_parameters_an_exported_parent_set() {
        // A shell exports every parameter it imports from its environment,
        // and assigning one keeps the flag: without the rendered `typeset +x`
        // the declared values would reach every child process.
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let child = format!(
            "'{}' -f -c 'print -r -- child: ${{(ok)parameters[(R)*export*]}}'\n",
            zsh.display()
        );
        let script = format!(
            "export HISTFILE=/inherited HISTSIZE=5 SAVEHIST=5\n{}\
             print -r -- \"$HISTFILE $HISTSIZE $SAVEHIST\"\n\
             print -r -- ${{(t)HISTFILE}} ${{(t)HISTSIZE}} ${{(t)SAVEHIST}}\n{child}",
            declared().render_zsh()
        );
        let got = String::from_utf8(run(&zsh, &["-f"], &script)).expect("utf-8");
        let lines: Vec<&str> = got.lines().collect();
        assert!(lines[0].ends_with("/.zsh_history 10000 10000"), "{got}");
        assert!(!lines[1].contains("export"), "{got}");
        assert!(lines[2].starts_with("child: "), "{got}");
        for name in ["HISTFILE", "HISTSIZE", "SAVEHIST"] {
            assert!(!lines[2].split(' ').any(|n| n == name), "{name}: {got}");
        }
    }

    #[test]
    fn bash_unexports_history_variables_an_exported_parent_set() {
        let Some(bash) = installed("bash") else {
            return;
        };
        let history = History {
            bash_file: Some(portable("~/.bash_history")),
            ignore_space: Some(true),
            ..declared()
        };
        let child = format!(
            "'{}' --norc --noprofile -c 'echo child: $(compgen -e)'\n",
            bash.display()
        );
        let script = format!(
            "export HISTFILE=/inherited HISTSIZE=5 HISTFILESIZE=5 HISTCONTROL=ignoreboth\n{}\
             printf '%s|' \"$HISTFILE\" \"$HISTSIZE\" \"$HISTFILESIZE\" \"$HISTCONTROL\"\n\
             echo; echo exported: $(compgen -e)\n{child}",
            history.render_bash()
        );
        let got =
            String::from_utf8(run(&bash, &["--norc", "--noprofile"], &script)).expect("utf-8");
        assert!(
            got.lines()
                .next()
                .is_some_and(|l| l.ends_with("/.bash_history|10000|10000|ignorespace:erasedups|")),
            "{got}"
        );
        assert!(
            got.contains("\nexported:") && got.contains("\nchild:"),
            "{got}"
        );
        for name in ["HISTFILE", "HISTSIZE", "HISTFILESIZE", "HISTCONTROL"] {
            for line in got.lines().skip(1) {
                assert!(!line.split_whitespace().any(|n| n == name), "{name}: {got}");
            }
        }
    }
}
