//! Declared keybindings: the `[keybindings]` table, a closed set of six keys
//! each bound to one of four line-editing actions.
//!
//! ```toml
//! [keybindings]
//! home      = "beginning-of-line"
//! end       = "end-of-line"
//! alt-right = "forward-word"
//! alt-f     = "forward-word"
//! alt-left  = "backward-word"
//! alt-b     = "backward-word"
//! ```
//!
//! The vocabulary is closed on both sides. A key is one of the six [`Key`]s
//! and an action one of the four [`Action`]s; a key or an action this version
//! does not know is a load error naming its line, never a line silently
//! dropped. Each action's name is the one zsh's line editor and bash's
//! readline both call it, so one declaration means the same thing in either.
//!
//! The table merges key by key, the last layer that binds a key winning, and
//! the bindings are always rendered in [`Key::ALL`]'s order, whatever order
//! they were written in, so the bytes are a function of the declaration alone.
//!
//! # zsh
//!
//! [`Keybindings::render_zsh`] lands in the interactive file's `keybindings`
//! phase. Home and End send different bytes on different terminals: the
//! sequence terminfo records for them (`khome`, `kend`) is the one a terminal
//! sends in keypad-transmit mode, and most terminals send `ESC [ H` and
//! `ESC [ F` otherwise. So a key with a terminfo capability is bound twice —
//! to the capability's value, looked up through zsh's own `$terminfo` when
//! the terminal defines one, and to the literal sequence — and a key without
//! one is bound to its literal sequence alone. The lookup is a parameter zsh
//! reads in-process: it starts no process and parses no file of bx's.
//!
//! # readline
//!
//! [`Keybindings::render_readline`] is the same declaration in `~/.inputrc`'s
//! words: the same bindings, in the same order, under the same action names.
//! An inputrc has no terminfo lookup, so each key is bound to its literal
//! sequence. Nothing attaches it to a file yet; the entry that generates
//! bash's own files places it.
//!
//! # Invariant 2
//!
//! The `keybindings` phase is generated shell content that is not an
//! environment fragment, so it carries no assignment: each line is `bindkey`
//! given a sequence and a widget, the capability lines guarded by a test.
//! `zsh_binds_every_key_and_sets_no_variable` runs the rendered bytes in zsh
//! and holds them to that.

use std::path::Path;

use toml_edit::Table;

use super::{Assembly, Phase};
use crate::config::{Ctx, Error, Origin};

/// The section header, as messages spell it.
pub(crate) const SECTION: &str = "[keybindings]";

/// A key a binding may name.
///
/// Declared in the order the bindings are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// Home.
    Home,
    /// End.
    End,
    /// Alt and the right arrow.
    AltRight,
    /// Alt and `f`.
    AltF,
    /// Alt and the left arrow.
    AltLeft,
    /// Alt and `b`.
    AltB,
}

impl Key {
    /// Every key, in the order the bindings are rendered.
    pub const ALL: [Self; 6] = [
        Self::Home,
        Self::End,
        Self::AltRight,
        Self::AltF,
        Self::AltLeft,
        Self::AltB,
    ];

    /// The key's name, as `[keybindings]` spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::End => "end",
            Self::AltRight => "alt-right",
            Self::AltF => "alt-f",
            Self::AltLeft => "alt-left",
            Self::AltB => "alt-b",
        }
    }

    /// The terminfo capability recording the key's sequence, where there is
    /// a standard one.
    #[must_use]
    pub const fn capability(self) -> Option<&'static str> {
        match self {
            Self::Home => Some("khome"),
            Self::End => Some("kend"),
            Self::AltRight | Self::AltF | Self::AltLeft | Self::AltB => None,
        }
    }

    /// What the key sends after its leading escape, in the terminal's normal
    /// mode: every one of the six opens with `ESC`.
    #[must_use]
    pub const fn after_escape(self) -> &'static str {
        match self {
            Self::Home => "[H",
            Self::End => "[F",
            Self::AltRight => "[1;3C",
            Self::AltF => "f",
            Self::AltLeft => "[1;3D",
            Self::AltB => "b",
        }
    }
}

/// A line-editing action a key may be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Move to the start of the line.
    BeginningOfLine,
    /// Move to the end of the line.
    EndOfLine,
    /// Move forward one word.
    ForwardWord,
    /// Move back one word.
    BackwardWord,
}

impl Action {
    /// Every action.
    pub const ALL: [Self; 4] = [
        Self::BeginningOfLine,
        Self::EndOfLine,
        Self::ForwardWord,
        Self::BackwardWord,
    ];

    /// The action's name: `[keybindings]`'s spelling, zsh's widget and
    /// readline's function alike.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeginningOfLine => "beginning-of-line",
            Self::EndOfLine => "end-of-line",
            Self::ForwardWord => "forward-word",
            Self::BackwardWord => "backward-word",
        }
    }
}

/// What one layer's `[keybindings]` table says, or what the merged layers say.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Keybindings {
    /// Each key's action, indexed by the key's position in [`Key::ALL`].
    bindings: [Option<Action>; 6],
    /// Where the table that last bound a key was written.
    pub origin: Option<Origin>,
}

impl Keybindings {
    /// The declaration with `key` bound to `action`.
    #[must_use]
    pub const fn bind(mut self, key: Key, action: Action) -> Self {
        self.bindings[key as usize] = Some(action);
        self
    }

    /// The action `key` is bound to, if any.
    #[must_use]
    pub const fn get(&self, key: Key) -> Option<Action> {
        self.bindings[key as usize]
    }

    /// Whether no key is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.iter().all(Option::is_none)
    }

    /// Each binding, in [`Key::ALL`]'s order.
    pub fn declared(&self) -> impl Iterator<Item = (Key, Action)> + '_ {
        Key::ALL
            .into_iter()
            .filter_map(|key| self.get(key).map(|action| (key, action)))
    }

    /// Fold a later layer's table over this one, key by key, the later layer
    /// winning.
    pub(crate) fn absorb(&mut self, later: &Self) {
        for key in Key::ALL {
            if let Some(action) = later.get(key) {
                self.bindings[key as usize] = Some(action);
            }
        }
        if let Some(origin) = &later.origin {
            self.origin = Some(origin.clone());
        }
    }

    /// The declaration in zsh's words, or nothing when no key is bound.
    ///
    /// A key with a terminfo capability gets a guarded line binding the
    /// capability's value, then a line binding its literal sequence; a key
    /// without one gets the literal line alone. The guard is an `if`, so a
    /// terminal without the capability leaves a status of 0, not the failed
    /// test's.
    #[must_use]
    pub fn render_zsh(&self) -> String {
        let mut out = String::new();
        for (key, action) in self.declared() {
            let action = action.name();
            if let Some(cap) = key.capability() {
                out.push_str(&format!(
                    "if [[ -n ${{terminfo[{cap}]-}} ]]; then \
                     bindkey -- \"${{terminfo[{cap}]}}\" {action}; fi\n"
                ));
            }
            out.push_str(&format!("bindkey -- '^[{}' {action}\n", key.after_escape()));
        }
        out
    }

    /// The declaration in `~/.inputrc`'s words, or nothing when no key is
    /// bound: one line per binding, each key's literal sequence.
    #[must_use]
    pub fn render_readline(&self) -> String {
        self.declared()
            .map(|(key, action)| format!("\"\\e{}\": {}\n", key.after_escape(), action.name()))
            .collect()
    }
}

/// Add the declared bindings to the `keybindings` phase, which adds nothing
/// when no key is bound.
pub fn contribute(assembly: &mut Assembly, keybindings: &Keybindings) {
    // The keybindings phase is not the terminal slot, so it never refuses.
    let _ = assembly.contribute(Phase::Keybindings, SECTION, keybindings.render_zsh());
}

/// Parse a `[keybindings]` table.
///
/// `text` is the whole layer file, because spans index into it.
///
/// # Errors
///
/// [`Error::UnknownKey`] for a key name this version does not know,
/// [`Error::WrongType`] for an action that is not a string, and
/// [`Error::BadValue`] for an action name this version does not know.
pub fn parse_keybindings(table: &Table, file: &Path, text: &str) -> Result<Keybindings, Error> {
    let ctx = Ctx::new(table, file, text, SECTION);
    let names = Key::ALL.map(Key::name);
    ctx.reject_unknown_keys(table, &names)?;
    let mut keybindings = Keybindings::default();
    for key in Key::ALL {
        let Some(raw) = ctx.str_at(table, key.name())? else {
            continue;
        };
        let action = Action::ALL
            .into_iter()
            .find(|action| action.name() == raw)
            .ok_or_else(|| {
                let known = Action::ALL
                    .map(|action| format!("{:?}", action.name()))
                    .join(", ");
                ctx.bad(
                    table,
                    key.name(),
                    format!("`{}` must be one of {known}; found {raw:?}", key.name()),
                )
            })?;
        keybindings = keybindings.bind(key, action);
    }
    if !keybindings.is_empty() {
        keybindings.origin = Some(ctx.origin().clone());
    }
    Ok(keybindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::shell::testing::{installed, run};

    /// The source configuration's bindings, written in its order.
    const SOURCE: &str = "[keybindings]\nhome = \"beginning-of-line\"\nend = \"end-of-line\"\n\
                          alt-right = \"forward-word\"\nalt-f = \"forward-word\"\n\
                          alt-left = \"backward-word\"\nalt-b = \"backward-word\"\n";

    fn parse(text: &str) -> Result<Keybindings, Error> {
        parse_str(text, Path::new("/repo/bx.toml"), Path::new("/home/u"))
            .map(|config| config.keybindings)
    }

    fn source() -> Keybindings {
        parse(SOURCE).expect("parses")
    }

    #[test]
    fn the_six_keys_and_four_actions_are_each_named_once() {
        let mut keys: Vec<_> = Key::ALL.iter().map(|k| k.name()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 6);
        let mut actions: Vec<_> = Action::ALL.iter().map(|a| a.name()).collect();
        actions.sort_unstable();
        actions.dedup();
        assert_eq!(actions.len(), 4);
        for (index, key) in Key::ALL.iter().enumerate() {
            assert_eq!(*key as usize, index, "{key:?}");
        }
    }

    #[test]
    fn every_key_parses_and_renders_for_zsh_in_a_fixed_order() {
        let keybindings = source();
        assert_eq!(keybindings.get(Key::Home), Some(Action::BeginningOfLine));
        assert_eq!(keybindings.get(Key::AltB), Some(Action::BackwardWord));
        assert!(keybindings.origin.is_some());
        let expected = "if [[ -n ${terminfo[khome]-} ]]; then \
                        bindkey -- \"${terminfo[khome]}\" beginning-of-line; fi\n\
                        bindkey -- '^[[H' beginning-of-line\n\
                        if [[ -n ${terminfo[kend]-} ]]; then \
                        bindkey -- \"${terminfo[kend]}\" end-of-line; fi\n\
                        bindkey -- '^[[F' end-of-line\n\
                        bindkey -- '^[[1;3C' forward-word\n\
                        bindkey -- '^[f' forward-word\n\
                        bindkey -- '^[[1;3D' backward-word\n\
                        bindkey -- '^[b' backward-word\n";
        assert_eq!(keybindings.render_zsh(), expected);
        // Written in any order, the same bytes; and twice, the same bytes.
        let mut lines: Vec<&str> = SOURCE.lines().skip(1).collect();
        lines.reverse();
        let reversed: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let shuffled = parse(&format!("[keybindings]\n{reversed}")).expect("parses");
        assert_eq!(shuffled.render_zsh(), expected);
        assert_eq!(keybindings.render_zsh(), keybindings.render_zsh());
    }

    #[test]
    fn readline_gets_the_same_bindings_under_the_same_names() {
        let keybindings = source();
        assert_eq!(
            keybindings.render_readline(),
            "\"\\e[H\": beginning-of-line\n\
             \"\\e[F\": end-of-line\n\
             \"\\e[1;3C\": forward-word\n\
             \"\\ef\": forward-word\n\
             \"\\e[1;3D\": backward-word\n\
             \"\\eb\": backward-word\n"
        );
        // One line per binding, in the order zsh gets them, each naming the
        // action zsh's literal line names.
        let (zsh, readline) = (keybindings.render_zsh(), keybindings.render_readline());
        let zsh: Vec<&str> = zsh
            .lines()
            .filter(|line| line.starts_with("bindkey -- '"))
            .map(|line| line.rsplit(' ').next().expect("an action"))
            .collect();
        let readline: Vec<&str> = readline
            .lines()
            .map(|line| line.rsplit(' ').next().expect("an action"))
            .collect();
        assert_eq!(zsh, readline);
    }

    #[test]
    fn binding_nothing_renders_nothing() {
        for text in ["", "[keybindings]\n"] {
            let keybindings = parse(text).expect(text);
            assert_eq!(keybindings, Keybindings::default());
            assert!(keybindings.is_empty());
            assert_eq!(keybindings.render_zsh(), "");
            assert_eq!(keybindings.render_readline(), "");
            let mut assembly = Assembly::new();
            contribute(&mut assembly, &keybindings);
            assert!(assembly.is_empty());
            assert!(!assembly.render().contains("keybindings"));
        }
    }

    #[test]
    fn an_unknown_key_an_unknown_action_or_a_non_string_is_refused() {
        for (text, needle) in [
            (
                "[keybindings]\nctrl-a = \"beginning-of-line\"\n",
                "unknown key `ctrl-a` in [keybindings]",
            ),
            (
                "[keybindings]\n\nhome = \"kill-line\"\n",
                "`home` must be one of \"beginning-of-line\", \"end-of-line\", \
                 \"forward-word\", \"backward-word\"; found \"kill-line\"",
            ),
            ("[keybindings]\nend = true\n", "`end` must be a string"),
            ("keybindings = 1\n", "a table `[keybindings]`"),
        ] {
            let err = parse(text).expect_err(text).to_string();
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.starts_with("/repo/bx.toml:"), "{text}: {err}");
        }
        // The action's error names the line it is on.
        let err = parse("[keybindings]\n\nhome = \"kill-line\"\n")
            .expect_err("unknown action")
            .to_string();
        assert!(err.starts_with("/repo/bx.toml:3:"), "{err}");
    }

    #[test]
    fn a_later_layer_wins_key_by_key() {
        let mut merged = source();
        let later = parse("[keybindings]\nalt-f = \"end-of-line\"\n").expect("parses");
        merged.absorb(&later);
        assert_eq!(merged.get(Key::AltF), Some(Action::EndOfLine));
        assert_eq!(merged.get(Key::Home), Some(Action::BeginningOfLine));
        assert_eq!(merged.origin, later.origin);
        // A layer binding nothing changes nothing, its origin included.
        let before = merged.clone();
        merged.absorb(&Keybindings::default());
        assert_eq!(merged, before);
    }

    #[test]
    fn zsh_binds_every_key_and_sets_no_variable() {
        let Some(zsh) = installed("zsh") else {
            return;
        };
        let rendered = source().render_zsh();
        // `bindkey SEQUENCE` prints the sequence and the widget bound to it.
        let probe = "for s in '^[[H' '^[[F' '^[[1;3C' '^[f' '^[[1;3D' '^[b'; do \
                     bindkey -- $s; done\n";
        let got = run(&zsh, &["-f", "-e"], &format!("{rendered}{probe}"));
        assert_eq!(
            String::from_utf8(got).expect("utf-8"),
            "\"^[[H\" beginning-of-line\n\"^[[F\" end-of-line\n\
             \"^[[1;3C\" forward-word\n\"^[f\" forward-word\n\
             \"^[[1;3D\" backward-word\n\"^[b\" backward-word\n"
        );

        // On a terminal whose terminfo records Home and End, the recorded
        // sequences are bound too.
        let got = run(
            &zsh,
            &["-f", "-e"],
            &format!(
                "TERM=xterm\n{rendered}\
                 [[ -n $terminfo[khome] && -n $terminfo[kend] ]] || print -r -- no-terminfo\n\
                 for c in khome kend; do r=$(bindkey -- \"$terminfo[$c]\"); \
                 print -r -- ${{r##* }}; done\n"
            ),
        );
        assert_eq!(
            String::from_utf8(got).expect("utf-8"),
            "beginning-of-line\nend-of-line\n"
        );

        // Invariant 2: every parameter zsh does not maintain itself, with its
        // value, the same before and after. The first, discarded dump loads
        // every autoloaded parameter, `terminfo` among them.
        let dump = "__bx_dump() { local n; for n in ${(ok)parameters}; do \
                    [[ ${parameters[$n]} == *special* ]] || print -r -- \"$n=${(P)n}\"; \
                    done; print -r -- ---; }\n";
        let dumps = |body: &str| {
            let script = format!("{dump}__bx_dump >/dev/null\n__bx_dump\n{body}__bx_dump\n");
            let got = String::from_utf8(run(&zsh, &["-f"], &script)).expect("utf-8");
            let (before, after) = got.split_once("---\n").expect("two dumps");
            (
                before.to_string(),
                after.trim_end_matches("---\n").to_string(),
            )
        };
        let (before, after) = dumps(&rendered);
        assert_eq!(after, before);
        let (before, after) = dumps("Z=1\n");
        assert_ne!(after, before);
    }
}
