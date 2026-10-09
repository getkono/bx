//! zsh's generated interactive file, `~/.local/share/bx/zshrc.zsh`: the
//! [`Interactive`] value resolution and the plan build, rendered through
//! [`Assembly`] in its fixed phase order.
//!
//! What the file holds, and which part of it is judged as an environment
//! fragment, is [`Interactive`]'s to say; this is how its bytes and its plan
//! row's note are made.

use super::{Assembly, Phase, SETTLE, Shell, held};
use crate::config::target::Interactive;

impl Interactive {
    /// The note the file's plan row carries: every function held back from
    /// it, then every source, each named with what would release it, then
    /// the declarations that do not reach zsh, or `None` when there is none
    /// of them.
    ///
    /// Decided by the values alone, never by `present`, so the note is the
    /// same whichever tools this machine has.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        let notes: Vec<String> = [
            super::function::note(&held(self.functions())),
            super::source::note(&held(self.sources())),
            self.omitted().map(str::to_string),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!notes.is_empty()).then(|| notes.join("; "))
    }

    /// The file's bytes.
    ///
    /// The fragment is contributed only when it holds a variable, so a file
    /// with plugins alone has no `env` phase, a history declaring nothing zsh
    /// reads adds no `options` phase, a file whose every alias is gated on a
    /// missing tool has no `aliases` phase, and a file whose every function is
    /// held back has no `functions` phase, and a file binding no key has no
    /// `keybindings` phase. The bytes are a function of the variables, the
    /// plugins, the history, the aliases, the functions, the keybindings, the
    /// sources, the activations the plan attached and `present`'s answers
    /// alone: never of whether a plugin's or a source's file exists.
    ///
    /// A file holding a plugin, a source line or an activation closes with
    /// [`SETTLE`]. A guarded line whose file is absent returns 1, an
    /// activation's `eval` returns whatever the tool's code last did, and a
    /// file sourced at
    /// startup returns the status of its last command, so a file ending on one
    /// would stop a shell running under `ERR_EXIT` before its prompt — and
    /// show every other shell a failed status at its first prompt.
    #[must_use]
    pub fn render(&self, present: &dyn Fn(&str) -> bool) -> String {
        let mut assembly = Assembly::new();
        let env = self.env();
        let contributed = if env.vars.is_empty() {
            Ok(())
        } else {
            assembly.contribute(Phase::Env, crate::config::env::SECTION, env.render(present))
        }
        .and_then(|()| super::plugin::contribute(&mut assembly, self.plugins()))
        .and_then(|()| {
            assembly.contribute(
                Phase::Options,
                crate::config::history::SECTION,
                self.history().render_zsh(),
            )
        });
        // Only the terminal slot refuses a contribution, and `with_plugins`
        // admitted at most one claimant.
        contributed.expect("an `Interactive` holds at most one terminal claimant");
        super::alias::contribute(&mut assembly, self.aliases(), present);
        // The held-back functions are the note's to name, not the bytes'.
        super::function::contribute(&mut assembly, self.functions(), present);
        super::update_prompt::contribute(&mut assembly, self.update_prompt(), Shell::Zsh);
        super::keybindings::contribute(&mut assembly, self.keybindings());
        // An activation lands only in `activations` or `completions`, neither
        // of which refuses a contribution.
        super::activation::contribute(&mut assembly, self.activations())
            .expect("an activation never claims the terminal slot");
        let activated = !self.activations().is_empty();
        // Last, so each source follows its phase's own declarations; the
        // held-back ones are the note's to name.
        let sourced = super::source::contribute(&mut assembly, self.sources(), Shell::Zsh, present);
        let mut out = assembly.render();
        if !self.plugins().is_empty() || sourced || activated {
            out.push_str(SETTLE);
        }
        out
    }
}
