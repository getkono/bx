//! `bx init`: the guided setup, first machine or fifth.
//!
//! Everything `init` does before it plans, in the order it does it:
//!
//! 1. **Answers, in memory.** Each `--set NAME=VALUE` is checked with the
//!    loader's own [`ResolvedValues::check_answer`], in declaration order
//!    whatever order the flags came in, so a later answer may reference an
//!    earlier one. Then every required value still unset is asked for, in
//!    declaration order, re-resolving after each answer so a later declaration
//!    sees the earlier ones — and a value an earlier answer made derivable is
//!    never asked at all. An invalid answer is re-asked with the loader's own
//!    reason. With no terminal, or with `--yes`, nothing is asked: a value
//!    still unset stops `init` naming each one and its `--set` spelling, with
//!    nothing written.
//! 2. **The config repo**, created with the fixed [`HEADER`] as its `bx.toml`
//!    when there is none. An existing repo is never written here.
//! 3. **`local.toml`**, written once, at `0600`, in the state directory — never
//!    in the repo — and only when an answer changed it. The edit is
//!    [`local::set`]'s, so a comment the account wrote there survives.
//! 4. **Discovery**, interactive runs only: the tool config already on the
//!    machine that [`adopt::discover`] finds, offered with nothing selected,
//!    and each selection adopted through [`adopt::add`] — `bx add` itself.
//!
//! Planning and applying are `bx apply`'s, with its approval rule, and are
//! called by [`crate::command::init`] once this has run. So a second `init` on
//! a converged machine asks nothing, writes nothing, and exits as `bx plan`
//! would: 0.

use std::path::{Path, PathBuf};

use toml_edit::DocumentMut;

use crate::adopt::{self, Adoption};
use crate::config::values::{self, AnswerError, ResolvedValues, ValueDecl, local};
use crate::config::{self, Layer, LayerKind, layers, merge};
use crate::fs::{self, Mode};
use crate::paths::{self, Portable};
use crate::plan::Env;
use crate::state::{self, ExclusiveLock, StateDir};

/// The `bx.toml` a new config repo starts with.
///
/// Fixed text: no timestamp, no account, no machine, so every repo `init`
/// creates starts byte-identical and publishable.
pub const HEADER: &str = "\
# bx configuration repository.
#
# This file and modules/*.toml declare what bx manages on every account that
# uses this repository: a [[target]] for each file, and a [[value]] for each
# thing an account answers for itself. `bx add PATH` appends a target here.
#
# No answer lives here. `bx init` writes each account's answers to local.toml
# in bx's state directory, outside this repository, so it is safe to publish.
";

/// Everything that stops `bx init` before it plans.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `--set` without an `=`.
    #[error("`--set {0}` has no `=`; write it as --set NAME=VALUE")]
    BadSet(String),
    /// A `--set` the loader would not accept.
    #[error("--set {name}: {source}; nothing was written")]
    Answer {
        /// The value it named.
        name: String,
        /// Why the answer is not usable.
        #[source]
        source: AnswerError,
    },
    /// Values are unset and there is nobody to ask.
    #[error(
        "bx init asks for a value only on a terminal and without --yes, and {} declared \
         value(s) have no answer; nothing was written. Answer each on the command line:\n{}",
        .0.len(),
        .0.iter().map(|(name, about)| format!("  bx init {}{about}", values::set_flag(name)))
            .collect::<Vec<_>>().join("\n")
    )]
    Unset(Vec<(String, String)>),
    /// The configuration could not be loaded, merged or resolved.
    #[error(transparent)]
    Config(#[from] config::Error),
    /// `local.toml` could not be read.
    #[error("reading {}: {source}", .path.display())]
    ReadLocal {
        /// `local.toml`.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// `local.toml` is not TOML `toml_edit` can edit.
    #[error("{}: {why}", .path.display())]
    Local {
        /// `local.toml`.
        path: PathBuf,
        /// Why.
        why: String,
    },
    /// The config repo's directory could not be made.
    #[error("creating the config repo {}: {source}", .path.display())]
    CreateRepo {
        /// The repo.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A write failed.
    #[error(transparent)]
    Fs(#[from] fs::Error),
    /// The state directory failed, including another bx holding it.
    #[error(transparent)]
    State(#[from] state::Error),
    /// A prompt failed or was interrupted.
    #[error("asking a question: {0}")]
    Prompt(#[source] inquire::InquireError),
    /// Adopting a selection failed.
    #[error(transparent)]
    Adopt(#[from] adopt::Error),
    /// Planning or applying failed.
    #[error(transparent)]
    Plan(#[from] crate::plan::Error),
    /// The output could not be written.
    #[error("writing the output: {0}")]
    Output(#[source] std::io::Error),
}

/// The questions `init` asks, as a seam: [`Terminal`] asks them on the
/// terminal, and a test answers them itself.
pub trait Ask {
    /// An answer for `decl`. `problem` is why the previous answer was refused.
    ///
    /// # Errors
    ///
    /// [`Error::Prompt`] when the question cannot be asked or is abandoned.
    fn value(&mut self, decl: &ValueDecl, problem: Option<&str>) -> Result<String, Error>;

    /// Which of `offered` to adopt. Nothing is selected until the user picks
    /// it.
    ///
    /// # Errors
    ///
    /// [`Error::Prompt`] when the question cannot be asked or is abandoned.
    fn adopt(&mut self, offered: &[Portable]) -> Result<Vec<Portable>, Error>;
}

/// [`Ask`] on the terminal, through `inquire`.
#[derive(Debug, Default)]
pub struct Terminal;

impl Ask for Terminal {
    fn value(&mut self, decl: &ValueDecl, problem: Option<&str>) -> Result<String, Error> {
        let label = format!("{}:", decl.description.as_deref().unwrap_or(&decl.name));
        let help = problem.map_or_else(
            || {
                format!(
                    "{} ({}); non-interactively, {}",
                    decl.name,
                    decl.kind,
                    values::set_flag(&decl.name)
                )
            },
            |problem| format!("{problem}; try again"),
        );
        inquire::Text::new(&label)
            .with_help_message(&help)
            .prompt()
            .map_err(Error::Prompt)
    }

    fn adopt(&mut self, offered: &[Portable]) -> Result<Vec<Portable>, Error> {
        let shown: Vec<&str> = offered.iter().map(Portable::as_str).collect();
        let picked = inquire::MultiSelect::new("Manage which of these with bx?", shown)
            .with_help_message(
                "space selects, enter confirms; nothing is selected until you pick it",
            )
            .raw_prompt()
            .map_err(Error::Prompt)?;
        Ok(picked
            .into_iter()
            .map(|option| offered[option.index].clone())
            .collect())
    }
}

/// What [`prepare`] did.
#[derive(Debug, Default)]
pub struct Prepared {
    /// The config repo, when `init` created it.
    pub created: Option<PathBuf>,
    /// `local.toml`, when `init` wrote it.
    pub saved: Option<PathBuf>,
    /// What adopting each selection did, in the order selected.
    pub adopted: Vec<Adoption>,
}

/// Everything `init` does before it plans; see the [module documentation](self).
///
/// `interactive` is whether questions may be asked: a terminal on standard
/// input and no `--yes`.
///
/// # Errors
///
/// [`Error::BadSet`] and [`Error::Answer`] for a `--set` that cannot be used,
/// and [`Error::Unset`] when a value is unset and `interactive` is false — all
/// three before anything is written — and otherwise whatever loading, asking,
/// writing or adopting returns.
pub fn prepare(
    env: &Env,
    sets: &[String],
    interactive: bool,
    ask: &mut dyn Ask,
) -> Result<Prepared, Error> {
    let home = &env.home;
    let repo = paths::config_root_in(home, env.xdg_config_home.as_deref());
    let state = StateDir::resolve_in(home, env.xdg_state_home.as_deref());
    let mut answers = Answers::load(&repo, &state, home)?;

    answers.set_all(sets)?;
    answers.ask_unset(interactive, ask)?;

    let mut prepared = Prepared {
        created: create_repo(&repo)?.then(|| repo.clone()),
        saved: answers.save(&state)?,
        adopted: Vec::new(),
    };

    if interactive {
        let config_home = paths::xdg_base(env.xdg_config_home.as_deref(), home, ".config");
        let offered = adopt::discover(&adopt::Context::load(env)?, &config_home)?;
        if !offered.is_empty() {
            for target in ask.adopt(&offered)? {
                // Reloaded for each, so each adoption sees what the one before
                // it declared.
                let ctx = adopt::Context::load(env)?;
                prepared.adopted.extend(adopt::add(&ctx, &target)?);
            }
        }
    }
    Ok(prepared)
}

/// Create the config repo with [`HEADER`] as its `bx.toml`, when nothing is at
/// `repo`. Reports whether it did.
///
/// Anything already at the path — a repo, an empty directory, or something
/// that is not a directory at all — is left exactly as it is: a directory is
/// a repo `init` must not rewrite, and anything else is the loader's to
/// refuse.
fn create_repo(repo: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(repo) {
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::CreateRepo {
                path: repo.to_path_buf(),
                source,
            });
        }
    }
    // At the umask's mode, as `git` makes a checkout's directories: this is
    // the user's repository, not bx's state.
    std::fs::create_dir_all(repo).map_err(|source| Error::CreateRepo {
        path: repo.to_path_buf(),
        source,
    })?;
    fs::write_atomically(&repo.join("bx.toml"), HEADER.as_bytes(), Mode::DEFAULT_FILE)?;
    Ok(true)
}

/// Split one `--set NAME=VALUE` at its first `=`.
fn parse_set(raw: &str) -> Result<(String, String), Error> {
    raw.split_once('=')
        .map(|(name, answer)| (name.to_string(), answer.to_string()))
        .ok_or_else(|| Error::BadSet(raw.to_string()))
}

/// The committed layers, and this account's `local.toml` as a document being
/// edited.
struct Answers {
    home: PathBuf,
    globals: Vec<Layer>,
    path: PathBuf,
    doc: DocumentMut,
    /// The file's text when `init` read it; `None` when there was none.
    original: Option<String>,
    /// Every answer set on `doc`, in the order it was set, so [`Self::save`]
    /// can set them again on the file as it stands when the lock is held.
    given: Vec<(String, String)>,
}

impl Answers {
    /// Load the layer set as `plan` does. With no config repo there is nothing
    /// declared, so no committed layer.
    fn load(repo: &Path, state: &StateDir, home: &Path) -> Result<Self, Error> {
        let globals = match layers::load_layer_set(repo, state.root(), home) {
            Ok(set) => set
                .into_iter()
                .filter(|layer| layer.kind == LayerKind::Global)
                .collect(),
            Err(config::Error::RepoMissing(_)) => Vec::new(),
            Err(other) => return Err(other.into()),
        };
        let path = state.local_toml();
        let original = read_local(&path)?;
        let doc = parse_local(&path, original.as_deref())?;
        Ok(Self {
            home: home.to_path_buf(),
            globals,
            path,
            doc,
            original,
            given: Vec::new(),
        })
    }

    /// Set `answer` for `name` on the document, and remember it for
    /// [`Self::save`].
    fn give(&mut self, name: &str, answer: &str) {
        local::set(&mut self.doc, name, answer);
        self.given.push((name.to_string(), answer.to_string()));
    }

    /// The declared values, resolved against the answers as they stand now.
    ///
    /// Through the loader's own parse and merge, with the document in place of
    /// the file, so what this reports is what the next load of the written
    /// file will.
    fn values(&self) -> Result<ResolvedValues, Error> {
        let local = Layer {
            file: self.path.clone(),
            kind: LayerKind::Local,
            config: config::parse_str(&self.doc.to_string(), &self.path, &self.home)?,
        };
        let mut set = self.globals.clone();
        set.push(local);
        let merged = merge::merge(&set, &self.home)?;
        Ok(ResolvedValues::resolve(
            merged.values,
            &merged.value_assignments,
            &self.home,
        )?)
    }

    /// Apply every `--set`, in declaration order.
    ///
    /// The answer written is the one given, not its canonical text. The
    /// canonical text is what the loader derives *from* a line, and it does not
    /// always read back as itself: `{{{{` is a literal `{{` in an answer, and
    /// the `{{` it becomes is a malformed placeholder the next load refuses.
    fn set_all(&mut self, sets: &[String]) -> Result<(), Error> {
        let mut sets = sets
            .iter()
            .map(|raw| parse_set(raw))
            .collect::<Result<Vec<_>, _>>()?;
        let values = self.values()?;
        // Stable, so of two `--set`s for one name the later one wins.
        sets.sort_by_key(|(name, _)| values.index_of(name).unwrap_or(usize::MAX));
        for (name, answer) in sets {
            self.values()?
                .check_answer(&name, &answer)
                .map_err(|source| Error::Answer {
                    name: name.clone(),
                    source,
                })?;
            self.give(&name, &answer);
        }
        Ok(())
    }

    /// Ask for every required value still unset, in declaration order, or —
    /// when nobody can be asked — refuse naming them all.
    fn ask_unset(&mut self, interactive: bool, ask: &mut dyn Ask) -> Result<(), Error> {
        loop {
            let values = self.values()?;
            let Some(decl) = values.unset_required().first().map(|decl| (*decl).clone()) else {
                return Ok(());
            };
            if !interactive {
                return Err(Error::Unset(
                    values
                        .unset_required()
                        .into_iter()
                        .map(|decl| {
                            let about = decl
                                .description
                                .as_deref()
                                .map_or_else(String::new, |about| format!("  ({about})"));
                            (decl.name.clone(), about)
                        })
                        .collect(),
                ));
            }
            let mut problem: Option<String> = None;
            let answer = loop {
                let answer = ask.value(&decl, problem.as_deref())?;
                match values.check_answer(&decl.name, &answer) {
                    Ok(_) => break answer,
                    Err(refused) => problem = Some(refused.to_string()),
                }
            };
            self.give(&decl.name, &answer);
        }
    }

    /// Write `local.toml` at `0600` when an answer changed it, reporting where.
    ///
    /// The answers are set again on the file as it stands once the lock is
    /// held, not on the copy read before the prompts, so an edit made while
    /// `init` was asking — by hand, or by another `bx init` — survives, and
    /// only the names answered here change.
    ///
    /// A state directory inside the repo never reaches this: [`Self::load`]
    /// runs the loader's own [`layers::layer_paths`], which refuses it, and
    /// no answer can be given without the repo that load reads.
    fn save(&self, state: &StateDir) -> Result<Option<PathBuf>, Error> {
        let unchanged = match &self.original {
            Some(original) => *original == self.doc.to_string(),
            None => self.doc.to_string() == local::empty().to_string(),
        };
        if unchanged {
            return Ok(None);
        }
        state.ensure()?;
        let _lock = ExclusiveLock::acquire(state)?;
        let current = read_local(&self.path)?;
        let mut doc = parse_local(&self.path, current.as_deref())?;
        for (name, answer) in &self.given {
            local::set(&mut doc, name, answer);
        }
        let text = doc.to_string();
        if current.as_deref() == Some(text.as_str()) {
            return Ok(None);
        }
        fs::write_atomically(&self.path, text.as_bytes(), Mode::PRIVATE_FILE)?;
        Ok(Some(self.path.clone()))
    }
}

/// `local.toml`'s text, or `None` when there is none.
fn read_local(path: &Path) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::ReadLocal {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// `local.toml`'s text as a document to edit; [`local::empty`] when there is
/// none.
fn parse_local(path: &Path, text: Option<&str>) -> Result<DocumentMut, Error> {
    match text {
        Some(text) => text.parse::<DocumentMut>().map_err(|e| Error::Local {
            path: path.to_path_buf(),
            why: e.to_string(),
        }),
        None => Ok(local::empty()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::plan::tests::{env, seed};
    use crate::testing::{GuardedHome, guarded_home};

    /// Answers from a script, recording what was asked.
    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) answers: Vec<&'static str>,
        pub(crate) asked: Vec<(String, Option<String>)>,
        pub(crate) pick: Vec<&'static str>,
        pub(crate) offered: Vec<Vec<String>>,
    }

    impl Ask for Script {
        fn value(&mut self, decl: &ValueDecl, problem: Option<&str>) -> Result<String, Error> {
            self.asked
                .push((decl.name.clone(), problem.map(str::to_string)));
            assert!(
                !self.answers.is_empty(),
                "asked for {} unscripted",
                decl.name
            );
            Ok(self.answers.remove(0).to_string())
        }

        fn adopt(&mut self, offered: &[Portable]) -> Result<Vec<Portable>, Error> {
            self.offered
                .push(offered.iter().map(|t| t.as_str().to_string()).collect());
            Ok(offered
                .iter()
                .filter(|t| self.pick.contains(&t.as_str()))
                .cloned()
                .collect())
        }
    }

    /// An [`Ask`] that must never be asked anything.
    pub(crate) struct Silent;

    impl Ask for Silent {
        fn value(&mut self, decl: &ValueDecl, _: Option<&str>) -> Result<String, Error> {
            panic!("asked for {}", decl.name)
        }

        fn adopt(&mut self, offered: &[Portable]) -> Result<Vec<Portable>, Error> {
            panic!("offered {offered:?}")
        }
    }

    const VALUES: &str = "[[value]]\nname = \"root\"\ndescription = \"Scratch root\"\n\
                          kind = \"path\"\nrequired = true\n\n\
                          [[value]]\nname = \"cache\"\nkind = \"path\"\nrequired = true\n\
                          default = \"{{root}}/cache\"\n\n\
                          [[value]]\nname = \"email\"\nkind = \"email\"\nrequired = true\n\n\
                          [[value]]\nname = \"note\"\nkind = \"string\"\n";

    fn local(home: &GuardedHome) -> PathBuf {
        home.child(".local/state/bx/local.toml")
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    #[test]
    fn a_missing_repo_is_created_with_the_fixed_header_and_an_existing_one_is_left_alone() {
        let home = guarded_home();
        let prepared = prepare(&env(home.path()), &[], false, &mut Silent).expect("init");

        let repo = home.child(".config/bx");
        assert_eq!(prepared.created.as_deref(), Some(repo.as_path()));
        assert_eq!(
            std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml"),
            HEADER
        );
        assert!(prepared.saved.is_none(), "nothing was answered");
        config::parse_str(HEADER, Path::new("bx.toml"), home.path()).expect("the header loads");

        std::fs::write(repo.join("bx.toml"), "# mine\n").expect("edit");
        let again = prepare(&env(home.path()), &[], false, &mut Silent).expect("init");
        assert!(again.created.is_none());
        assert_eq!(
            std::fs::read_to_string(repo.join("bx.toml")).expect("bx.toml"),
            "# mine\n"
        );

        let bare = guarded_home();
        std::fs::create_dir_all(bare.child(".config/bx")).expect("an empty repo");
        let prepared = prepare(&env(bare.path()), &[], false, &mut Silent).expect("init");
        assert!(prepared.created.is_none());
        assert!(
            !bare.child(".config/bx/bx.toml").exists(),
            "an existing repo is not written"
        );
    }

    #[test]
    fn a_repo_path_that_cannot_be_examined_is_an_error() {
        let home = guarded_home();
        home.write(".config", "not a directory");
        let error = create_repo(&home.child(".config/bx")).expect_err("ENOTDIR");
        assert!(matches!(error, Error::CreateRepo { .. }), "{error:?}");
    }

    #[test]
    fn unset_values_are_asked_in_declaration_order_and_later_ones_see_earlier_answers() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        let mut script = Script {
            answers: vec!["relative", "~/scratch", "not-an-email", "a@b.invalid"],
            ..Script::default()
        };

        let prepared = prepare(&env(home.path()), &[], true, &mut script).expect("init");

        let asked: Vec<&str> = script.asked.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            asked,
            ["root", "root", "email", "email"],
            "cache derives from root, and note is optional: neither is asked"
        );
        assert!(script.asked[0].1.is_none());
        assert!(
            script.asked[1]
                .1
                .as_deref()
                .is_some_and(|p| p.contains("`path`")),
            "{:?}",
            script.asked[1]
        );
        assert!(
            script.asked[3]
                .1
                .as_deref()
                .is_some_and(|p| p.contains("`email`"))
        );
        assert_eq!(prepared.saved.as_deref(), Some(local(&home).as_path()));
        let written = std::fs::read_to_string(local(&home)).expect("local.toml");
        assert!(written.starts_with("# This account's answers"), "{written}");
        assert!(
            written.ends_with("[values]\nroot = \"~/scratch\"\nemail = \"a@b.invalid\"\n"),
            "{written}"
        );
        assert_eq!(mode_of(&local(&home)), 0o600);
        assert!(
            !std::fs::read_to_string(home.child(".config/bx/bx.toml"))
                .expect("bx.toml")
                .contains("scratch"),
            "no answer reaches the repo"
        );
    }

    #[test]
    fn an_answer_may_reference_an_earlier_value() {
        let home = guarded_home();
        seed(
            home.path(),
            "[[value]]\nname = \"a\"\nkind = \"path\"\nrequired = true\n\
             [[value]]\nname = \"b\"\nkind = \"path\"\nrequired = true\n",
        );
        let mut script = Script {
            answers: vec!["~/a", "{{a}}/b"],
            ..Script::default()
        };
        prepare(&env(home.path()), &[], true, &mut script).expect("init");
        assert_eq!(script.asked.len(), 2, "{:?}", script.asked);
        assert!(
            std::fs::read_to_string(local(&home))
                .expect("local.toml")
                .ends_with("b = \"{{a}}/b\"\n"),
            "the answer as given, not its expansion"
        );
    }

    #[test]
    fn set_answers_without_asking_in_declaration_order_and_keeps_the_accounts_comments() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        home.write(
            ".local/state/bx/local.toml",
            "# mine\n[values]\nnote = \"kept\"  # why\n",
        );

        let prepared = prepare(
            &env(home.path()),
            &[
                "email=a@b.invalid".to_string(),
                "root=~/first".to_string(),
                "root=~/scratch".to_string(),
                "cache={{root}}/c".to_string(),
            ],
            false,
            &mut Silent,
        )
        .expect("init");

        assert!(prepared.saved.is_some());
        assert_eq!(
            std::fs::read_to_string(local(&home)).expect("local.toml"),
            "# mine\n[values]\nnote = \"kept\"  # why\nroot = \"~/scratch\"\n\
             cache = \"{{root}}/c\"\nemail = \"a@b.invalid\"\n"
        );
        assert_eq!(mode_of(&local(&home)), 0o600, "written at 0600");
    }

    /// Answers `root` and `email`, and edits `local.toml` while asking, as a
    /// person in another terminal, or another `bx init`, would.
    struct EditsWhileAsking {
        local: PathBuf,
    }

    impl Ask for EditsWhileAsking {
        fn value(&mut self, decl: &ValueDecl, _: Option<&str>) -> Result<String, Error> {
            std::fs::write(
                &self.local,
                "# theirs\n[values]\nnote = \"theirs\"\nemail = \"old@b.invalid\"\n",
            )
            .expect("edit local.toml");
            Ok(match decl.name.as_str() {
                "root" => "~/s",
                _ => "a@b.invalid",
            }
            .to_string())
        }

        fn adopt(&mut self, offered: &[Portable]) -> Result<Vec<Portable>, Error> {
            panic!("offered {offered:?}")
        }
    }

    #[test]
    fn an_edit_to_local_toml_during_the_prompts_survives_the_save() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        home.write(".local/state/bx/local.toml", "# mine\n");
        let mut ask = EditsWhileAsking {
            local: local(&home),
        };

        let prepared = prepare(&env(home.path()), &[], true, &mut ask).expect("init");

        assert_eq!(prepared.saved.as_deref(), Some(local(&home).as_path()));
        assert_eq!(
            std::fs::read_to_string(local(&home)).expect("local.toml"),
            "# theirs\n[values]\nnote = \"theirs\"\nemail = \"a@b.invalid\"\nroot = \"~/s\"\n",
            "the edit is kept, and only the names answered here change"
        );
        assert_eq!(mode_of(&local(&home)), 0o600);
    }

    #[test]
    fn a_save_that_finds_its_answers_already_written_writes_nothing() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        let state = StateDir::resolve(home.path());
        let mut answers =
            Answers::load(&home.child(".config/bx"), &state, home.path()).expect("load");
        answers.give("root", "~/s");
        home.write(".local/state/bx/local.toml", "[values]\nroot = \"~/s\"\n");
        std::fs::set_permissions(local(&home), std::fs::Permissions::from_mode(0o644))
            .expect("chmod");

        assert!(answers.save(&state).expect("save").is_none());
        assert_eq!(mode_of(&local(&home)), 0o644, "not rewritten");
    }

    #[test]
    fn a_state_directory_inside_the_repo_is_refused_before_anything_is_asked_or_written() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        let inside = Env {
            xdg_state_home: Some(home.child(".config/bx/state").into_os_string()),
            ..env(home.path())
        };

        let error =
            prepare(&inside, &["root=~/s".to_string()], true, &mut Silent).expect_err("refused");

        assert!(
            matches!(error, Error::Config(config::Error::LocalInRepo { .. })),
            "{error:?}"
        );
        assert!(!home.child(".config/bx/state").exists(), "nothing written");
    }

    #[test]
    fn a_set_the_loader_refuses_writes_nothing() {
        for (set, bad) in [
            ("root", "has no `=`"),
            ("root=relative", "`path`"),
            ("nobody=x", "no layer declares the value `nobody`"),
        ] {
            let home = guarded_home();
            seed(home.path(), VALUES);
            let error = prepare(&env(home.path()), &[set.to_string()], false, &mut Silent)
                .expect_err("refused");
            assert!(error.to_string().contains(bad), "{set}: {error}");
            assert!(!home.child(".local/state").exists(), "{set}: wrote");
        }

        let fresh = guarded_home();
        prepare(&env(fresh.path()), &["x=1".to_string()], false, &mut Silent)
            .expect_err("nothing is declared in a repo that does not exist");
        assert!(
            !fresh.child(".config").exists(),
            "the repo was created anyway"
        );
    }

    #[test]
    fn without_a_terminal_an_unset_value_names_every_one_and_its_flag_and_writes_nothing() {
        let home = guarded_home();
        seed(home.path(), VALUES);

        let error = prepare(&env(home.path()), &[], false, &mut Silent).expect_err("unset");

        let shown = error.to_string();
        assert!(
            matches!(error, Error::Unset(ref names) if names.len() == 2),
            "{shown}"
        );
        assert!(
            shown.contains(
                "  bx init --set root=VALUE  (Scratch root)\n  bx init --set email=VALUE"
            ),
            "{shown}"
        );
        assert!(shown.contains("nothing was written"), "{shown}");
        assert!(!home.child(".local/state").exists());
    }

    #[test]
    fn a_second_run_asks_nothing_and_writes_nothing() {
        let home = guarded_home();
        seed(home.path(), VALUES);
        let sets = ["root=~/s".to_string(), "email=a@b.invalid".to_string()];
        prepare(&env(home.path()), &sets, false, &mut Silent).expect("first");
        let before = std::fs::read(local(&home)).expect("local.toml");

        let again = prepare(&env(home.path()), &[], true, &mut Script::default()).expect("second");

        assert!(again.created.is_none() && again.saved.is_none() && again.adopted.is_empty());
        assert_eq!(std::fs::read(local(&home)).expect("local.toml"), before);
    }

    #[test]
    fn discovery_offers_unmanaged_config_and_adopts_only_what_is_picked() {
        let home = guarded_home();
        seed(home.path(), "");
        home.write(".zshrc", "z\n");
        home.write(".gitconfig", "g\n");
        home.write(".bash_history", "secret typed at a prompt\n");
        home.write(".netrc", "machine x\n");
        home.write(".cache/x", "x\n");
        home.write(".config/nvim/init.lua", "n\n");
        home.write(".config/starship.toml", "s\n");
        home.write(".config/age/keys.txt", "k\n");
        std::os::unix::fs::symlink(home.child(".zshrc"), home.child(".zshrc.link"))
            .expect("a link");
        std::os::unix::fs::symlink(home.child(".config/nvim"), home.child(".config/vim"))
            .expect("a link");

        let mut script = Script {
            pick: vec!["~/.config/nvim", "~/.zshrc"],
            ..Script::default()
        };
        let prepared = prepare(&env(home.path()), &[], true, &mut script).expect("init");

        assert_eq!(
            script.offered,
            [[
                "~/.config/nvim",
                "~/.config/starship.toml",
                "~/.gitconfig",
                "~/.zshrc"
            ]]
        );
        let adopted: Vec<&str> = prepared
            .adopted
            .iter()
            .map(|row| row.target().as_str())
            .collect();
        assert_eq!(
            adopted,
            ["~/.config/nvim/init.lua", "~/.zshrc"],
            "in the order offered"
        );
        let layer = std::fs::read_to_string(home.child(".config/bx/bx.toml")).expect("bx.toml");
        assert!(
            layer.contains("path = \"~/.zshrc\"\nfile = \"files/.zshrc\""),
            "{layer}"
        );

        let mut again = Script::default();
        prepare(&env(home.path()), &[], true, &mut again).expect("init");
        assert_eq!(
            again.offered,
            [["~/.config/starship.toml", "~/.gitconfig"]],
            "what was adopted is managed now, and is not offered again"
        );
    }

    #[test]
    fn a_non_interactive_run_offers_and_adopts_nothing() {
        let home = guarded_home();
        seed(home.path(), "");
        home.write(".zshrc", "z\n");
        let prepared = prepare(&env(home.path()), &[], false, &mut Silent).expect("init");
        assert!(prepared.adopted.is_empty());
    }

    #[test]
    fn nothing_to_offer_asks_nothing() {
        let home = guarded_home();
        seed(home.path(), "");
        prepare(&env(home.path()), &[], true, &mut Silent).expect("init");
    }

    #[test]
    fn a_config_home_outside_the_home_is_not_looked_in() {
        let home = guarded_home();
        let elsewhere = guarded_home();
        elsewhere.write("tool.toml", "t\n");
        seed(home.path(), "");
        let ctx = adopt::Context::load(&env(home.path())).expect("context");
        assert!(
            adopt::discover(&ctx, elsewhere.path())
                .expect("discover")
                .is_empty()
        );

        home.write("xdg/tool.toml", "t\n");
        assert_eq!(
            adopt::discover(&ctx, &home.child("xdg")).expect("discover"),
            [Portable::parse_in("~/xdg/tool.toml", home.path()).expect("portable")],
            "a config home inside the home is looked in, wherever it is"
        );
        assert!(
            adopt::discover(&ctx, &home.child("absent"))
                .expect("an absent config home is nothing to offer")
                .is_empty()
        );
    }

    #[test]
    fn a_local_toml_that_does_not_parse_is_an_error() {
        let home = guarded_home();
        let state = StateDir::resolve(home.path());
        home.write(".local/state/bx/local.toml", "[values\n");
        let error = Answers::load(&home.child("absent"), &state, home.path())
            .err()
            .expect("unparseable");
        assert!(matches!(error, Error::Local { .. }), "{error:?}");

        std::fs::remove_file(local(&home)).expect("rm");
        std::fs::create_dir(local(&home)).expect("a directory where the file goes");
        let error = Answers::load(&home.child("absent"), &state, home.path())
            .err()
            .expect("unreadable");
        assert!(matches!(error, Error::ReadLocal { .. }), "{error:?}");
    }

    /// Set on the child that actually calls [`Terminal`].
    const TERMINAL_CHILD: &str = "BX_TEST_INIT_TERMINAL_CHILD";

    #[test]
    #[ignore = "spawned by the test below; it must run with a stdin that is not a terminal"]
    fn terminal_child() {
        if std::env::var_os(TERMINAL_CHILD).is_none() {
            return;
        }
        let decl = config::parse_str(
            "[[value]]\nname = \"a\"\nkind = \"string\"\n",
            Path::new("bx.toml"),
            Path::new("/"),
        )
        .expect("a declaration")
        .values
        .remove(0);
        for problem in [None, Some("no")] {
            assert!(matches!(
                Terminal.value(&decl, problem),
                Err(Error::Prompt(inquire::InquireError::NotTTY))
            ));
        }
        let offered = [Portable::parse_in("~/.a", Path::new("/h")).expect("portable")];
        assert!(matches!(
            Terminal.adopt(&offered),
            Err(Error::Prompt(inquire::InquireError::NotTTY))
        ));
    }

    #[test]
    fn the_terminal_prompts_without_a_terminal_are_errors_and_never_answers() {
        // As `command::tests::confirm_without_a_terminal_is_a_prompt_error_and_never_an_answer`:
        // in a child whose stdin is certainly not a terminal, so this never
        // hangs on a developer's machine.
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "init::tests::terminal_child",
            ])
            .env(TERMINAL_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn the terminal child");
        let ran = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{ran}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            ran.contains("1 passed") && ran.contains("0 failed"),
            "{ran}"
        );
    }
}
