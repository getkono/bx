use super::*;
use tempfile::TempDir;

/// The paths `code` reaches `crate::shell` by, each with its line: every
/// `shell::` that does not continue a longer name, so `crate::shell::`,
/// `super::super::shell::` and a grouped `{shell::…}` are found while
/// `shells::` and `shell_options::` are not.
fn shell_paths(code: &str) -> Vec<String> {
    code.lines()
        .filter(|line| {
            line.match_indices("shell::").any(|(at, _)| {
                !line[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
        })
        .map(|line| line.trim().to_string())
        .collect()
}

#[test]
fn the_scan_finds_every_spelling_of_a_path_into_shell_and_nothing_else() {
    let code = "use crate::shell::alias;\n\
                    use super::super::shell::Phase;\n\
                    use crate::{config, shell::bash};\n\
                    let x = shell::quote(\"a\");\n\
                    use super::shells::Shell;\n\
                    use super::shell_options::ShellOptions;\n\
                    let y = myshell::z;\n";
    assert_eq!(
        shell_paths(code),
        [
            "use crate::shell::alias;",
            "use super::super::shell::Phase;",
            "use crate::{config, shell::bash};",
            "let x = shell::quote(\"a\");",
        ]
    );
}

#[test]
fn no_config_module_names_anything_in_shell() {
    // A structural test, because the property is a dependency direction:
    // `shell` reads the values `config` parses and resolves, and `config`
    // names nothing of `shell`'s, so a renderer can change without the
    // configuration model knowing. Every file of the module is read off
    // the directory at run time, so a file added to it is scanned without
    // anyone listing it. The test module is left out — its tests may run
    // what they parse through a shell's renderer — and so are whole-line
    // comments, whose links say where a value is rendered without
    // depending on it. Only the module: a `#[cfg(test)]` item above it
    // is code the scan still reads, like everything around it.
    for (path, source) in crate::testing::module_sources("config") {
        let code: String = crate::testing::shipped_source(&path, &source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let found = shell_paths(&code);
        assert!(
            found.is_empty(),
            "{} names `crate::shell` outside its tests: {found:?}",
            path.display()
        );
    }
}

/// A config repo with the given files, each `(relative path, contents)`.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("a tempdir");
    for (rel, contents) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(&path, contents).expect("write");
    }
    dir
}

/// Just the filenames of the discovered layers, in order.
fn names(repo: &Path) -> Vec<String> {
    layer_files(repo)
        .expect("discovery")
        .iter()
        .map(|p| {
            p.file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

use crate::testing::example_home as home;

fn parse(text: &str) -> Result<Config, Error> {
    parse_str(text, Path::new("bx.toml"), home())
}

/// A `[[target]]` entry built in memory, with no spans anywhere.
///
/// Entry A3 parses a single entry out of a layer it is merging without
/// going through a whole document, which is the case these tests cover.
fn in_memory_target(extra: &[(&str, toml_edit::Item)]) -> Table {
    let mut table = Table::new();
    table.insert("path", toml_edit::value("~/.gitconfig"));
    table.insert("file", toml_edit::value("files/gitconfig"));
    for (key, item) in extra {
        table.insert(key, item.clone());
    }
    table
}

#[test]
fn an_entry_with_no_span_degrades_to_an_unknown_origin() {
    // `Ctx::new` asks `toml_edit` for the entry header's span, and a table
    // nothing parsed has none. Line 0 says "this file, position unknown"
    // rather than pretending it is line 1 -- and rather than panicking on
    // an `expect`, which is what a caller like `merge` would hit.
    let file = Path::new("bx.toml");
    let target = target::parse_target(&in_memory_target(&[]), file, "", home()).unwrap();

    assert_eq!(target.origin, Origin::unknown(file));
    assert_eq!(target.origin.to_string(), "bx.toml:0");
}

#[test]
fn a_key_with_no_span_falls_back_to_its_entry() {
    // `Ctx::key_origin` positions an error at the offending key. With no
    // span it falls back to the entry's own origin, which for an in-memory
    // table is itself unknown.
    let file = Path::new("bx.toml");
    let table = in_memory_target(&[("nope", toml_edit::value(1))]);
    let error = target::parse_target(&table, file, "", home()).expect_err("unknown key");

    assert!(error.to_string().starts_with("bx.toml:0:"), "{error}");
    assert!(error.to_string().contains("`nope`"), "{error}");
}

#[test]
fn a_section_key_with_no_span_degrades_to_an_unknown_origin() {
    // The third fallback. Unreachable from `parse_str`, because every key
    // in a parsed document has a span -- including the implicit one in
    // `[nope.deep]` -- so it is exercised where it lives.
    let mut root = Table::new();
    root.insert("target", toml_edit::value(1));

    assert_eq!(
        section_origin(&root, "target", Path::new("bx.toml"), ""),
        Origin::unknown(Path::new("bx.toml"))
    );
}

#[test]
fn an_unreadable_modules_directory_names_the_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = repo(&[("bx.toml", ""), ("modules/a.toml", "")]);
    let modules = dir.path().join(MODULES_DIR);
    std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

    // A process that can read a 0000 directory -- root, or one holding
    // CAP_DAC_READ_SEARCH -- cannot construct this case at all. Every job in
    // `.github/workflows/ci.yml` is a plain `runs-on: ubuntu-latest` with no
    // `container:` and no `user:`, and `mise run test` runs as the invoking
    // user, so no gate takes the branch below. Rather than a silent skip
    // nothing exercises, such a run fails unless the skip is asked for by
    // name, and the opted-in skip is announced through the stderr handle.
    let constructible = std::fs::read_dir(&modules).is_err();
    let result = layer_files(dir.path());
    std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o755))
        .expect("restore, so the tempdir can be removed");

    if !constructible {
        crate::testing::skip_unconstructible(
            "this process can read a 0000 directory, so the io error cannot be \
                 constructed here",
        );
        return;
    }
    match result {
        Err(Error::Io { path, .. }) => assert_eq!(path, modules),
        other => panic!(
            "expected an io error naming {}, got {other:?}",
            modules.display()
        ),
    }
}

fn message(text: &str) -> String {
    parse(text)
        .expect_err("should have been rejected")
        .to_string()
}

// --- discovery and ordering ------------------------------------------

#[test]
fn the_global_layer_comes_before_every_module() {
    let dir = repo(&[
        ("modules/aaa.toml", ""),
        ("bx.toml", ""),
        ("modules/bbb.toml", ""),
    ]);

    assert_eq!(names(dir.path()), ["bx.toml", "aaa.toml", "bbb.toml"]);
}

#[test]
fn modules_are_ordered_by_raw_filename_bytes() {
    // Byte order, and nothing else: this expectation fails under
    // case-insensitive ordering, under natural-numeric ordering, and under
    // directory-iteration order alike.
    let dir = repo(&[
        ("modules/a.toml", ""),
        ("modules/_.toml", ""),
        ("modules/Z.toml", ""),
        ("modules/2-b.toml", ""),
        ("modules/10-a.toml", ""),
    ]);

    assert_eq!(
        names(dir.path()),
        ["10-a.toml", "2-b.toml", "Z.toml", "_.toml", "a.toml"]
    );
}

#[test]
fn module_order_does_not_depend_on_creation_order() {
    let forward: Vec<(String, String)> = (0..20)
        .map(|i| (format!("modules/{i:02}.toml"), String::new()))
        .collect();
    let reversed: Vec<(&str, &str)> = forward
        .iter()
        .rev()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();

    let dir = repo(&reversed);
    let expected: Vec<String> = (0..20).map(|i| format!("{i:02}.toml")).collect();

    assert_eq!(names(dir.path()), expected);
}

#[test]
fn a_missing_modules_directory_is_not_an_error() {
    let dir = repo(&[("bx.toml", "")]);
    assert_eq!(names(dir.path()), ["bx.toml"]);
}

#[test]
fn a_missing_bx_toml_is_not_an_error() {
    let dir = repo(&[("modules/one.toml", "")]);
    assert_eq!(names(dir.path()), ["one.toml"]);
}

#[test]
fn an_empty_repo_has_no_layers() {
    let dir = repo(&[]);
    assert!(layer_files(dir.path()).unwrap().is_empty());
}

#[test]
fn a_missing_repo_is_an_error() {
    let dir = repo(&[]);
    let missing = dir.path().join("nowhere");

    let error = layer_files(&missing).expect_err("should be an error");
    assert!(matches!(error, Error::RepoMissing(ref p) if *p == missing));
    assert!(error.to_string().contains("no bx config repo at"));
}

/// A repo root beneath a regular file is missing, exactly as one at a file is.
///
/// `lstat` on `dotconfig/bx` with `dotconfig` a regular file says `ENOTDIR`,
/// not `ENOENT`, and that came back as an io error while a regular file at
/// the root itself was `RepoMissing`: one fault, two answers.
///
/// Guards the other side of R4-6: a root that is a symlink to such a place
/// is still an error. The follow with `stat` fails with `ENOTDIR` as well,
/// never `ENOENT`, so what comes back is a plain io error naming the link,
/// and not the dangling one. The kind is asserted so this doc cannot drift
/// from it.
#[test]
fn a_repo_beneath_a_regular_file_is_missing() {
    let dir = repo(&[("dotconfig", "")]);
    let beneath = dir.path().join("dotconfig/bx");

    let error = layer_files(&beneath).expect_err("should be an error");
    assert!(
        matches!(error, Error::RepoMissing(ref p) if *p == beneath),
        "{error:?}"
    );

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path().join("dotconfig/x"), &link).expect("symlink");
    match layer_files(&link) {
        Err(Error::Io { path, source }) => {
            assert_eq!(path, link);
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotADirectory,
                "the follow fails at `dotconfig`, not at a missing target: {source}"
            );
            assert!(!source.to_string().contains("dangling"), "{source}");
        }
        other => panic!("expected an io error naming the link, got {other:?}"),
    }
}

#[test]
fn non_toml_files_in_modules_are_ignored() {
    let dir = repo(&[
        ("modules/keep.toml", ""),
        ("modules/README.md", ""),
        ("modules/notes.toml.bak", ""),
        ("modules/toml", ""),
    ]);

    assert_eq!(names(dir.path()), ["keep.toml"]);
}

#[test]
fn a_dotfile_in_modules_is_ignored() {
    let dir = repo(&[("modules/keep.toml", ""), ("modules/.hidden.toml", "")]);
    assert_eq!(names(dir.path()), ["keep.toml"]);
}

#[test]
fn a_directory_named_like_a_module_is_ignored() {
    let dir = repo(&[("modules/keep.toml", "")]);
    std::fs::create_dir(dir.path().join("modules/looks-like.toml")).expect("mkdir");

    assert_eq!(names(dir.path()), ["keep.toml"]);
}

#[test]
fn a_nested_directory_is_not_searched() {
    let dir = repo(&[("modules/keep.toml", ""), ("modules/sub/deep.toml", "")]);
    assert_eq!(names(dir.path()), ["keep.toml"]);
}

/// The io error `layer_files` returned for `repo`, which must name `expected`.
fn io_error_naming(repo: &Path, expected: &Path) -> std::io::Error {
    match layer_files(repo) {
        Err(Error::Io { path, source }) => {
            assert_eq!(path, expected);
            source
        }
        other => panic!(
            "expected an io error naming {}, got {other:?}",
            expected.display()
        ),
    }
}

/// A module that is a dangling symlink is an error, not an absent layer.
///
/// `is_file()` answers `false` for every failed `stat`, so a dangling
/// `modules/20-off.toml` -- the module that says `enabled = false` -- was
/// dropped and `Ok([bx.toml, 10-a.toml])` came back. The target it disables
/// then applies, and nothing says why.
#[test]
fn a_dangling_module_symlink_is_an_error_naming_it() {
    let dir = repo(&[("bx.toml", ""), ("modules/10-a.toml", "")]);
    let dangling = dir.path().join("modules/20-off.toml");
    std::os::unix::fs::symlink(dir.path().join("nowhere.toml"), &dangling).expect("symlink");

    io_error_naming(dir.path(), &dangling);
    let message = layer_files(dir.path()).expect_err("dangling").to_string();
    assert!(message.contains("20-off.toml"), "{message}");
    assert!(message.contains("dangling symlink"), "{message}");
}

/// A symlink loop is reported as the loop, not as a dangling link.
///
/// `ELOOP` comes from following the link, after `lstat` found it. Reading
/// every failure there as "dangling" would name the wrong fault, and nothing
/// else distinguishes the two branches.
#[test]
fn a_module_symlink_loop_is_an_error_naming_the_loop() {
    let dir = repo(&[("bx.toml", "")]);
    std::fs::create_dir(dir.path().join(MODULES_DIR)).expect("mkdir");
    let looped = dir.path().join("modules/loop.toml");
    std::os::unix::fs::symlink(&looped, &looped).expect("a symlink to itself");

    let source = io_error_naming(dir.path(), &looped);
    assert_ne!(source.kind(), std::io::ErrorKind::NotFound, "{source}");
    assert!(!source.to_string().contains("dangling"), "{source}");
}

/// A dangling `bx.toml` is an error, not a repo without a global layer.
///
/// Under `is_file()` this returned `Ok([10-a.toml])`: every module, and
/// silently not the layer they are all meant to sit on top of.
#[test]
fn a_dangling_bx_toml_is_an_error_naming_it() {
    let dir = repo(&[("modules/10-a.toml", "")]);
    let global = dir.path().join(GLOBAL_LAYER);
    std::os::unix::fs::symlink(dir.path().join("nowhere.toml"), &global).expect("symlink");

    io_error_naming(dir.path(), &global);
}

/// A dangling `modules` is an error, not a repo without modules.
#[test]
fn a_dangling_modules_directory_is_an_error_naming_it() {
    let dir = repo(&[("bx.toml", "")]);
    let modules = dir.path().join(MODULES_DIR);
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &modules).expect("symlink");

    io_error_naming(dir.path(), &modules);
}

/// A `modules/` that can be listed but not searched is an error.
///
/// At mode 0644 `read_dir` succeeds, because listing needs only `r`, and
/// every `stat` inside fails with `EACCES`, because that needs `x`. Under
/// `is_file()` every module was dropped and `Ok([bx.toml])` came back.
#[test]
fn a_modules_directory_that_cannot_be_searched_names_the_entry() {
    use std::os::unix::fs::PermissionsExt;

    let dir = repo(&[("bx.toml", ""), ("modules/10-a.toml", "")]);
    let modules = dir.path().join(MODULES_DIR);
    let module = modules.join("10-a.toml");
    std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    // A process that can stat inside an unsearchable directory -- root, or
    // one holding CAP_DAC_READ_SEARCH -- cannot construct this case. No CI
    // job runs that way, so a silent skip would be a branch nothing
    // exercises: such a run fails unless the skip is asked for by name.
    let constructible = std::fs::metadata(&module).is_err();
    let result = layer_files(dir.path());
    std::fs::set_permissions(&modules, std::fs::Permissions::from_mode(0o755))
        .expect("restore, so the tempdir can be removed");

    if !constructible {
        crate::testing::skip_unconstructible(
            "this process can stat inside a 0644 directory, so EACCES cannot be \
                 constructed here",
        );
        return;
    }
    match result {
        Err(Error::Io { path, source }) => {
            assert_eq!(path, module);
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!(
            "expected an io error naming {}, got {other:?}",
            module.display()
        ),
    }
}

/// A name that is not a layer is filtered out before it is ever stat'ed.
///
/// Otherwise a dangling `README.md`, or the `.#keep.toml` lock Emacs leaves
/// as a dangling symlink, would become an error about a file bx never meant
/// to read.
#[test]
fn a_dangling_name_that_is_not_a_layer_is_never_examined() {
    let dir = repo(&[("modules/keep.toml", "")]);
    let modules = dir.path().join(MODULES_DIR);
    for name in [".#keep.toml", "README.md", "notes.toml.bak"] {
        std::os::unix::fs::symlink(dir.path().join("nowhere"), modules.join(name))
            .expect("symlink");
    }

    assert_eq!(names(dir.path()), ["keep.toml"]);
}

/// A symlink to a regular file is a layer, as it was under `is_file()`.
#[test]
fn a_module_symlinked_to_a_regular_file_is_a_layer() {
    let dir = repo(&[("elsewhere/real.toml", ""), ("bx.toml", "")]);
    std::fs::create_dir(dir.path().join(MODULES_DIR)).expect("mkdir");
    std::os::unix::fs::symlink(
        dir.path().join("elsewhere/real.toml"),
        dir.path().join("modules/linked.toml"),
    )
    .expect("symlink");

    assert_eq!(names(dir.path()), ["bx.toml", "linked.toml"]);
}

/// A `bx.toml` or `modules` that exists as the wrong kind of file is a
/// clean "not a layer", not an error.
#[test]
fn a_global_layer_or_modules_of_the_wrong_kind_is_skipped() {
    let dir = repo(&[("modules", "a regular file, not a directory")]);
    std::fs::create_dir(dir.path().join(GLOBAL_LAYER)).expect("mkdir");

    assert!(layer_files(dir.path()).unwrap().is_empty());
}

/// A repo that is a regular file is missing; a dangling one is an error.
#[test]
fn a_repo_that_is_a_file_is_missing_and_a_dangling_one_is_an_error() {
    let dir = repo(&[("file", "")]);
    let file = dir.path().join("file");
    assert!(matches!(layer_files(&file), Err(Error::RepoMissing(ref p)) if *p == file));

    let dangling = dir.path().join("repo");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).expect("symlink");
    io_error_naming(&dangling, &dangling);
}

// --- loading ----------------------------------------------------------

#[test]
fn layers_are_returned_unmerged() {
    // The same target path in two layers stays two layers. Replacing one
    // with the other is A3's merge, and it needs both to do it.
    let dir = repo(&[
        (
            "bx.toml",
            "[[target]]\npath = \"~/.gitconfig\"\nfile = \"files/gitconfig\"\n",
        ),
        (
            "modules/git.toml",
            "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"overridden\"\n",
        ),
    ]);
    let layers = load_layers(dir.path(), home()).expect("loading");

    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].file, dir.path().join("bx.toml"));
    assert_eq!(layers[1].file, dir.path().join("modules/git.toml"));
    assert_eq!(layers[0].config.targets.len(), 1);
    assert_eq!(layers[1].config.targets.len(), 1);
    assert_ne!(layers[0].config.targets[0], layers[1].config.targets[0]);
}

#[test]
fn every_entry_names_the_file_it_came_from() {
    let dir = repo(&[(
        "modules/git.toml",
        "# a module\n\n[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n",
    )]);
    let layers = load_layers(dir.path(), home()).expect("loading");
    let origin = &layers[0].config.targets[0].origin;

    assert_eq!(origin.file, dir.path().join("modules/git.toml"));
    assert_eq!(origin.line, 3);
}

#[test]
fn a_layer_that_cannot_be_read_names_the_file() {
    let dir = repo(&[]);
    let missing = dir.path().join("bx.toml");

    let error = load_layer(&missing, dir.path(), home()).expect_err("should be an error");
    assert!(matches!(error, Error::Io { .. }));
    assert!(error.to_string().contains("bx.toml"));
}

#[test]
fn a_target_under_a_platform_directory_loads_only_when_kept_to_its_os() {
    let module = |top: &str, own: &str, path: &str| {
        parse_str(
            &format!("{top}[[target]]\npath = \"{path}\"\ncontent = \"x\"\n{own}"),
            Path::new("modules/m.toml"),
            home(),
        )
    };
    for path in [
        "~/.config/systemd/user/a.service",
        "~/.config/environment.d/60-a.conf",
        "~/.config/systemd/user/{{slice}}.slice",
    ] {
        for (top, own) in [
            ("", ""),
            ("", "when = \"os:macos\"\n"),
            ("when = \"os:macos\"\n", ""),
            ("", "when = [\"has:systemctl\", \"host:box\"]\n"),
        ] {
            let error = module(top, own, path).expect_err("refused");
            assert!(
                error.to_string().contains("which only linux reads"),
                "{path} {top:?} {own:?}: {error}"
            );
        }
        for (top, own) in [
            ("", "when = \"os:linux\"\n"),
            ("", "when = [\"has:systemctl\", \"os:linux\"]\n"),
            ("when = \"os:linux\"\n", ""),
            (
                "when = [\"os:linux\", \"host:box\"]\n",
                "when = \"has:x\"\n",
            ),
        ] {
            module(top, own, path).unwrap_or_else(|e| panic!("{path} {top:?} {own:?}: {e}"));
        }
    }
    let error =
        module("", "when = \"os:linux\"\n", "~/Library/Preferences/a.plist").expect_err("refused");
    assert!(
        error.to_string().contains("which only macos reads"),
        "{error}"
    );
    module("when = \"os:macos\"\n", "", "~/Library").expect("kept to macOS by its module");
    // The anchor is a directory, not a prefix of a name.
    module("", "", "~/Libraryx").expect("not under ~/Library");
    // `~/library` is `~/Library` on macOS's case-folding volume and a
    // directory of its own elsewhere, so it is refused only ungated.
    for (top, own) in [("", ""), ("", "when = \"host:box\"\n")] {
        let error = module(top, own, "~/library/Fonts/a.ttf").expect_err("refused");
        assert!(
            error
                .to_string()
                .contains("is `~/Library` on macos, whose volumes"),
            "{own:?}: {error}"
        );
    }
    for (top, own) in [
        ("", "when = \"os:macos\"\n"),
        ("", "when = \"os:linux\"\n"),
        ("when = [\"host:box\", \"os:linux\"]\n", ""),
    ] {
        module(top, own, "~/LIBRARY/a").unwrap_or_else(|e| panic!("{top:?} {own:?}: {e}"));
    }
    // Linux's filesystems tell names apart by case, so its anchors do not
    // fold.
    module("", "", "~/.config/Systemd/user/a.service").expect("not a user unit");
    module("", "", "~/.config/systemd/a.service").expect("not a user unit");

    // A tree rooted under an anchor is judged as written.
    let error = parse_str(
        "[[target]]\npath = \"~/Library/Fonts\"\ntree = \"files/fonts\"\n",
        Path::new("bx.toml"),
        home(),
    )
    .expect_err("refused");
    assert!(
        error.to_string().contains("which only macos reads"),
        "{error}"
    );
}

#[test]
fn a_tree_reaching_a_platform_directory_is_judged_by_the_files_it_expands_to() {
    let tree = "[[target]]\npath = \"~/.config\"\ntree = \"files/config\"\n";
    let dir = repo(&[
        ("bx.toml", tree),
        ("files/config/git/config", "x"),
        ("files/config/systemd/user/a.service", "x"),
    ]);
    let error = load_layer(&dir.path().join("bx.toml"), dir.path(), home()).expect_err("refused");
    assert!(
        error
            .to_string()
            .contains("`~/.config/systemd/user/a.service` lies under"),
        "{error}"
    );

    std::fs::write(
        dir.path().join("bx.toml"),
        format!("{tree}when = \"os:linux\"\n"),
    )
    .expect("write");
    let layer = load_layer(&dir.path().join("bx.toml"), dir.path(), home()).expect("kept to Linux");
    assert_eq!(layer.config.targets.len(), 2);
}

// --- parsing ----------------------------------------------------------

#[test]
fn an_empty_layer_is_the_default_config() {
    assert_eq!(parse("").unwrap(), Config::default());
    assert_eq!(parse("# only a comment\n").unwrap(), Config::default());
}

#[test]
fn entries_keep_document_order() {
    let text = "[[target]]\npath = \"~/z\"\nfile = \"z\"\n\n\
                    [[target]]\npath = \"~/a\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"~/m\"\nfile = \"m\"\n";
    let config = parse(text).unwrap();
    let paths: Vec<&str> = config.targets.iter().map(|t| t.path.as_str()).collect();

    assert_eq!(paths, ["~/z", "~/a", "~/m"]);
}

#[test]
fn every_section_lands_in_its_own_field() {
    let text = "[[target]]\npath = \"~/.gitconfig\"\nfile = \"f\"\n\n\
                    [[value]]\nname = \"git_email\"\nkind = \"email\"\nrequired = true\n\n\
                    [values]\ngit_email = \"someone@example.invalid\"\n\n\
                    [[env]]\nname = \"LANG\"\nvalue = \"C.UTF-8\"\nkind = \"environment\"\n";
    let config = parse(text).unwrap();

    assert_eq!(config.targets.len(), 1);
    assert_eq!(config.values.len(), 1);
    assert_eq!(config.value_assignments.len(), 1);
    assert_eq!(config.value_assignments[0].name, "git_email");
    assert_eq!(config.envs.len(), 1);
    assert_eq!(config.envs[0].name, "LANG");
}

#[test]
fn a_duplicate_env_name_in_one_layer_is_rejected() {
    let entry = "[[env]]\nname = \"LANG\"\nvalue = \"C\"\nkind = \"gui\"\n";
    let twice = message(&format!("{entry}{entry}"));
    assert!(twice.contains("duplicate env `LANG`"), "{twice}");
    // And a toggle beside the entry it flips is the same ambiguity.
    let toggled = message(&format!(
        "{entry}[[env]]\nname = \"LANG\"\nenabled = false\n"
    ));
    assert!(toggled.contains("duplicate env `LANG`"), "{toggled}");
}

#[test]
fn a_plugin_section_parses_and_a_duplicate_name_is_rejected() {
    let entry = "[[plugin]]\nname = \"autosuggest\"\nsource = \"~/a.zsh\"\n";
    let config = parse_str(
        &format!("{entry}[[plugin]]\nname = \"other\"\nenabled = false\n"),
        Path::new("/repo/bx.toml"),
        home(),
    )
    .expect("parses");
    assert_eq!(config.plugins.len(), 1);
    assert_eq!(config.plugins[0].name, "autosuggest");
    assert_eq!(config.toggles.len(), 1);
    assert_eq!(config.toggles[0].section, toggle::Section::Plugin);

    let twice = message(&format!("{entry}{entry}"));
    assert!(twice.contains("duplicate plugin `autosuggest`"), "{twice}");
    let toggled = message(&format!(
        "{entry}[[plugin]]\nname = \"autosuggest\"\nenabled = false\n"
    ));
    assert!(
        toggled.contains("duplicate plugin `autosuggest`"),
        "{toggled}"
    );
    // The entry's own parser runs: a malformed source is refused here.
    let bad = message("[[plugin]]\nname = \"a\"\nsource = \"a.zsh\"\n");
    assert!(bad.contains("must open with"), "{bad}");
}

#[test]
fn an_activation_section_parses_and_a_duplicate_name_is_rejected() {
    let entry = "[[activation]]\nname = \"starship\"\ncommand = [\"starship\", \"init\", \"zsh\"]\n\
                     phase = \"completions\"\n";
    let config = parse_str(
        &format!("{entry}[[activation]]\nname = \"mise\"\nenabled = false\n"),
        Path::new("/repo/bx.toml"),
        home(),
    )
    .expect("parses");
    assert_eq!(config.activations.len(), 1);
    assert_eq!(config.activations[0].name, "starship");
    assert_eq!(
        config.activations[0].command,
        ["starship", "init", "zsh"].map(String::from)
    );
    assert_eq!(config.toggles.len(), 1);
    assert_eq!(config.toggles[0].section, toggle::Section::Activation);

    let twice = message(&format!("{entry}{entry}"));
    assert!(twice.contains("duplicate activation `starship`"), "{twice}");
    let toggled = message(&format!(
        "{entry}[[activation]]\nname = \"starship\"\nenabled = false\n"
    ));
    assert!(
        toggled.contains("duplicate activation `starship`"),
        "{toggled}"
    );
    // The entry's own parser runs: an empty command is refused here.
    let bad = message("[[activation]]\nname = \"a\"\ncommand = []\n");
    assert!(bad.contains("`command` is empty"), "{bad}");
}

#[test]
fn an_unknown_section_is_rejected_with_its_line() {
    let text = "[[target]]\npath = \"~/a\"\nfile = \"f\"\n\n[[abbr]]\nname = \"ll\"\n";
    let message = message(text);

    assert!(message.contains("unknown section `abbr`"), "{message}");
    assert!(message.contains("bx.toml:5"), "{message}");
}

#[test]
fn a_section_of_the_wrong_shape_is_rejected() {
    assert!(message("[target]\npath = \"~/a\"\n").contains("a repeated section"));
    assert!(message("[[values]]\nx = \"1\"\n").contains("a table `[values]`"));
}

#[test]
fn a_syntax_error_names_the_file_and_position() {
    let error = parse_str("[[target]\n", Path::new("/repo/bx.toml"), home())
        .expect_err("should be a syntax error");

    assert!(matches!(error, Error::Syntax { .. }));
    let message = error.to_string();
    assert!(message.contains("/repo/bx.toml"), "{message}");
    assert!(message.contains("line 1"), "{message}");
}

#[test]
fn a_duplicate_target_path_in_one_layer_is_rejected() {
    let text = "[[target]]\npath = \"~/.gitconfig\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\nfile = \"b\"\n";
    let message = message(text);

    assert!(
        message.contains("duplicate target `~/.gitconfig`"),
        "{message}"
    );
    assert!(message.contains("first declared at bx.toml:1"), "{message}");
    assert!(message.contains("bx.toml:5"), "{message}");
}

#[test]
fn a_duplicate_target_path_spelled_differently_is_rejected() {
    // The natural key is the normalised Portable, not the bytes a human
    // typed. Without that, one file quietly acquires two ledger rows.
    for second in ["~/.ssh/./config", "~/.ssh//config", "~/.ssh/keys/../config"] {
        let text = format!(
            "[[target]]\npath = \"~/.ssh/config\"\nfile = \"a\"\n\n\
                 [[target]]\npath = \"{second}\"\nfile = \"b\"\n"
        );
        assert!(
            message(&text).contains("duplicate target `~/.ssh/config`"),
            "{second} should collide with ~/.ssh/config"
        );
    }
}

#[test]
fn the_absolute_spelling_of_a_home_file_never_becomes_a_second_key() {
    // check_unique compares the stored strings, so it cannot see that
    // `/var/home/example/.ssh/config` and `~/.ssh/config` are one file. The
    // parser refuses the absolute spelling instead, which is what keeps one
    // file from acquiring two `attach = "own"` targets in one layer set.
    let text = "[[target]]\npath = \"~/.ssh/config\"\nfile = \"a\"\n\n\
                    [[target]]\npath = \"/var/home/example/.ssh/config\"\nfile = \"b\"\n";
    let message = message(text);

    assert!(message.contains("~/.ssh/config"), "{message}");
    assert!(
        message.contains("bx.toml:6"),
        "the caret must land on the offending `path` key: {message}"
    );
}

/// `load_layers` parses against the home it is *given*.
///
/// Nothing pinned that. Mutating `load_layers` to forward a hard-coded
/// `/nonexistent/mutated/home` left every test in this module passing,
/// because they all spell target paths `~/…`, which `parse_in` accepts
/// identically under any home; the tests that do depend on the home call
/// `parse_str` or `parse_target` directly and never reach the loader. So the
/// home threads through five call sites and the first two — `load_layers`
/// into `load_layer`, `load_layer` into `parse_str` — were unpinned, and
/// `load_layers` is the function `merge` and every other reader of a
/// config repo reads it through.
///
/// An **absolutely** spelled target path is the discriminating input: it is
/// admissible under one home and refused under another, so the error can
/// only arrive if this exact home reached `Portable::parse_in`.
#[test]
fn load_layers_parses_against_the_home_it_is_given() {
    let dir = repo(&[(
        "modules/ssh.toml",
        "[[target]]\npath = \"/var/home/example/.ssh/config\"\nfile = \"files/ssh\"\n",
    )]);

    let error = load_layers(dir.path(), home()).expect_err("absolute, and under this home");
    let message = error.to_string();
    assert!(
        message.contains("write ~/.ssh/config"),
        "the message must name the `~/…` spelling for *this* home: {message}"
    );

    // The same repo under a home the path is not inside parses, and keeps
    // the absolute spelling: the rule is about this home, not about the
    // string.
    let layers = load_layers(dir.path(), Path::new("/var/home/other")).expect("outside");
    assert_eq!(
        layers[0].config.targets[0].path.as_str(),
        "/var/home/example/.ssh/config"
    );
}

#[test]
fn a_target_path_that_climbs_out_of_home_is_rejected() {
    let text = "[[target]]\npath = \"~/../../etc/passwd\"\nfile = \"a\"\n";
    assert!(message(text).contains("climb out of the home"));
}

#[test]
fn a_duplicate_value_name_in_one_layer_is_rejected() {
    let text = "[[value]]\nname = \"scratch_root\"\nkind = \"path\"\n\n\
                    [[value]]\nname = \"scratch_root\"\nkind = \"string\"\n";
    assert!(message(text).contains("duplicate value `scratch_root`"));
}

#[test]
fn one_layer_may_not_both_restate_an_entry_and_toggle_it() {
    // The silent no-op the toggle mechanism exists to prevent, at its
    // sharpest: which of the two wins would depend on the order the merge
    // happens to apply them in, and nothing in the file says what that order
    // is. The uniqueness check sees toggles alongside the entries they flip
    // for exactly this.
    let text = "[[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\nenabled = false\n";
    let message = message(text);

    assert!(
        message.contains("duplicate target `~/.gitconfig`"),
        "{message}"
    );
    assert!(message.contains("first declared at bx.toml:1"), "{message}");
    assert!(message.contains("bx.toml:5"), "{message}");
}

#[test]
fn a_toggle_before_the_entry_it_flips_is_the_same_ambiguity() {
    // Order within the file makes no difference: it is the pair that is
    // ambiguous, not the direction.
    let text = "[[target]]\npath = \"~/.gitconfig\"\nenabled = false\n\n\
                    [[target]]\npath = \"~/.gitconfig\"\ncontent = \"x\"\n";
    assert!(message(text).contains("duplicate target `~/.gitconfig`"));

    let text = "[[value]]\nname = \"agent_slice\"\nkind = \"string\"\n\n\
                    [[value]]\nname = \"agent_slice\"\nenabled = false\n";
    assert!(message(text).contains("duplicate value `agent_slice`"));
}

#[test]
fn the_same_path_in_two_layers_is_not_a_duplicate() {
    // It is a replacement, and A3 performs it.
    let a = parse("[[target]]\npath = \"~/a\"\nfile = \"a\"\n").unwrap();
    let b = parse("[[target]]\npath = \"~/a\"\nfile = \"b\"\n").unwrap();

    assert_eq!(a.targets[0].path, b.targets[0].path);
}

// --- the invariants ---------------------------------------------------

#[test]
fn parsing_is_a_pure_function_of_the_bytes() {
    // Invariant 3. Two plan runs a week apart on an unchanged tree have to
    // read the same configuration in the same order.
    let text = "[[target]]\npath = \"~/z\"\nfile = \"z\"\n\n\
                    [[target]]\npath = \"~/a\"\ncontent = \"x\"\n\n\
                    [[value]]\nname = \"v\"\nkind = \"string\"\n\n\
                    [values]\nv = \"1\"\n";

    let first = parse(text).unwrap();
    for _ in 0..8 {
        assert_eq!(parse(text).unwrap(), first);
    }
}

#[test]
fn comments_and_formatting_survive_a_round_trip() {
    // Invariant 1, for configuration. Reading through toml_edit's DOM is
    // what will let `bx add` edit a hand-written file without rewriting a
    // byte the user wrote. `into_mut` is called only to render here; the
    // parser never calls it, because it discards every span.
    let text = "# the global layer\n\
                    \n\
                    [[target]]   # the gitconfig\n\
                    path    = \"~/.gitconfig\"     # where it lands\n\
                    file    = 'files/gitconfig'\n\
                    \n\
                    \n\
                    [values]\n\
                    v = \"1\"  # trailing\n\
                    # a trailing comment with no newline after it";

    parse(text).expect("the fixture parses");
    let rendered = Document::parse(text)
        .expect("valid TOML")
        .into_mut()
        .to_string();

    assert_eq!(rendered, text);
}

#[test]
fn every_error_renders_with_its_origin() {
    let origin = Origin {
        file: PathBuf::from("bx.toml"),
        line: 7,
    };
    let first = Origin {
        file: PathBuf::from("bx.toml"),
        line: 2,
    };

    let rendered = [
        Error::RepoMissing(PathBuf::from("/repo")).to_string(),
        Error::Io {
            path: PathBuf::from("/repo/bx.toml"),
            source: std::io::Error::other("broken"),
        }
        .to_string(),
        Error::UnknownSection {
            origin: origin.clone(),
            section: "alias".to_string(),
        }
        .to_string(),
        Error::UnknownKey {
            origin: origin.clone(),
            section: "[[target]]",
            key: "symlink".to_string(),
        }
        .to_string(),
        Error::MissingKey {
            origin: origin.clone(),
            section: "[[target]]",
            key: "path",
        }
        .to_string(),
        Error::WrongType {
            origin: origin.clone(),
            key: "enabled".to_string(),
            expected: "a boolean",
            found: "string",
        }
        .to_string(),
        Error::BadValue {
            origin: origin.clone(),
            message: "unusable".to_string(),
        }
        .to_string(),
        Error::Duplicate {
            origin,
            kind: "target",
            key: "~/.gitconfig".to_string(),
            first,
        }
        .to_string(),
    ];

    assert_eq!(rendered[0], "no bx config repo at /repo");
    assert_eq!(rendered[1], "/repo/bx.toml: broken");
    assert_eq!(
        Error::LocalInRepo {
            local: PathBuf::from("/repo/local.toml"),
            repo: PathBuf::from("/repo"),
        }
        .to_string(),
        "/repo/local.toml: this account's local layer is inside the config repo /repo, a \
             git working tree meant to be published; set XDG_STATE_HOME to a directory outside it"
    );
    for message in &rendered[2..] {
        assert!(
            message.starts_with("bx.toml:7: "),
            "every error says where: {message}"
        );
    }
    assert!(
        rendered
            .last()
            .unwrap()
            .contains("first declared at bx.toml:2")
    );
}
