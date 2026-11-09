// The stub starship as a native program, which the bench compiles into its
// scratch PATH ahead of `stubs/`, because the real starship is one. Its cached
// output ends with `PROMPT2="$(starship prompt --continuation)"`, so every
// start that sources it spawns starship once, and the overhead counts that
// spawn: answering it with the shell script would count what starting
// `/bin/sh` costs instead, which is many times a native program's on macOS.
//
// `prompt` is answered here and starts nothing more; every other command is
// the shell stub's, which emits the init block.
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("prompt") {
        print!("> ");
        return;
    }
    let error = Command::new(env!("BX_BENCH_STARSHIP")).args(&args).exec();
    eprintln!("starship stub: {error}");
    std::process::exit(1);
}
