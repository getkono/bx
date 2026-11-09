/*
 * The stub starship as a native program, which the bench compiles into its
 * scratch PATH ahead of `stubs/`, because the real starship is one. Its cached
 * output ends with `PROMPT2="$(starship prompt --continuation)"`, so every
 * start that sources it spawns starship once, and the overhead counts that
 * spawn: answering it with the shell script would count what starting
 * `/bin/sh` costs instead, which is many times a native program's on macOS.
 *
 * It is C, built by the `cc` that links bx, so the spawn costs a fork and the
 * exec of a program that links only libc: the least any native program pays,
 * which is the part of the real starship's spawn no tool can avoid. A Rust
 * program's runtime set-up would add its own cost on top, and the budget would
 * be judging that rather than the spawn.
 *
 * `prompt` is answered here and starts nothing more; every other command is
 * the shell stub's, BX_BENCH_STARSHIP, which emits the init block.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	(void)argc;
	if (argv[1] != NULL && strcmp(argv[1], "prompt") == 0)
		return write(STDOUT_FILENO, "> ", 2) == 2 ? 0 : 1;
	argv[0] = BX_BENCH_STARSHIP;
	execv(BX_BENCH_STARSHIP, argv);
	perror("starship stub");
	return 1;
}
