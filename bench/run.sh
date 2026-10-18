#!/bin/sh
# Measure what bx's generated startup files cost zsh and bash, against their
# budget, and trace that they start no process and read no configuration.
#
# bx is on every shell start, so "fast enough to forget" is a product
# requirement, and a requirement that is not measured is a requirement that
# regresses. This is the external profile: it never sources the developer's real
# config, so the number is about bx, not about the machine it ran on.
#
# It measures bytes bx itself generated. The real bx binary applies the example
# configuration in fixtures/bx to a scratch home, and the shells measured are the
# ones that home starts: the account's own ~/.zshrc and ~/.bashrc with bx's
# region in each, and every file those regions and ~/.zshenv's source. Each
# shell skips the machine's system-wide startup files (zsh -d, bash --rcfile),
# which are neither the account's nor bx's.
#
# For each shell:
#
#   overhead  baseline vs the same rc file after `bx apply`. This is what bx's
#             generated files cost, cached activations included. Gated at
#             BX_BUDGET_MS (default 5).
#   net       a hand-written `eval "$(tool init)"` rc file vs bx's. Reported,
#             never gated: it depends on which tools are integrated, so a
#             threshold would be arbitrary.
#
# And, gated, invariant 6 traced on the running shells: any process started
# while bx's startup files ran alone, which must be none, and the files under
# the configuration and state directories they read.
#
# Environment:
#   BX_BIN        the bx binary to apply with (default: target/release/bx,
#                 which `mise run bench` builds first)
#   BX_BUDGET_MS  overhead budget in milliseconds (default: 5)
#   BX_BENCH_RUNS minimum hyperfine runs per fixture (default: 50)

set -eu

BUDGET_MS="${BX_BUDGET_MS:-5}"
RUNS="${BX_BENCH_RUNS:-50}"
SHELLS="zsh bash"

cd "$(dirname "$0")"
BENCH_DIR="$(pwd)"
RESULTS="${BENCH_DIR}/results"
BX="${BX_BIN:-$(dirname "$BENCH_DIR")/target/release/bx}"

[ -x "$BX" ] || {
	echo "error: no bx binary at ${BX}; build it with \`cargo build --release\`," >&2
	echo "       or run \`mise run bench\`, which does." >&2
	exit 1
}
for tool in $SHELLS git; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "error: ${tool} is required." >&2
		exit 1
	}
done
command -v hyperfine >/dev/null 2>&1 || {
	echo "error: hyperfine is required (mise install)." >&2
	exit 1
}
command -v python3 >/dev/null 2>&1 || {
	echo "error: python3 is required to read hyperfine's JSON." >&2
	exit 1
}
# How a traced start's processes are counted: Linux reads the shell's own
# /proc/$$/stat, and macOS, which has no /proc, watches the shell's forks
# through kqueue. Both are explained where the trace runs.
if [ -r /proc/self/stat ]; then
	COUNT_BY=proc
elif python3 -c 'import select; select.KQ_NOTE_FORK' 2>/dev/null; then
	COUNT_BY=kqueue
else
	echo "error: counting the processes a start spawns needs /proc/self/stat (Linux)" >&2
	echo "       or kqueue's NOTE_FORK (macOS)." >&2
	exit 1
fi
# Said once, so a log shows which way the spawns below were counted; CI's
# macOS bench job requires the kqueue line.
case "$COUNT_BY" in
proc) echo "Counting the processes a start spawns through /proc/\$\$/stat." ;;
kqueue) echo "Counting the processes a start spawns through kqueue NOTE_FORK." ;;
esac

mkdir -p "$RESULTS"

# Hermetic: a scratch home per fixture so nothing in the developer's own home is
# read, and the stub tools ahead of the system's programs on PATH.
WORK="$(mktemp -d)"
# shellcheck disable=SC2064 # WORK is expanded now, on purpose.
trap "rm -rf '$WORK'" EXIT INT TERM
SEARCH="${BENCH_DIR}/stubs:/usr/local/bin:/usr/bin:/bin"

for f in baseline legacy bx; do
	mkdir -p "${WORK}/${f}"
done
for rc in .zshrc .bashrc; do
	cp "${BENCH_DIR}/fixtures/baseline/${rc}" "${WORK}/baseline/${rc}"
	cp "${BENCH_DIR}/fixtures/legacy/${rc}" "${WORK}/legacy/${rc}"
	# The bx home starts as the baseline does.
	cp "${BENCH_DIR}/fixtures/baseline/${rc}" "${WORK}/bx/${rc}"
done

# The bx home's config repo is the example configuration, with this account's
# answers. The pinned external and the secret are switched off: one would clone
# over the network and the other needs a key, and neither is on the shell's
# startup path.
mkdir -p "${WORK}/bx/.config" "${WORK}/bx/.local/state/bx"
cp -R "${BENCH_DIR}/fixtures/bx" "${WORK}/bx/.config/bx"

# The followed external stays on, because following a branch is what puts the
# update-prompt hook in the generated interactive files, and that hook is on
# the startup path. It clones from a local upstream instead of the network:
# the home's ~/.gitconfig redirects the declared url there, as the acceptance
# suite does, and the copy's bx.lock holds that upstream's commit.
UPSTREAM="${WORK}/upstream/zsh-completions"
mkdir -p "${UPSTREAM}/src"
echo '#compdef example' >"${UPSTREAM}/src/_example"
upstream() { # upstream <args>: git in the local upstream, with nothing inherited
	env -i PATH="$SEARCH" HOME="${WORK}/upstream" GIT_CONFIG_NOSYSTEM=1 \
		GIT_AUTHOR_NAME=bench GIT_AUTHOR_EMAIL=bench@example.invalid \
		GIT_COMMITTER_NAME=bench GIT_COMMITTER_EMAIL=bench@example.invalid \
		git -C "$UPSTREAM" "$@"
}
upstream init --quiet -b master
upstream add --all
upstream commit --quiet -m 'the completions'
LOCK="${WORK}/bx/.config/bx/bx.lock"
sed "s/^rev = \".*\"\$/rev = \"$(upstream rev-parse HEAD)\"/" \
	"${BENCH_DIR}/fixtures/bx/bx.lock" >"$LOCK"
cat >"${WORK}/bx/.gitconfig" <<GIT
[url "file://${WORK}/upstream/"]
	insteadOf = https://github.com/zsh-users/
GIT

cat >"${WORK}/bx/.local/state/bx/local.toml" <<'TOML'
[values]
git_name = "Bench"
git_email = "bench@example.invalid"

[[target]]
path = "~/.ssh/config"
enabled = false

[[external]]
path = "~/.local/share/zsh/zsh-autosuggestions"
enabled = false
TOML

bx() { # bx <args>: the real binary, in the bx home, with nothing inherited
	env -i HOME="${WORK}/bx" PATH="$SEARCH" "$BX" "$@" >"${WORK}/bx.log" 2>&1 || {
		status=$?
		echo "error: \`bx $*\` exited ${status}:" >&2
		cat "${WORK}/bx.log" >&2
		exit 1
	}
}
bx apply --yes
# Converged, so what is measured is exactly what bx leaves in place.
bx plan

# The hook is measured only if bx generated it: each shell's interactive file
# must register it, or the number below says nothing about it.
for hook in 'precmd_functions+=(__bx_update)' "PROMPT_COMMAND+=('\${BX_UPDATE_HOOK-}')"; do
	grep -qsF "$hook" "${WORK}/bx/.local/share/bx/"* || {
		echo "error: bx generated no update-prompt hook (${hook}) to measure." >&2
		exit 1
	}
done

startup() { # startup <shell> <fixture>: the command that starts it, as one line
	case "$1" in
	zsh) echo "zsh -d -i -c exit" ;;
	bash) echo "bash --rcfile ${WORK}/${2}/.bashrc -i -c exit" ;;
	esac
}

# Invariant 6, read: every file bx generated or attached a region to is
# searched for a command substitution, including branches a start in this home
# never takes. The hand-written rc files are searched too, so a pattern that
# finds nothing is known to work.
# shellcheck disable=SC2016 # the patterns are literal on purpose.
SUBST='\$(' TICK='`'
spawns() { # spawns <file>...: lines, not comments, holding a command substitution
	cat "$@" | grep -v '^[[:space:]]*#' | grep -c -e "$SUBST" -e "$TICK" || true
}
generated() { # generated <shell>: the startup files bx wrote or attached to
	case "$1" in
	zsh) echo "${WORK}/bx/.zshenv ${WORK}/bx/.zshrc ${WORK}/bx/.local/share/bx/"*.zsh ;;
	bash) echo "${WORK}/bx/.bashrc ${WORK}/bx/.local/share/bx/"*.bash ;;
	esac
}
for sh in $SHELLS; do
	# shellcheck disable=SC2046 # the scratch paths hold no whitespace.
	found="$(spawns $(generated "$sh"))"
	legacy="$(spawns "${WORK}/legacy/.${sh}rc")"
	[ "$legacy" -eq 4 ] || {
		echo "error: the spawn count found ${legacy} of the hand-written ${sh}rc's 4." >&2
		exit 1
	}
	[ "$found" -eq 0 ] || {
		echo "FAIL: bx's ${sh} startup files hold ${found} line(s) that start a process:" >&2
		# shellcheck disable=SC2046
		grep -n -e "$SUBST" -e "$TICK" $(generated "$sh") |
			grep -v ':[0-9]*:[[:space:]]*#' >&2 || true
		exit 1
	}
done

# Invariant 6, traced on running shells. Each traced start runs bx's lines
# alone: the regions bx attached to the account's rc files, cut into a trace
# directory, in the bx home, so every file they source is the one bx wrote.
# The account's own lines are not bx's to answer for (the baseline zshrc's
# compinit starts a process of its own). The hand-written rc files' activation
# lines are traced the same way, so a trace that sees nothing is known to work.
TRACE="${WORK}/trace"
mkdir -p "${TRACE}/bx" "${TRACE}/legacy"
for rc in .zshenv .zshrc .bashrc; do
	sed -n '/^# >>> bx >>>$/,/^# <<< bx <<<$/p' "${WORK}/bx/${rc}" >"${TRACE}/bx/${rc}"
done
for rc in .zshrc .bashrc; do
	grep '^eval ' "${WORK}/legacy/${rc}" >"${TRACE}/legacy/${rc}"
done
WATCH="" # a command the traced shell runs under, set only while counting forks
traced() { # traced <shell> <fixture> [command]: start it with only its traced lines
	case "$1" in
	zsh) set -- "$2" "${3:-exit}" zsh -d -i ;;
	bash) set -- "$2" "${3:-exit}" bash --rcfile "${TRACE}/${2}/.bashrc" -i ;;
	esac
	fixture="$1" command="$2"
	shift 2
	# shellcheck disable=SC2086 # WATCH is a command line; the scratch paths hold no whitespace.
	$WATCH env -i HOME="${WORK}/${fixture}" ZDOTDIR="${TRACE}/${fixture}" PATH="$SEARCH" \
		"$@" -c "$command" 2>/dev/null
}

# Spawns, on Linux: a shell that started a process and waited for it carries
# that child's page faults in its own /proc/$$/stat (cminflt, the 11th field),
# and no process runs without faulting a page in. So the traced shell reads
# that field itself, with builtins, once its startup files and a `wait` are
# done: 0 exactly when they started nothing, and nothing else on the machine
# moves it.
# shellcheck disable=SC2016 # expanded by the traced shell, not this one.
SELF='wait; read -r stat </proc/$$/stat; echo "$stat"'
# Spawns, on macOS: no /proc, and a shell's builtins expose no child page
# faults (bash's `times` rounds a fork's cost to 0 ms). So the traced shell is
# watched from outside instead: forks.py forks, registers a kqueue NOTE_FORK
# filter on its child while the child waits, and only then lets it exec the
# shell, so no fork from the first line of a startup file on is missed. Every
# process a shell starts, a command or a subshell, begins as a fork of the
# shell, and `env` execs it without forking. It prints the forks it saw: 0
# exactly when the startup files started nothing. Repeated forks between two
# reads coalesce into one event, so a non-zero count is a lower bound.
cat >"${WORK}/forks.py" <<'PY'
import os, select, sys

go_r, go_w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(go_w)
    os.read(go_r, 1)
    os.execvp(sys.argv[1], sys.argv[1:])
os.close(go_r)
kq = select.kqueue()
watch = select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                      select.KQ_NOTE_FORK | select.KQ_NOTE_EXIT)
kq.control([watch], 0)
os.close(go_w)
forks, done = 0, False
while not done:
    for event in kq.control(None, 8):
        forks += bool(event.fflags & select.KQ_NOTE_FORK)
        done = done or bool(event.fflags & select.KQ_NOTE_EXIT)
os.waitpid(pid, 0)
print(forks)
PY
spawned() { # spawned <shell> <fixture>: what its traced start spawned, 0 for nothing
	case "$COUNT_BY" in
	proc) traced "$1" "$2" "$SELF" | awk '{ print $11 }' ;;
	kqueue)
		WATCH="python3 ${WORK}/forks.py"
		traced "$1" "$2" wait | tail -n 1
		WATCH=""
		;;
	esac
}
unit() { # unit: what spawned counts
	case "$COUNT_BY" in
	proc) echo "page faults" ;;
	kqueue) echo "forks" ;;
	esac
}
for sh in $SHELLS; do
	legacy="$(spawned "$sh" legacy)"
	[ "${legacy:-0}" -gt 0 ] || {
		echo "error: the ${sh} trace saw no process start from the hand-written ${sh}rc." >&2
		exit 1
	}
	spawns="$(spawned "$sh" bx)"
	[ -n "$spawns" ] || {
		echo "error: the ${sh} trace of bx's startup files read nothing back." >&2
		exit 1
	}
	[ "$spawns" -eq 0 ] || {
		echo "FAIL: bx's ${sh} startup files started a process (${spawns} $(unit))." >&2
		exit 1
	}
done

# Reads: the startup path parses no configuration. Every file under the bx
# home's configuration and state directories, bx's own config repo and state
# among them, has its access time set into the past; a read moves it to now
# under Linux's relatime and strictatime mounts and macOS's default APFS ones,
# and BSD find and touch take the same flags as GNU's here. A read made first
# proves this filesystem records reads at all.
WITNESS="${WORK}/bx/.config ${WORK}/bx/.local/state"
unread() { # unread: set every witness's access time into the past
	# shellcheck disable=SC2086 # the scratch paths hold no whitespace.
	find $WITNESS -type f -exec touch -a -t 200001010000 {} +
}
read_since() { # read_since: the witnesses read since `unread`
	# shellcheck disable=SC2086
	find $WITNESS -type f -newerat '2000-01-02'
}
unread
cat "${WORK}/bx/.local/state/bx/local.toml" >/dev/null
[ -n "$(read_since)" ] || {
	echo "error: the filesystem under ${WORK} does not record reads (noatime);" >&2
	echo "       set TMPDIR to a directory on one that does." >&2
	exit 1
}
for sh in $SHELLS; do
	unread
	traced "$sh" bx >/dev/null || true
	read="$(read_since)"
	[ -z "$read" ] || {
		echo "FAIL: bx's ${sh} startup files read configuration:" >&2
		echo "$read" | sed "s|^${WORK}/bx/|  ~/|" >&2
		exit 1
	}
done

run() { # run <name> <shell> <fixture>...
	name="$1"
	sh="$2"
	shift 2
	cmds=""
	for f in "$@"; do
		# `env` rather than a `VAR=… cmd` prefix: --shell=none execs the
		# command directly, so there is no shell to interpret an assignment.
		cmds="${cmds} -n ${f} 'env -i HOME=${WORK}/${f} PATH=${SEARCH} $(startup "$sh" "$f")'"
	done
	# Prime each fixture once so compinit's dump exists before timing.
	for f in "$@"; do
		# shellcheck disable=SC2046
		env -i HOME="${WORK}/${f}" PATH="$SEARCH" $(startup "$sh" "$f") >/dev/null 2>&1 || true
	done
	eval "hyperfine --warmup 5 --min-runs ${RUNS} --shell=none \
		--export-json '${RESULTS}/${name}-${sh}.json' ${cmds}" >/dev/null
}

for sh in $SHELLS; do
	echo "Measuring bx's generated ${sh} startup files (budget ${BUDGET_MS} ms)..."
	run overhead "$sh" baseline bx
	echo "Measuring net effect vs a hand-written ${sh}rc..."
	run net "$sh" legacy bx
done

# shellcheck disable=SC2086 # one argument per shell.
python3 - "$RESULTS" "$BUDGET_MS" $SHELLS <<'PY'
import json, sys

results, budget, shells = sys.argv[1], float(sys.argv[2]), sys.argv[3:]

labels = {"overhead": ["baseline", "bx"], "net": ["legacy", "bx"]}


def medians(name, shell):
    with open(f"{results}/{name}-{shell}.json") as fh:
        data = json.load(fh)["results"]
    # The -n labels are not echoed back in the JSON, so pair by position: the
    # results are in the order the commands were given. The median, not the
    # mean: a start the scheduler delayed moves the mean by its whole delay
    # and the median not at all, and the gate is about bx, not about the
    # machine's other load. hyperfine 1 puts it at the top of each result,
    # hyperfine 2 under its summary's wall-clock time.
    return {label: median(r) * 1000 for label, r in zip(labels[name], data)}


def median(result):
    if "summary" in result:
        return result["summary"]["time_wall_clock"]["median"]
    return result["median"]


over_budget = []
for shell in shells:
    over = medians("overhead", shell)
    net = medians("net", shell)
    overhead = over["bx"] - over["baseline"]
    saved = net["legacy"] - net["bx"]
    if overhead > budget:
        over_budget.append((shell, overhead))

    print()
    print(f"  {shell}")
    print(f"  baseline   {over['baseline']:7.2f} ms")
    print(f"  + bx       {over['bx']:7.2f} ms   after `bx apply` of the example")
    print(f"  overhead   {overhead:7.2f} ms   (budget {budget:.2f} ms)")
    print(f"  spawns     {0:7d}      processes bx's startup files started")
    print(f"  reads      {0:7d}      configuration files they read")
    print()
    print(f"  legacy     {net['legacy']:7.2f} ms   eval \"$(tool init)\" per tool")
    print(f"  bx         {net['bx']:7.2f} ms   the same tools, cached by bx")
    print(f"  saved      {saved:7.2f} ms")

print()
for shell, overhead in over_budget:
    print(f"FAIL: bx adds {overhead:.2f} ms to {shell}, over its {budget:.2f} ms budget.")
if over_budget:
    sys.exit(1)
print(f"OK: bx adds less than its {budget:.2f} ms budget to {' and '.join(shells)},")
print("    starts no process and reads no configuration.")
PY
