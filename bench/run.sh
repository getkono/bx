#!/bin/sh
# Measure what bx's generated startup files cost zsh and bash, against their
# budget, and trace that bx's own startup lines start no process and read no
# configuration; a tool's cached activation output starts what it would under
# `eval "$(tool init)"`, and the budget counts it.
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
#             BX_BUDGET_MS (default 5), reported with the noise it is read
#             through, and measured again before failing when it is over
#             budget by less than that noise.
#   net       a hand-written `eval "$(tool init)"` rc file vs bx's. Reported,
#             never gated: it depends on which tools are integrated, so a
#             threshold would be arbitrary.
#
# And, gated, invariant 6 traced on the running shells: any process started
# while bx's own startup lines ran alone, which must be none, and the files
# under the configuration and state directories they read. A tool's cached
# activation output is the one exception: what it starts, as starship's
# continuation prompt does, it starts as it would under `eval "$(tool init)"`,
# and the overhead counts it.
#
# Environment:
#   BX_BIN        the bx binary to apply with (default: target/release/bx,
#                 which `mise run bench` builds first)
#   BX_BUDGET_MS  overhead budget in milliseconds (default: 5)
#   BX_BENCH_RUNS minimum hyperfine runs per fixture (default: 50)
#   BX_BENCH_ROUNDS interleaved rounds the overhead is measured in, each
#                 starting either fixture twice (default: BX_BENCH_RUNS / 2,
#                 rounded up)

set -eu

BUDGET_MS="${BX_BUDGET_MS:-5}"
RUNS="${BX_BENCH_RUNS:-50}"
ROUNDS="${BX_BENCH_ROUNDS:-$(((RUNS + 1) / 2))}"
SHELLS="zsh bash"
[ "$ROUNDS" -ge 1 ] 2>/dev/null || {
	echo "error: BX_BENCH_ROUNDS must be a whole number of at least 1." >&2
	exit 1
}

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
# Only this run's measurements, so the uploaded results are the ones read.
rm -f "${RESULTS}"/*.json

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
#
# The one exception is a tool's cached activation output: bx sources it as the
# tool printed it, so a substitution the tool emitted runs at every start, as
# it would under `eval "$(tool init)"`, and the overhead above counts it. bx
# caches that output verbatim, as one single-quoted `eval` under a
# `# bx activation: NAME` line, so following that quoting splits bx's own lines
# from the tools'. bx's own must hold no substitution, and the cached output
# must hold exactly the ones the tools print themselves: one bx added inside
# it, or dropped from it, changes that count.
# shellcheck disable=SC2016 # the patterns are literal on purpose.
SUBST='\$(' TICK='`'
count() { # count: lines on stdin, not comments, holding a command substitution
	grep -v '^[[:space:]]*#' | grep -c -e "$SUBST" -e "$TICK" || true
}
spawns() { # spawns <file>...: lines, not comments, holding a command substitution
	cat "$@" | count
}
split() { # split <own|cached> <file>...: bx's own lines, or the tools' cached output
	want="$1"
	shift
	awk -v want="$want" '
		!block && /^# bx activation: / { block = 1; head = 1 }
		{
			cached = block
			# Inside single quotes only a quote means anything; outside, a
			# backslash escapes the next character. The block ends with the
			# line that closes the eval quote it opened.
			for (i = 1; block && !head && i <= length($0); i++) {
				c = substr($0, i, 1)
				if (open) {
					if (c == "\047") open = 0
				} else if (c == "\\") {
					i++
				} else if (c == "\047") {
					open = 1
				}
			}
			if (block && !head && !open) block = 0
			head = 0
			if ((want == "cached") == cached) print
		}' "$@"
}
emitted() { # emitted <shell>: what the tools the hand-written rc activates print for it
	# shellcheck disable=SC2016 # the pattern is literal on purpose.
	sed -n 's/^eval "\$(\(.*\))"$/\1/p' "${WORK}/legacy/.${1}rc" | while read -r tool; do
		# shellcheck disable=SC2086 # a command line, split into its words on purpose.
		env -i PATH="$SEARCH" $tool
	done
}
generated() { # generated <shell>: the startup files bx wrote or attached to
	case "$1" in
	zsh) echo "${WORK}/bx/.zshenv ${WORK}/bx/.zshrc ${WORK}/bx/.local/share/bx/"*.zsh ;;
	bash) echo "${WORK}/bx/.bashrc ${WORK}/bx/.local/share/bx/"*.bash ;;
	esac
}
for sh in $SHELLS; do
	# shellcheck disable=SC2046 # the scratch paths hold no whitespace.
	found="$(split own $(generated "$sh") | count)"
	# shellcheck disable=SC2046
	cached="$(split cached $(generated "$sh") | count)"
	tools="$(emitted "$sh" | count)"
	legacy="$(spawns "${WORK}/legacy/.${sh}rc")"
	[ "$legacy" -eq 4 ] || {
		echo "error: the spawn count found ${legacy} of the hand-written ${sh}rc's 4." >&2
		exit 1
	}
	[ "$tools" -gt 0 ] || {
		echo "error: no stub's ${sh} output starts a process, as starship's does;" >&2
		echo "       the bench would not measure what a real start costs." >&2
		exit 1
	}
	[ "$found" -eq 0 ] || {
		echo "FAIL: bx's ${sh} startup files hold ${found} line(s) of their own that start a process:" >&2
		# shellcheck disable=SC2046
		split own $(generated "$sh") | grep -n -e "$SUBST" -e "$TICK" |
			grep -v '^[0-9]*:[[:space:]]*#' >&2 || true
		exit 1
	}
	[ "$cached" -eq "$tools" ] || {
		echo "FAIL: bx's cached ${sh} activations hold ${cached} line(s) that start a process;" >&2
		echo "      the tools themselves print ${tools}." >&2
		exit 1
	}
done

# Invariant 6, traced on running shells. Each traced start runs bx's lines
# alone: the regions bx attached to the account's rc files, cut into a trace
# directory, in the bx home, so every file they source is the one bx wrote.
# The account's own lines are not bx's to answer for (the baseline zshrc's
# compinit starts a process of its own). The hand-written rc files' activation
# lines are traced the same way, so a trace that sees nothing is known to work.
#
# The tools' cached output is the exception the read check above attributes,
# and the trace attributes it the same way. `cached` runs the regions as bx
# wrote them, so it starts what the stub starship's output starts, and must
# read above 0: the bench measures that spawn rather than missing it. `bx`
# runs the same regions sourcing copies of bx's generated files with every
# cached activation split out, so it runs bx's own lines alone, and must read
# 0.
TRACE="${WORK}/trace"
SHARE="${WORK}/bx/.local/share/bx"
mkdir -p "${TRACE}/bx" "${TRACE}/cached" "${TRACE}/legacy" "${TRACE}/own"
for f in "$SHARE"/*; do
	split own "$f" >"${TRACE}/own/${f##*/}"
done
for rc in .zshenv .zshrc .bashrc; do
	sed -n '/^# >>> bx >>>$/,/^# <<< bx <<<$/p' "${WORK}/bx/${rc}" >"${TRACE}/cached/${rc}"
	sed "s|~/.local/share/bx/|${TRACE}/own/|g" "${TRACE}/cached/${rc}" >"${TRACE}/bx/${rc}"
	grep -qF "${TRACE}/own/" "${TRACE}/bx/${rc}" || {
		echo "error: bx's ${rc} region sources nothing from ~/.local/share/bx to trace." >&2
		exit 1
	}
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
	home="${WORK}/bx" # every trace fixture but the hand-written one starts the bx home
	[ "$fixture" != legacy ] || home="${WORK}/legacy"
	# shellcheck disable=SC2086 # WATCH is a command line; the scratch paths hold no whitespace.
	$WATCH env -i HOME="$home" ZDOTDIR="${TRACE}/${fixture}" PATH="$SEARCH" \
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
	cached="$(spawned "$sh" cached)"
	[ "${cached:-0}" -gt 0 ] || {
		echo "error: the ${sh} trace saw no process start from the cached activations," >&2
		echo "       as the stub starship's output starts one; the bench would not measure it." >&2
		exit 1
	}
	spawns="$(spawned "$sh" bx)"
	[ -n "$spawns" ] || {
		echo "error: the ${sh} trace of bx's startup files read nothing back." >&2
		exit 1
	}
	[ "$spawns" -eq 0 ] || {
		echo "FAIL: bx's own ${sh} startup lines started a process (${spawns} $(unit))." >&2
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

prime() { # prime <shell> <fixture>...: start each once, so compinit's dump exists
	sh="$1"
	shift
	for f in "$@"; do
		# shellcheck disable=SC2046
		env -i HOME="${WORK}/${f}" PATH="$SEARCH" $(startup "$sh" "$f") >/dev/null 2>&1 || true
	done
}
run() { # run <name> <shell> <warmup> <count> <fixture>...: one hyperfine, in that order
	name="$1"
	sh="$2"
	warmup="$3"
	count="$4" # hyperfine's run count, e.g. `--runs 5`
	shift 4
	cmds=""
	for f in "$@"; do
		# `env` rather than a `VAR=… cmd` prefix: --shell=none execs the
		# command directly, so there is no shell to interpret an assignment.
		cmds="${cmds} -n ${f} 'env -i HOME=${WORK}/${f} PATH=${SEARCH} $(startup "$sh" "$f")'"
	done
	eval "hyperfine --warmup ${warmup} ${count} --shell=none \
		--export-json '${RESULTS}/${name}-${sh}.json' ${cmds}" >/dev/null
}

# The overhead is a difference of two fixtures, and hyperfine times each
# fixture's runs as one block, so whatever the machine is doing while one block
# runs and not the other lands in the difference: a shared CI runner moves the
# same start by more than the budget from one start to the next, and a macOS
# runner holds a slow spell for a fraction of a second, shorter than any block
# of runs. So the overhead is measured in rounds of four single starts, each
# fixture twice, mirrored (baseline bx bx baseline, then bx baseline baseline
# bx the round after), and the gate reads the median of the rounds'
# differences: a drift that is steady across a round's four starts cancels out
# of it, every fixture holds every position equally often, and a round a spell
# broke into is outvoted. The rounds are primed, so none needs a warmup.
measure() { # measure <shell> <name>: the overhead's rounds, as <name>-<round>
	round=1
	while [ "$round" -le "$ROUNDS" ]; do
		case "$((round % 2))" in
		1) run "${2}-${round}" "$1" 0 "--runs 1" baseline bx bx baseline ;;
		0) run "${2}-${round}" "$1" 0 "--runs 1" bx baseline baseline bx ;;
		esac
		round=$((round + 1))
	done
}
for sh in $SHELLS; do
	prime "$sh" baseline legacy bx
	echo "Measuring bx's generated ${sh} startup files (budget ${BUDGET_MS} ms)..."
	measure "$sh" overhead
	echo "Measuring net effect vs a hand-written ${sh}rc..."
	run net "$sh" 5 "--min-runs ${RUNS}" legacy bx
done

# The gate. A macOS runner's zsh baseline is 35-40 ms, so the same generated
# files can read well under the budget on one runner and just over it on the
# next. Each shell's report therefore carries the noise its median overhead is
# read through, estimated from the starts that differ only by chance: each
# round's two baseline starts. An overhead over budget by more than that noise
# fails at once. One over budget but within it is measured again, in as many
# fresh rounds, and fails only if the repeat is over budget too. The budget
# itself never moves: a pass always reads an overhead under it.
cat >"${WORK}/judge.py" <<'PY'
import json, math, statistics, sys

results, budget, rounds = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
name, again, shells = sys.argv[4], sys.argv[5], sys.argv[6:]


def order(name):
    # The order run.sh gave the fixtures in: odd rounds are baseline bx bx
    # baseline, even rounds their mirror.
    if name == "net":
        return ["legacy", "bx"]
    if int(name.split("-")[1]) % 2:
        return ["baseline", "bx", "bx", "baseline"]
    return ["bx", "baseline", "baseline", "bx"]


def starts(name, shell):
    with open(f"{results}/{name}-{shell}.json") as fh:
        data = json.load(fh)["results"]
    # hyperfine 1 does not echo the -n labels back in the JSON, so pair by
    # position: the results are in the order the commands were given. The
    # median, not the mean: a start the scheduler delayed moves the mean by
    # its whole delay and the median not at all, and the gate is about bx, not
    # about the machine's other load. hyperfine 1 puts it at the top of each
    # result, hyperfine 2 under its summary's wall-clock time. A fixture a
    # round starts twice keeps both starts, in the order they ran.
    each = {}
    for label, r in zip(order(name), data):
        each.setdefault(label, []).append(median(r) * 1000)
    return each


def medians(name, shell):
    # A fixture a round starts twice reads as the mean of its two starts,
    # which is what cancels a steady drift across the round.
    return {label: statistics.mean(t) for label, t in starts(name, shell).items()}


def median(result):
    if "summary" in result:
        return result["summary"]["time_wall_clock"]["median"]
    return result["median"]


def noise(each):
    # A round's two baseline starts differ only by chance, so the spread of
    # their differences is the runner's noise. Its median absolute deviation,
    # times 1.4826, estimates their standard deviation robustly, and that
    # deviation is sqrt(2) times a round's, which also differences two pairs
    # of starts. The median of the rounds deviates about 1.2533 / sqrt(rounds)
    # times as much again; the noise is twice that, so an overhead beyond it
    # is not chance.
    diffs = [b[0] - b[1] for b in (m["baseline"] for m in each)]
    centre = statistics.median(diffs)
    spread = 1.4826 * statistics.median(abs(d - centre) for d in diffs)
    return 2 * 1.2533 * spread / math.sqrt(2 * len(each))


failed = []
for shell in shells:
    each = [starts(f"{name}-{r}", shell) for r in range(1, rounds + 1)]
    means = [{k: statistics.mean(t) for k, t in m.items()} for m in each]
    baseline = statistics.median(m["baseline"] for m in means)
    with_bx = statistics.median(m["bx"] for m in means)
    overhead = statistics.median(m["bx"] - m["baseline"] for m in means)
    spread = noise(each)
    if overhead > budget and not again:
        failed.append((shell, overhead, "measured twice"))
    elif overhead - spread > budget:
        failed.append((shell, overhead, "beyond the noise"))
    elif overhead > budget:
        with open(again, "a") as fh:
            print(shell, file=fh)

    print()
    print(f"  {shell}" + ("" if again else ", measured again"))
    print(f"  baseline   {baseline:7.2f} ms")
    print(f"  + bx       {with_bx:7.2f} ms   after `bx apply` of the example")
    print(f"  overhead   {overhead:7.2f} ms   (budget {budget:.2f} ms; median of {rounds} rounds)")
    print(f"  noise      {spread:7.2f} ms   baseline vs baseline, at that median")
    if not again:
        continue
    net = medians("net", shell)
    print(f"  spawns     {0:7d}      processes bx's own startup lines started")
    print(f"  reads      {0:7d}      configuration files they read")
    print()
    print(f"  legacy     {net['legacy']:7.2f} ms   eval \"$(tool init)\" per tool")
    print(f"  bx         {net['bx']:7.2f} ms   the same tools, cached by bx")
    print(f"  saved      {net['legacy'] - net['bx']:7.2f} ms")

print()
for shell, overhead, why in failed:
    print(f"FAIL: bx adds {overhead:.2f} ms to {shell}, over its {budget:.2f} ms budget, {why}.")
if failed:
    sys.exit(1)
PY
judge() { # judge <name> <again> <shell>...: the overhead read from <name>'s rounds
	python3 "${WORK}/judge.py" "$RESULTS" "$BUDGET_MS" "$ROUNDS" "$@"
}
# An empty <again> means this reading is the repeat, so there is no other.
AGAIN="${WORK}/again"
: >"$AGAIN"
# shellcheck disable=SC2086 # one argument per shell.
judge overhead "$AGAIN" $SHELLS
retry="$(cat "$AGAIN")"
if [ -n "$retry" ]; then
	# shellcheck disable=SC2086 # one word per shell.
	for sh in $retry; do
		echo "Measuring bx's ${sh} overhead again: over budget, but within the noise..."
		measure "$sh" again
	done
	# shellcheck disable=SC2086
	judge again "" $retry
fi
printf 'OK: bx adds less than its %.2f ms budget to %s,\n' "$BUDGET_MS" "$(echo "$SHELLS" | sed 's/ / and /')"
echo "    and its own startup lines start no process and read no configuration."
