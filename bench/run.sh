#!/bin/sh
# Measure what bx's generated startup files cost zsh, against their budget.
#
# bx is on every shell start, so "fast enough to forget" is a product
# requirement, and a requirement that is not measured is a requirement that
# regresses. This is the external profile: it never sources the developer's real
# config, so the number is about bx, not about the machine it ran on.
#
# It measures bytes bx itself generated. The real bx binary applies the example
# configuration in fixtures/bx to a scratch home, and the shell measured is the
# one that home starts: the account's own ~/.zshrc with bx's region in it, and
# every file that region and ~/.zshenv's source.
#
# Two measurements, for two different questions:
#
#   overhead  baseline vs the same zshrc after `bx apply`. This is what bx's
#             generated files cost, cached activations included. Gated at
#             BX_BUDGET_MS (default 5).
#   net       a hand-written `eval "$(tool init)"` zshrc vs bx's. Reported,
#             never gated: it depends on which tools are integrated, so a
#             threshold would be arbitrary.
#
# Environment:
#   BX_BIN        the bx binary to apply with (default: target/release/bx,
#                 which `mise run bench` builds first)
#   BX_BUDGET_MS  overhead budget in milliseconds (default: 5)
#   BX_BENCH_RUNS minimum hyperfine runs per fixture (default: 50)

set -eu

BUDGET_MS="${BX_BUDGET_MS:-5}"
RUNS="${BX_BENCH_RUNS:-50}"

cd "$(dirname "$0")"
BENCH_DIR="$(pwd)"
RESULTS="${BENCH_DIR}/results"
BX="${BX_BIN:-$(dirname "$BENCH_DIR")/target/release/bx}"

[ -x "$BX" ] || {
	echo "error: no bx binary at ${BX}; build it with \`cargo build --release\`," >&2
	echo "       or run \`mise run bench\`, which does." >&2
	exit 1
}
command -v zsh >/dev/null 2>&1 || {
	echo "error: zsh is required." >&2
	exit 1
}
command -v hyperfine >/dev/null 2>&1 || {
	echo "error: hyperfine is required (mise install)." >&2
	exit 1
}
command -v python3 >/dev/null 2>&1 || {
	echo "error: python3 is required to read hyperfine's JSON." >&2
	exit 1
}

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
cp "${BENCH_DIR}/fixtures/baseline/.zshrc" "${WORK}/baseline/.zshrc"
cp "${BENCH_DIR}/fixtures/legacy/.zshrc" "${WORK}/legacy/.zshrc"

# The bx home starts as the baseline does, with the example configuration as
# its config repo and this account's answers. The external and the secret are
# switched off: one would clone over the network and the other needs a key,
# and neither is on the shell's startup path.
cp "${BENCH_DIR}/fixtures/baseline/.zshrc" "${WORK}/bx/.zshrc"
mkdir -p "${WORK}/bx/.config" "${WORK}/bx/.local/state/bx"
cp -R "${BENCH_DIR}/fixtures/bx" "${WORK}/bx/.config/bx"
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

# Invariant 6: the startup path spawns no process. Every file bx generated or
# attached a region to is searched for a command substitution; the hand-written
# zshrc is searched too, so a pattern that finds nothing is known to work.
# shellcheck disable=SC2016 # the patterns are literal on purpose.
SUBST='\$(' TICK='`'
spawns() { # spawns <file>...: lines, not comments, holding a command substitution
	cat "$@" | grep -v '^[[:space:]]*#' | grep -c -e "$SUBST" -e "$TICK" || true
}
generated="$(spawns "${WORK}/bx/.zshenv" "${WORK}/bx/.zshrc" "${WORK}/bx/.local/share/bx/"*.zsh)"
legacy="$(spawns "${WORK}/legacy/.zshrc")"
[ "$legacy" -eq 4 ] || {
	echo "error: the spawn count found ${legacy} of the hand-written zshrc's 4." >&2
	exit 1
}
[ "$generated" -eq 0 ] || {
	echo "FAIL: bx's startup files hold ${generated} line(s) that start a process:" >&2
	grep -n -e "$SUBST" -e "$TICK" "${WORK}/bx/.zshenv" "${WORK}/bx/.zshrc" \
		"${WORK}/bx/.local/share/bx/"*.zsh | grep -v ':[0-9]*:[[:space:]]*#' >&2 || true
	exit 1
}

run() { # run <name> <fixture>...
	name="$1"
	shift
	cmds=""
	for f in "$@"; do
		# `env` rather than a `VAR=… cmd` prefix: --shell=none execs the
		# command directly, so there is no shell to interpret an assignment.
		cmds="${cmds} -n ${f} 'env -i HOME=${WORK}/${f} PATH=${SEARCH} zsh -i -c exit'"
	done
	# Prime each fixture once so compinit's dump exists before timing.
	for f in "$@"; do
		env -i HOME="${WORK}/${f}" PATH="$SEARCH" zsh -i -c exit >/dev/null 2>&1 || true
	done
	eval "hyperfine --warmup 5 --min-runs ${RUNS} --shell=none \
		--export-json '${RESULTS}/${name}.json' ${cmds}" >/dev/null
}

echo "Measuring bx's generated startup files (budget ${BUDGET_MS} ms)..."
run overhead baseline bx

echo "Measuring net effect vs a hand-written zshrc..."
run net legacy bx

python3 - "$RESULTS" "$BUDGET_MS" "$generated" <<'PY'
import json, sys

results, budget, spawns = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])

labels = {"overhead": ["baseline", "bx"], "net": ["legacy", "bx"]}


def means(name):
    with open(f"{results}/{name}.json") as fh:
        data = json.load(fh)["results"]
    # The -n labels are not echoed back in the JSON, so pair by position: the
    # results are in the order the commands were given.
    return {label: r["mean"] * 1000 for label, r in zip(labels[name], data)}


over = means("overhead")
net = means("net")
overhead = over["bx"] - over["baseline"]
saved = net["legacy"] - net["bx"]

print()
print(f"  baseline   {over['baseline']:7.2f} ms")
print(f"  + bx       {over['bx']:7.2f} ms   after `bx apply` of the example")
print(f"  overhead   {overhead:7.2f} ms   (budget {budget:.2f} ms)")
print(f"  spawns     {spawns:7d}      process-starting lines bx generated")
print()
print(f"  legacy     {net['legacy']:7.2f} ms   eval \"$(tool init)\" per tool")
print(f"  bx         {net['bx']:7.2f} ms   the same tools, cached by bx")
print(f"  saved      {saved:7.2f} ms")
print()

if overhead > budget:
    print(f"FAIL: bx adds {overhead:.2f} ms, over its {budget:.2f} ms budget.")
    sys.exit(1)
print(f"OK: bx adds {overhead:.2f} ms, within its {budget:.2f} ms budget.")
PY
