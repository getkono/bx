#!/bin/sh
# Measure bx's contribution to zsh startup against its budget.
#
# bx runs at every shell start, so "fast enough to forget" is a product
# requirement, and a requirement that is not measured is a requirement that
# regresses. This is the external profile: it never sources the developer's real
# config, so the number is about bx, not about the machine it ran on.
#
# Two measurements, for two different questions:
#
#   overhead  baseline vs baseline+bx. This is what bx costs. Gated at
#             BX_BUDGET_MS (default 5).
#   net       a hand-written `eval "$(tool init)"` zshrc vs the equivalent bx
#             generates. Reported, never gated: it depends on which tools are
#             integrated, so a threshold would be arbitrary.
#
# Environment:
#   BX_BUDGET_MS  overhead budget in milliseconds (default: 5)
#   BX_BENCH_RUNS minimum hyperfine runs per fixture (default: 50)

set -eu

BUDGET_MS="${BX_BUDGET_MS:-5}"
RUNS="${BX_BENCH_RUNS:-50}"

cd "$(dirname "$0")"
BENCH_DIR="$(pwd)"
RESULTS="${BENCH_DIR}/results"

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

# Hermetic: a scratch HOME so nothing in the developer's own home is read, and
# the stub tools ahead of anything real on PATH.
WORK="$(mktemp -d)"
# shellcheck disable=SC2064 # WORK is expanded now, on purpose.
trap "rm -rf '$WORK'" EXIT INT TERM

for f in baseline bx legacy generated; do
	cp -r "${BENCH_DIR}/fixtures/${f}" "${WORK}/${f}"
done
# legacy and generated must describe the same shell, so they share a snippet.
cp "${BENCH_DIR}/fixtures/bx/bx-init.zsh" "${WORK}/generated/bx-init.zsh"
# Inline the activations bx would have cached, then compile the result. zsh's
# `source` prefers a `.zwc` that is newer than its source (see zshbuiltins), so
# this is what the shell actually loads.
for t in starship zoxide mise fzf; do
	"${BENCH_DIR}/stubs/${t}" >>"${WORK}/generated/bx-init.zsh"
done
for f in bx generated; do
	zsh -fc "zcompile ${WORK}/${f}/bx-init.zsh" || {
		echo "error: zcompile failed for ${f}." >&2
		exit 1
	}
done

PATH="${BENCH_DIR}/stubs:${PATH}"
export PATH
HOME="$WORK"
export HOME

run() { # run <name> <fixture>...
	name="$1"
	shift
	set -- "$@"
	cmds=""
	for f in "$@"; do
		# `env` rather than a `VAR=… cmd` prefix: --shell=none execs the
		# command directly, so there is no shell to interpret an assignment.
		cmds="${cmds} -n ${f} 'env ZDOTDIR=${WORK}/${f} zsh -i -c exit'"
	done
	# Prime each fixture once so compinit's dump exists before timing.
	for f in "$@"; do
		ZDOTDIR="${WORK}/${f}" zsh -i -c exit >/dev/null 2>&1 || true
	done
	eval "hyperfine --warmup 5 --min-runs ${RUNS} --shell=none \
		--export-json '${RESULTS}/${name}.json' ${cmds}" >/dev/null
}

echo "Measuring bx overhead (budget ${BUDGET_MS} ms)..."
run overhead baseline bx

echo "Measuring net effect vs a hand-written zshrc..."
run net legacy generated

python3 - "$RESULTS" "$BUDGET_MS" <<'PY'
import json, sys

results, budget = sys.argv[1], float(sys.argv[2])

labels = {"overhead": ["baseline", "bx"], "net": ["legacy", "generated"]}


def means(name):
    with open(f"{results}/{name}.json") as fh:
        data = json.load(fh)["results"]
    # The -n labels are not echoed back in the JSON, so pair by position: the
    # results are in the order the commands were given.
    return {label: r["mean"] * 1000 for label, r in zip(labels[name], data)}


over = means("overhead")
net = means("net")
overhead = over["bx"] - over["baseline"]
saved = net["legacy"] - net["generated"]

print()
print(f"  baseline   {over['baseline']:7.2f} ms")
print(f"  + bx       {over['bx']:7.2f} ms")
print(f"  overhead   {overhead:7.2f} ms   (budget {budget:.2f} ms)")
print()
print(f"  legacy     {net['legacy']:7.2f} ms   eval \"$(tool init)\" per tool")
print(f"  generated  {net['generated']:7.2f} ms   bx snippet, zcompiled")
print(f"  saved      {saved:7.2f} ms")
print()

if overhead > budget:
    print(f"FAIL: bx adds {overhead:.2f} ms, over its {budget:.2f} ms budget.")
    sys.exit(1)
print(f"OK: bx adds {overhead:.2f} ms, within its {budget:.2f} ms budget.")
PY
