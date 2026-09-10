#!/bin/sh
# Emit a block of zsh of a representative size for tool $1. The content must be
# *parsed* by zsh to be a fair measurement, so it is real syntax, not comments.
set -eu
name="$1"
lines="$2"
printf '%s\n' "__bench_${name}_loaded=1"
i=0
while [ "$i" -lt "$lines" ]; do
	cat <<-ZSH
		__bench_${name}_fn_${i}() {
		  local a="value-${i}" b
		  case "\$a" in
		    value-*) b="\${a#value-}" ;;
		    *) b=0 ;;
		  esac
		  [[ -n "\$b" ]] && print -r -- "\$b" >/dev/null
		}
	ZSH
	i=$((i + 1))
done
printf '%s\n' "autoload -Uz __bench_${name}_fn_0"
