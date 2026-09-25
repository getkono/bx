#!/bin/sh
# Emit a block of shell of a representative size for tool $1. The content must be
# *parsed* by the shell to be a fair measurement, so it is real syntax, not
# comments. It is syntax zsh and bash both run without complaint, because the
# example configuration activates each stub for both shells.
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
		  [[ -n "\$b" ]] && printf '%s\n' "\$b" >/dev/null
		}
	ZSH
	i=$((i + 1))
done
printf '%s\n' "typeset -f __bench_${name}_fn_0 >/dev/null"
