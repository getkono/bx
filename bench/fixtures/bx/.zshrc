# Baseline + bx's own managed block, and nothing else. The delta against
# `baseline` is bx's overhead, which the 5 ms budget applies to.
autoload -Uz compinit && compinit -i -d "${ZDOTDIR}/.zcompdump"

# >>> bx >>>  (generated; edit bx.toml instead)
[[ -r ${BX_INIT:=$ZDOTDIR/bx-init.zsh} ]] && source $BX_INIT
# <<< bx <<<
