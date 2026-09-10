# What bx generates instead: one source of a snippet whose zcompiled form zsh
# loads directly, with every activation already expanded into it.
autoload -Uz compinit && compinit -C -d "${ZDOTDIR}/.zcompdump"

# >>> bx >>>  (generated; edit bx.toml instead)
[[ -r ${BX_INIT:=$ZDOTDIR/bx-init.zsh} ]] && source $BX_INIT
# <<< bx <<<
