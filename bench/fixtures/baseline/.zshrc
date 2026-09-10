# Baseline: an interactive zsh with no bx and no tool integrations at all.
# Everything the other fixtures measure is relative to this.
autoload -Uz compinit && compinit -i -d "${ZDOTDIR}/.zcompdump"
