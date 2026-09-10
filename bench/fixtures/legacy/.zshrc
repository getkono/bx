# The shape of a hand-written zshrc: each tool activated with a command
# substitution, so every shell start forks, execs, and parses the output.
autoload -Uz compinit && compinit -i -d "${ZDOTDIR}/.zcompdump"

eval "$(starship init zsh)"
eval "$(zoxide init zsh)"
eval "$(mise activate zsh)"
eval "$(fzf --zsh)"
