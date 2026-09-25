# The shape of a hand-written zshrc: the baseline, with each tool the example
# configuration activates activated by a command substitution, so every shell
# start forks, execs, and parses the output.
autoload -Uz compinit && compinit -i

eval "$(mise activate zsh)"
eval "$(starship init zsh)"
eval "$(zoxide init zsh)"
eval "$(fzf --zsh)"
