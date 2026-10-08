# The shape of a hand-written bashrc: the baseline, with each tool the example
# configuration activates activated by a command substitution, so every shell
# start forks, execs, and parses the output.
[[ $- == *i* ]] || return

eval "$(mise activate bash)"
eval "$(starship init bash)"
eval "$(zoxide init bash)"
eval "$(fzf --bash)"
