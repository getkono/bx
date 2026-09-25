# Baseline: an interactive zsh with no bx and no tool integrations at all — the
# account's own zshrc before bx applies anything. The bx fixture starts from this same
# file, so the difference between the two is what bx's generated files cost.
autoload -Uz compinit && compinit -i
