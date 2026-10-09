# Baseline: an interactive bash with no bx and no tool integrations at all — the
# account's own bashrc before bx applies anything. The bx fixture starts from this
# same file, so the difference between the two is what bx's generated files cost.
[[ $- == *i* ]] || return
