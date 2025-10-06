#!/bin/bash

SESSION_NAME="my_three_pane_session"

#brew install reattach-to-user-namespace
# Enable mouse mode for pane selection, resizing, and scrolling
set -g mouse on

# Use vim keybindings in copy mode
setw -g mode-keys vi

# Enable clipboard integration
set -g set-clipboard on

# Copy to macOS clipboard using pbcopy with the mouse
bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "reattach-to-user-namespace pbcopy"

# Copy to macOS clipboard using pbcopy with `y`
bind-key -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "reattach-to-user-namespace pbcopy"


# --- Get terminal dimensions for proportional panels ---
set -- $(stty size) # $1 = rows, $2 = columns
TERMINAL_ROWS=$(($1 - 1)) # Account for tmux status line
TERMINAL_COLUMNS=$2

# --- Create new detached session with specific dimensions ---
tmux -2 new-session -d -s "$SESSION_NAME" -x "$TERMINAL_COLUMNS" -y "$TERMINAL_ROWS" -n "ThreePaneLayout"

# --- Configure Scrolling and Mouse Support ---
tmux set-window-option -t "$SESSION_NAME:ThreePaneLayout" mode-keys vi
tmux set-option -t "$SESSION_NAME:ThreePaneLayout" mouse on

# --- Setup the 3-pane proportional layout ---

# 1. Split the initial window (pane 0) vertically to create the wide bottom pane.
#    Let's say the bottom pane takes 30% of the height, leaving 70% for the top section.
#    The new pane (pane 1, which will become our wide bottom pane) is created at the bottom.
tmux split-window -v -p 30 -t "$SESSION_NAME:ThreePaneLayout.0" # -p 30 means the *new* pane (bottom) is 30% height

# 2. Select the top pane (pane 0) to start creating the two top panes.
tmux select-pane -t "$SESSION_NAME:ThreePaneLayout.0"

# 3. Split the top pane horizontally, so the new pane (pane 2) is on the right
#    and takes 50% of the width, leaving pane 0 on the top-left also at 50%.
tmux split-window -h -p 50 -t "$SESSION_NAME:ThreePaneLayout.0"

# 4. (Optional) Select the bottom wide pane to make it the active pane on startup,
#    or select the top-left pane (0) or top-right pane (2) if preferred.
tmux select-pane -t "$SESSION_NAME:ThreePaneLayout.1"


# --- Attach to the session ---
tmux attach -t "$SESSION_NAME"
