#!/bin/bash

# Define the session name
SESSION_NAME="2x3_layout"

# Check if the session already exists
tmux has-session -t "${SESSION_NAME}" 2>/dev/null

if [ $? != 0 ]; then
  # Create a new detached session
  tmux new-session -d -s "${SESSION_NAME}"

  # Split the first pane vertically to create a total of 2 rows
  tmux split-window -v -t "${SESSION_NAME}:0.0"

  # Split each of the first two panes horizontally to create 2 columns
  # This targets pane 0.0 (top left)
  tmux split-window -h -t "${SESSION_NAME}:0.0"
  # This targets pane 0.1 (bottom left)
  tmux split-window -h -t "${SESSION_NAME}:0.1"

  # Split the two newly created right panes to get the third row
  # This targets pane 0.2 (top right)
  tmux split-window -v -t "${SESSION_NAME}:0.2"

  # Apply the tiled layout to ensure all panes are equal
  tmux select-layout -t "${SESSION_NAME}:0" tiled
fi

# Attach to the session
tmux attach-session -t "${SESSION_NAME}"
