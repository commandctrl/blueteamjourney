#!/bin/bash

# Check if a path argument was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <target path>"
  exit 1
fi

# Use the first command line argument as the directory to search in.
SEARCH_DIR="$1"

# Find all .gz files in the directory and its subdirectories,
# and decompress them with gunzip in verbose mode.
find "$SEARCH_DIR" -type f -name "*.gz" -exec gunzip -v {} \;

echo "Decompression complete."
