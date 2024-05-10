#!/bin/bash

# Define the directory to search in.
SEARCH_DIR="/path/to/your/directory"

# Find all .gz files in the directory and its subdirectories,
# and decompress them with gunzip.
find "$SEARCH_DIR" -type f -name "*.gz" -exec gunzip {} \;

echo "Decompression complete."
