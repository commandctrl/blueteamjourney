#!/bin/bash

# path to folder

search_dir="/Users/<user>/Downloads/<folder>"

# unzip all zips in folder path

find "$search_dir" -type f -name '*.zip' -exec unzip -d "{}_extracted" "{}" \;
