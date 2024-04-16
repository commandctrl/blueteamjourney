#!/bin/bash

# path to folder

search_dir="/Users/<user>/Downloads/<folder>"

# unzip all zips in folder path ignoring duplicates

find "$search_dir" -type f -name '*.zip' | while read zipFile; do
  extractDir="${zipFile}_extracted" 
  
  if [ ! -d "$extractDir" ]; then
    unzip -d "$extractDir" "$zipFile" 
  else 
    echo "Skipping extraction of $zipFile as $extractDir already exists."
  fi
done
