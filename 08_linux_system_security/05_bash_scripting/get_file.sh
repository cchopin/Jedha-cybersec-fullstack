#!/usr/bin/env bash

function usage() {
  echo "Usage:"
  echo "  get_file.sh directory"
  echo
  echo "Examples:"
  echo "  get_file.sh /tmp"

  exit 1
}

function count {
    directory=$1
    total_files=0
    world_writable=0
    while read line; do
       ((total_files++))
       stat -f "%N %Su %Sm" "$line"
       perm=$(stat -f "%p" "$line")
       other=$(( perm % 10 ))
       if [ $(( other & 2 )) -ne 0 ]; then
           echo "world-writable!"
           ((world_writable++))
       fi
    done < <(find "$directory" -mtime -7 -type f)
    echo "total_files :" $total_files
    echo "world_writable :" $world_writable
}

if ! [[ -z "$1" ]]; then
    if [[ -d "$1" ]]; then
        count "$1"
    fi
else
    usage
fi
