#!/bin/bash

usage(){
    echo "Usage: $0 <root-directory>"
    echo "Outputs simple HTML index file starting from <root-directory>"
}

if [ $# == 0 ]; then
  usage
  exit 0;
fi

ROOT=$1

IFS=$'\n'

i=0
echo "<!DOCTYPE html><html><body><ul>"
for filepath in `ls -a "$ROOT" | cat`; do
  path=`basename "$filepath"`
  echo "  <li><a href='$path'>$path</a></li>"
done
echo "</ul></body></html>"