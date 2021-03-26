#!/bin/bash
while getopts "c:" opt; do
  case ${opt} in
    c ) BUILD_TYPE=$OPTARG
      ;;
    \? ) echo "Usage: build.sh [-c <cmake-build-type>]"
      ;;
  esac
done

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ "$BUILD_TYPE" == "" ]; then
  BUILD_DIR=cmake-build
else
  BUILD_DIR=cmake-build-$BUILD_TYPE
fi

cmake -S "$DIR" -B "$BUILD_DIR" && make -C "$BUILD_DIR"
