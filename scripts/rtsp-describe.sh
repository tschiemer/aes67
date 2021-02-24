#!/bin/bash

if [ $# == 1 ]; then
  if [ ${#1} -le 7 ] || [ ${1:0:7} != "rtsp://" ]; then
    echo "invalid uri $1"
    exit 1;
  fi
  URI=$1
  TMP=${1:7}
  HOSTPORT=${TMP%%/*}
elif [ $# == 3 ]; then
  if [ "$2" != "id" ] && [ "$2" != "name" ]; then
    echo "invalid option $2"
    exit 1;
  fi
  URI="rtsp://$1/by-$2/$3"
  HOSTPORT=$1
else
  echo "Usage:"
  echo -e "\t $0 <rtsp-uri>"
  echo -e "\t $0 <host-port> id <id>"
  echo -e "\t $0 <host-port> name <name>"
  exit 0;
fi

echo -ne "DESCRIBE $URI RTSP/1.0\r\nCSeq: 1\r\n\r\n" | socat - TCP:$HOSTPORT