#!/bin/bash

usage(){
    echo "Usage:"
    echo -e "\t $0 [-v] <rtsp-uri>"
    echo -e "\t $0 [-v] <host-port> id <id>"
    echo -e "\t $0 [-v] <host-port> name <name>"
    echo -e "\t -v \t output RTSP header"
    echo "Performs a quick and dirty rtsp stream describe query to retrieve SDPs."
    echo "The id/name form conform to RAVENNA URIs."
    echo "Returns 0 iff RTSP result code is 200 (ie OK)"
}

VERBOSE=0

while getopts "vh" o; do
  case "${o}" in
    v)
      VERBOSE=1
      ;;

    h)
      usage
      exit 0
      ;;

    *)
      echo "invalid option $o"
      exit 0
      ;;
  esac
done
shift $((OPTIND-1))

if [ $# == 0 ]; then
  usage
  exit 0;
fi

if [ $# == 1 ]; then
  if [ ${#1} -le 7 ] || [ "${1:0:7}" != "rtsp://" ]; then
    echo "invalid uri $1"
    exit 1;
  fi
  URI=${1// /%20}
  TMP=${1:7}
  HOSTPORT=${TMP%%/*}
elif [ $# == 3 ]; then
  if [ "$2" != "id" ] && [ "$2" != "name" ]; then
    echo "invalid option $2"
    exit 1;
  fi
  URI="rtsp://$1/by-$2/$3"
  HOSTPORT="$1"
else
  exit 0;
fi

RES=$(echo -ne "DESCRIBE $URI RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n" | socat -d - "TCP:$HOSTPORT")

IFS=$'\r\n'
for line in $RES
do
  if [ "$BODY" == "1" ] || [ "$VERBOSE" == "1" ]; then
    echo -e "$line"
  elif [ "$line" == "" ]; then
    BODY=1
  fi
done;


CODE=${RES%%$'\r\n'*}

if [[ $CODE =~ ^RTSP/([12]{1}).0\ 200\ OK$ ]]; then
  exit 0
else
  exit 1
fi
