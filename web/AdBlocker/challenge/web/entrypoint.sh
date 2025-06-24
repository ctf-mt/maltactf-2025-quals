#!/bin/sh

(
  while true; do
    echo "[$(date +'%T')]> Cleaning old chromium processes...";
    ps -o pid,etime,comm | awk '$3 ~ /chrom/ && $1 != 1 && $2 !~ /^0:/ {print $1}' | xargs -r kill -9;

    echo "[$(date +'%T')]> Cleaning /tmp folders older than 1 minute...";
    find /tmp -maxdepth 1 -user ctfuser -mmin +1 -print0 | xargs -r -0 rm -rf

    sleep 180;
  done
) &

exec node server.js 