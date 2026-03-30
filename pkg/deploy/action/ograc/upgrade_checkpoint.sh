#!/bin/bash
function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

log "make full checkpoint..."
node_ip=$1
ogsql / as sysdba -q -c "alter system checkpoint global;"


if [[ $? = 0 ]]
then
        log "make full checkpoint success"
else
        log "make full checkpoint failed"
        exit 1
fi