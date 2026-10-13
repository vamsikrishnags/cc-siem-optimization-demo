#!/bin/sh
# Called by Zeek after rotating a log: $1 is the rotated file name.
# Give Fluent Bit time to finish reading it, then remove it.
( sleep 60; rm -f "/logs/$1" "$1" ) &
