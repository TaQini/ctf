#!/bin/bash
exec 2> /dev/null
cd /home/ctf/
#sleep 1

./stdbuf -i 0 -o 0 -e 0 ./nanoprint

