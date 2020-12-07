#!/bin/bash
cd /home/ctf
stdbuf -i 0 -o 0 -e 0 /usr/bin/timeout 90 ./qtar
