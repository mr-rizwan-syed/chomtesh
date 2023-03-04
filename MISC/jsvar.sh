#!/bin/bash

target=$1
echo -e "\e[1;33m$target\n\e[32m";
curl -s $target | grep -Eo "var [a-zA-Z0-9_]+" | sort -u | cut -d" " -f2 | awk 'length($1) >= 3 {print $1}'