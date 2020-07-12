#!/usr/bin/env bash

printf "Content-Type: text/html\r\n\r\n"
echo "<pre>"
date
echo $$ $PPID
env
echo "</pre>"
