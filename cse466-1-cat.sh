#!/bin/bash

LOG_DIR=/home/flyingfish # need to change this to ctf once move to server
# Variables are better than hard-coded values.
cd $LOG_DIR

MAN_TOOL=cat

mapfile -t my_array < <((man $MAN_TOOL | grep -Eio \ \ \-[a-zA-Z]))

my_array_len=${#my_array[@]}

for ((i=0; i<$(( $my_array_len)); i++ ))
do
	$MAN_TOOL /flag
	$MAN_TOOL "${my_array[$i]}" /flag
	$MAN_TOOL "${my_array[$i]}" /flag /asdf
	$MAN_TOOL "${my_array[$i]}" /flag /dev/stdout
done
echo $my_array_len
