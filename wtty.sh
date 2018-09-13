#!/bin/bash

function watch () {
    dev=/dev/pts/$1
    while [ -c $dev ]
    do
        var=;
        read  -n 1 -s var < $dev && echo -n $var > $dev && echo "$var on $dev" ;
    done
}

for tty in `ls -lA /dev/pts/ | awk '{dev = ($3 = "tty") ? $4 ":" $10 : "-"; print dev}' | grep tty | awk -F: '{print $2}'`;
do
    if [ `tty | awk -F/ '{print $4}'` -ne "$tty" ]; then watch "$tty" & fi
done

#TODO Support special characters (input, output)

