#!/bin/sh
dates=`ssh shadow ls malware` > /dev/null
for date in $dates
do
    count=`cat done.log | grep $date | wc -l`
    if [ $count -eq 0 ]
    then
        echo "$date" >> 'done.log'
        echo $date
    fi
done

