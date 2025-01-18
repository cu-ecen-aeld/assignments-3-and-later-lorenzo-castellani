#!/bin/sh
#Author:  Lorenzo Castellani
# finder.sh <filesdir> <searchstr>
#

if [ $# != 2 ] || ! [ -d $1 ]; then
	echo "use finder.sh <filesdir> <searchstr>"
	exit 1
fi

result=$( grep -rc $2 $1/* )
numfile=0
numfound=0
for i in $result
do
    found=$(echo $i | awk -F':' '{print $2}')
    numfound=$(( numfound + $found ))
    numfile=$(($numfile + 1))
done
echo "The number of files are $numfile and the number of matching lines are $numfound"
