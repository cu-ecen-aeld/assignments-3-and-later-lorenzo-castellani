#!/bin/bash
#Author:  Lorenzo Castellani
# write.sh <writefile> <writestr>
#

if [ $# != 2 ]; then
	echo "use write.sh <writefile> <writestr>"
	exit 1
fi


dirs=$(echo $1 | tr "/" " ")
arr=()
n=0
for i in $dirs
do
	arr[n]=$i
	n=$[$n+1]
done

unset 'arr[${#arr[@]}-1]'

dir=""
for i in "${arr[@]}"
do
	dir="$dir/$i"
	mkdir -p $dir
done

echo $2 >$1


