#!/bin/bash
# Date: Wed Dec 22 16:29:50 2021
# Author: January


files=$(find .)
for file in ${files[*]}
do
    path=${file%/*}
    filename=${file##*/}
    if [ "$file" == "${file%.h}" ];then
        continue
    fi
    des_path=include/libecc/${path#.}
    [ -d "$des_path" ] || mkdir -p $des_path
    mv $file "$des_path/$filename"
done