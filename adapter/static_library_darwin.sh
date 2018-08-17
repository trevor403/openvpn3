#!/bin/bash

libs=()

function push() {
    libs=("${libs[@]}" $1)
}

outputName=$1
shift;

push "process.o"
push "$O3/deps/mbedtls/mbedtls-osx/library/libmbedtls.a"
push "$O3/deps/lz4/lz4-osx/lib/liblz4.a"


libtool -static -o $outputName ${libs[@]}