#!/usr/bin/env bash

while true
do
    cargo test --release prop_
    if [[ x$? != x0 ]] ; then
        exit $?
    fi
done
