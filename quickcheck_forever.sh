#!/usr/bin/env bash

export QUICKCHECK_TESTS=10000000

while true
do
    cargo test --no-default-features --features bad_crypto prop_
    if [[ x$? != x0 ]] ; then
        exit $?
    fi
done
