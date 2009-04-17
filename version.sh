#!/bin/sh

if git describe > version.num.tmp
then
    mv version.num.tmp version.num
    echo "m4_define([VERSION_NUMBER], [`tr -d '\n' < version.num`])" \
        > version.m4
else
    rm version.num.tmp
fi
