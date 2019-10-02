#!/bin/bash

test_file=$1 # Pass the test file as parameter
memcached_folder=$2 # Pass the memcached source folder as parameter
memcached_test_folder=$memcached_folder/t

currdir=$(pwd)
cp $test_file $memcached_test_folder
cd $memcached_folder
prove t/$test_file
rm -f $memcached_test_folder/$test_file
cd $currdir
