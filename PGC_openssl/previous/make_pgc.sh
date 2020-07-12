#!/bin/bash
dir="/Users/chenyu/Documents/openssl-master"

g++ -std=c++11 test_pgc.cpp -L ${dir} -l ssl -l crypto -o test_pgc -I ${dir}