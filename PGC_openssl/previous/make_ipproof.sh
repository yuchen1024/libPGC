#!/bin/bash
dir="/Users/chenyu/Documents/openssl-master"

g++ -std=c++11 -O2 test_ipproof.cpp -L ${dir} -l ssl -l crypto -o test_ipproof -I ${dir}