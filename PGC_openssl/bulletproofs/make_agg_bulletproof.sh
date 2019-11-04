#!/bin/bash
dir="/Users/chenyu/Documents/openssl-master"

g++ -std=c++11 -O2 test_agg_bulletproof.cpp -L ${dir} -l ssl -l crypto -o test_bulletproof -I ${dir}