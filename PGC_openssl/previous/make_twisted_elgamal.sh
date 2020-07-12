#!/bin/bash
dir="/Users/chenyu/Documents/openssl-master"

g++ -std=c++11 -pthread -O3 test_twisted_elgamal.cpp -L ${dir} -l ssl -l crypto -o test_enc -I ${dir}