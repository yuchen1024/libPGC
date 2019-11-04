#!/bin/bash
dir="../depends/MIRACL"
g++ -std=c++11 test_agg_bulletproof.cpp ${dir}/zzn.cpp ${dir}/big.cpp ${dir}/ecn.cpp ${dir}/miracl.a -o test_agg_bulletproof -I ${dir}