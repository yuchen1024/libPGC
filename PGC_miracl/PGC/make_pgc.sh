#!/bin/bash
dir="../depends/MIRACL"
g++ -std=c++11 test_pgc.cpp ${dir}/zzn.cpp ${dir}/big.cpp ${dir}/ecn.cpp ${dir}/miracl.a -o test_pgc -I ${dir}