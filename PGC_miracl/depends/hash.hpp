/****************************************************************************
this hpp implements hash functions 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include "ecn.h"
#include "zzn.h"

#define HASH_OUTPUT_LEN 32  // hash output = 256-bit string

/*
    H: Z^n ==> Zq
    H(Z1, ..., Zn) mod q
*/
Big Hash_ZZn_ZZ(const vector<Big> vec_a)
{ 
    char hash_output[HASH_OUTPUT_LEN]; 
    Big x;
    sha256 sh;
    shs256_init(&sh);

    for (int i = 0; i < vec_a.size(); i++)
    {
        x = vec_a[i]; 
        while (x > 0)
        {
            shs256_process(&sh, x%256);
            x /= 256;
        }
    }

    shs256_hash(&sh, hash_output);
    Big hash_value = from_binary(HASH_OUTPUT_LEN, hash_output);
    return hash_value%q;
}

/*
    H: G^n ==> Zq
    H(A1, ..., An) mod q
*/
Big Hash_GGn_ZZ(const vector<ECn> vec_g)
{ 
    char hash_output[HASH_OUTPUT_LEN]; 
    Big x, y;
    sha256 sh;
    shs256_init(&sh);

    for (int i = 0; i < vec_g.size(); i++)
    {
        vec_g[i].get(x, y);
        while (x > 0)
        {
            shs256_process(&sh, x%256);
            x /= 256;
        }
        while (y > 0)
        {
            shs256_process(&sh, y%256);
            y /= 256;
        }
    }

    shs256_hash(&sh, hash_output);
    Big hash_value = from_binary(HASH_OUTPUT_LEN, hash_output);
    return hash_value%q;
}

/*
    H(msg_file) mod q 
*/
Big Hash_File_ZZ(const string msg_file)
{ 
    char ch; 
    char hash_output[HASH_OUTPUT_LEN]; 
 
    sha256 sh;
    shs256_init(&sh);

    ifstream fin; 
    fin.open(msg_file);
    if(!fin){
        throw "cannot open the input file"; 
    }

    forever 
    { /* read in bytes from message file */
        if (fin.eof()) break;
        fin >> ch; 
        shs256_process(&sh, ch);
    }
    fin.close(); 

    shs256_hash(&sh, hash_output);

    Big hash_value = from_binary(HASH_OUTPUT_LEN, hash_output);
    return hash_value%q;  
}

/*
    H(str) mod q 
*/
Big Hash_String_ZZ(const string str)
{ 
    char ch; 
    char hash_output[HASH_OUTPUT_LEN]; 
 
    sha256 sh;
    shs256_init(&sh);

    for(int i = 0; i < str.length(); i++) 
    { 
        shs256_process(&sh, str[i]);
    }
    
    shs256_hash(&sh, hash_output);

    Big hash_value = from_binary(HASH_OUTPUT_LEN, hash_output);
    return hash_value%q;  
}

