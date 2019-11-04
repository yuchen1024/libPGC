/****************************************************************************
this hpp implements hash functions 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include <openssl/sha.h>
#include <vector>

const size_t HASH_OUTPUT_LEN = 32;  // hash output = 256-bit string

/*
    H(str) mod q 
*/
void Hash_String_ZZ(BIGNUM*y, string str)
{ 
    unsigned char hash_output[HASH_OUTPUT_LEN]; 
 
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    char *buffer = const_cast<char *>(str.data()); 
    SHA256(reinterpret_cast<unsigned char*>(buffer), str.size(), hash_output);

    BN_bin2bn(hash_output, HASH_OUTPUT_LEN, y);
    BN_nnmod(y, y, order, bn_ctx);
}

