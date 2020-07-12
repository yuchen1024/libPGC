/**************************************************************************** 
this hpp initialize and finalize the global enviroment 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

/*
curve list
https://github.com/openssl/openssl/blob/4e6647506331fc3b3ef5b23e5dbe188279ddd575/include/openssl/obj_mac.h
int curve_id = NID_secp256k1
*/


#ifndef __GLOBAL__
#define __GLOBAL__

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <thread>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace std;

/* global constants */
const size_t POINT_LEN = 33; // the compressed expression of an EC points is 33 bytes
const size_t BN_LEN = 32;    // assume base field and scalar field are less than 2^256 (stored in 32-bytes)

/* global variables of OpenSSL*/
EC_GROUP *group;
const BIGNUM *order; 
const EC_POINT *generator; 
BN_CTX *bn_ctx;  

BIGNUM *BN_0; 
BIGNUM *BN_1; 
BIGNUM *BN_2; 

/* initialize global variables */
bool global_initialize(int curve_id)
{
    #ifdef DEBUG
        cout << "initialize global environment" << endl; 
    #endif
    group = EC_GROUP_new_by_curve_name(curve_id); 
    generator = EC_GROUP_get0_generator(group);
    order = EC_GROUP_get0_order(group);
    bn_ctx = BN_CTX_new();
    if (group == NULL || order == NULL || bn_ctx == NULL) return false; 
    EC_GROUP_precompute_mult((EC_GROUP*) group, bn_ctx); // pre-compute the table of g     
    
    #ifdef DEBUG
    if(EC_GROUP_have_precompute_mult((EC_GROUP*)group)){ 
        cout << "precompute enable" << endl;
    } 
    else{
        cout << "precompute disable" << endl;
    } 
    #endif

    BN_0 = BN_new(); 
    BN_zero(BN_0); // set bn_0 = 0
    BN_1 = BN_new();  
    BN_one(BN_1); // set bn_1 = 1
    BN_2 = BN_new(); 
    BN_set_word(BN_2, 2); // set bn_2 = 2
    if (BN_0 == NULL || BN_1 == NULL || BN_2 == NULL) return false; 
    
    return true;
}

/* finalize global variables */ 
void global_finalize()
{
    #ifdef DEBUG
        cout << "finalize global environment" << endl; 
    #endif
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    
    BN_free(BN_0); 
    BN_free(BN_1); 
    BN_free(BN_2); 
}

#endif




