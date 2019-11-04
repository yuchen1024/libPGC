/**************************************************************************** 
this hpp initialize and finalize the global enviroment 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

// #include <iostream>
// using namespace std; 

/*
curve list
https://github.com/openssl/openssl/blob/4e6647506331fc3b3ef5b23e5dbe188279ddd575/include/openssl/obj_mac.h
int curve_id = NID_secp256k1
*/

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "../depends/print.hpp"

using namespace std;

EC_GROUP *group;
const BIGNUM *order; 
BN_CTX *bn_ctx;  

BIGNUM *bn_0; 
BIGNUM *bn_1; 
BIGNUM *bn_2; 


bool global_initialize(int curve_id)
{
    group = EC_GROUP_new_by_curve_name(curve_id); 
    // if(group == NULL){
    //     cout << "initiate curve error" << endl; 
    //     exit(0); 
    // }
    // get the group order
    order = EC_GROUP_get0_order(group);
    bn_ctx = BN_CTX_new();

    bn_0 = BN_new(); 
    BN_zero(bn_0); // set bn_0 = 0
    bn_1 = BN_new();  
    BN_one(bn_1); // set bn_1 = 1
    bn_2 = BN_new(); 
    BN_set_word(bn_2, 2); // set bn_2 = 2

    // #ifdef DEBUG
    // cout << "global initialization finished >>>" << endl;  
    // Print_Splitline('*');  
    // #endif

    return true;
}

bool global_finalize()
{
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    
    BN_free(bn_1); 
    BN_free(bn_2); 

    return true; 
}




