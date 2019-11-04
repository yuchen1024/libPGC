/****************************************************************************
this hpp implements twisted ElGamal encrypt scheme
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "stdio.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <vector>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "calculate_dlog.hpp"

uint64_t MSG_LEN = 32; 
BIGNUM* bn_M; // the range of message space

// define the structure of PP
struct Twisted_ElGamal_PP
{
    EC_POINT* g; 
    EC_POINT* h; // two random generators 
};

// define the structure of keypair
struct Twisted_ElGamal_KP
{
    EC_POINT* pk;  // define pk
    BIGNUM* sk;    // define sk
};

// define the structure of ciphertext
struct Twisted_ElGamal_CT
{
    EC_POINT* X; // X = pk^r 
    EC_POINT* Y; // Y = g^m h^r 
};

// define the structure of two-recipients one-message ciphertext (MR denotes multiple recipients)
struct MR_Twisted_ElGamal_CT
{
    EC_POINT* X1; // X = pk1^r
    EC_POINT* X2; // X = pk2^r 
    EC_POINT* Y; // Y = G^m H^r 
};

void Twisted_ElGamal_KP_Init(Twisted_ElGamal_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void Twisted_ElGamal_CT_Init(Twisted_ElGamal_CT &CT)
{
    CT.X = EC_POINT_new(group); 
    CT.Y = EC_POINT_new(group);
}

void MR_Twisted_ElGamal_CT_Init(MR_Twisted_ElGamal_CT &CT)
{
    CT.X1 = EC_POINT_new(group);
    CT.X2 = EC_POINT_new(group);  
    CT.Y = EC_POINT_new(group);
}

void Twisted_ElGamal_PP_Free(Twisted_ElGamal_PP &pp)
{ 
    EC_POINT_free(pp.h);
    BN_free(bn_M); 
}

void Twisted_ElGamal_KP_Free(Twisted_ElGamal_KP &keypair)
{
    EC_POINT_free(keypair.pk); 
    BN_free(keypair.sk);
}

void Twisted_ElGamal_CT_Free(Twisted_ElGamal_CT &CT)
{
    EC_POINT_free(CT.X); 
    EC_POINT_free(CT.Y);
}

void MR_Twisted_ElGamal_CT_Free(MR_Twisted_ElGamal_CT &CT)
{
    EC_POINT_free(CT.X1);
    EC_POINT_free(CT.X2); 
    EC_POINT_free(CT.Y);
}

void Print_Twisted_ElGamal_PP(Twisted_ElGamal_PP &pp)
{
    print_gg(pp.g, "pp.g"); 
    print_gg(pp.h, "pp.h"); 
} 

void Print_Twisted_ElGamal_KP(Twisted_ElGamal_KP &keypair)
{
    print_gg(keypair.pk, "pk"); 
    print_zz(keypair.sk, "sk"); 
} 


void Print_Twisted_ElGamal_CT(Twisted_ElGamal_CT &CT)
{
    print_gg(CT.X, "CT.X");
    print_gg(CT.Y, "CT.Y");
} 

void Print_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT &CT)
{
    print_gg(CT.X1, "CT.X1");
    print_gg(CT.X2, "CT.X2");
    print_gg(CT.Y, "CT.Y");
} 

void Serialize_Twisted_ElGamal_CT(Twisted_ElGamal_CT &CT, ofstream& fout)
{
    Serialize_GG(CT.X, fout); 
    Serialize_GG(CT.Y, fout); 
} 

void Deserialize_Twisted_ElGamal_CT(Twisted_ElGamal_CT &CT, ifstream& fin)
{
    Deserialize_GG(CT.X, fin); 
    Deserialize_GG(CT.Y, fin); 
} 


void Serialize_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT &CT, ofstream& fout)
{
    Serialize_GG(CT.X1, fout); 
    Serialize_GG(CT.X2, fout);
    Serialize_GG(CT.Y,  fout); 
} 

void Deserialize_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT &CT, ifstream& fin)
{
    Deserialize_GG(CT.X1, fin); 
    Deserialize_GG(CT.X2, fin); 
    Deserialize_GG(CT.Y, fin); 
}

// Setup algorithm
void Twisted_ElGamal_Setup(Twisted_ElGamal_PP &pp)
{ 
    pp.g = (EC_POINT*)EC_GROUP_get0_generator(group);
    pp.h = EC_POINT_new(group);
    //random_gg(pp.h); 

    // generate pp.h via deterministic manner in order to test Shanks's algorithm
    BIGNUM* e = BN_new(); 
    vector<EC_POINT*> vec_A(1);
    vec_A[0] = pp.g;  
    Hash_GGn_ZZ(e, vec_A); 
    EC_POINT_mul(group, pp.h, NULL, pp.g, e, bn_ctx); // set h = g^e
    BN_free(e); 

    EC_GROUP_precompute_mult((EC_GROUP*)group, bn_ctx); // pre-compute the table of g 

    #ifdef DEBUG
    cout << "generate the global public parameters >>>" << endl; 
    Print_Twisted_ElGamal_PP(pp); 
    if(EC_GROUP_have_precompute_mult((EC_GROUP*)group)){ 
        cout << "precompute enable" << endl;
    } 
    else{
        cout << "precompute disable" << endl;
    } 
    #endif

    // set the message space to 2^{MSG_LEN}
    bn_M = BN_new();   
    BN_set_word(bn_M, long(pow(2, MSG_LEN))); 
    
    #ifdef DEBUG
    cout << "message space = [0," << long(pow(2, MSG_LEN)-1) << "]" << endl; 
    #endif

    Serialize_Map(pp.h, "point_2_index.table"); // generate and serialize the point_2_index table
    Load_Map("point_2_index.table");            // load the table from file
}

// KeyGen algorithm
void Twisted_ElGamal_KeyGen(Twisted_ElGamal_PP &pp, Twisted_ElGamal_KP &keypair)
{ 
    random_zz(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

    #ifdef DEBUG
    cout << "key generation finished >>>" << endl;  
    Print_Twisted_ElGamal_KP(keypair); 
    #endif
}

// Encryption algorithm: compute CT = Enc(pk, m; r)
void Twisted_ElGamal_Enc(Twisted_ElGamal_PP &pp, 
                         EC_POINT* &pk, 
                         BIGNUM* &m, 
                         Twisted_ElGamal_CT &CT)
{ 
    // generate the random coins 
    BIGNUM *r = BN_new(); 
    random_zz(r);

    // begin encryption
    EC_POINT_mul(group, CT.X, NULL, pk, r, bn_ctx); // X = pk^r
    EC_POINT_mul(group, CT.Y, r, pp.h, m, bn_ctx);  // Y = g^r h^m
    
    BN_free(r); 

    #ifdef DEBUG
        cout << "twisted ElGamal encryption finishes >>>"<< endl;
        Print_Twisted_ElGamal_CT(CT); 
    #endif
}

// Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness
void Twisted_ElGamal_Enc(Twisted_ElGamal_PP &pp, 
                         EC_POINT* &pk, 
                         BIGNUM* &m, 
                         BIGNUM* &r, 
                         Twisted_ElGamal_CT &CT)
{ 
    // begin encryption
    EC_POINT_mul(group, CT.X, NULL, pk, r, bn_ctx); // X = pk^r
    EC_POINT_mul(group, CT.Y, r, pp.h, m, bn_ctx); // Y = g^r h^m

    #ifdef DEBUG
        cout << "twisted ElGamal encryption finishes >>>"<< endl;
        Print_Twisted_ElGamal_CT(CT); 
    #endif
}

// Decryption algorithm: compute m = Dec(sk, CT)
bool Twisted_ElGamal_Dec(Twisted_ElGamal_PP &pp, 
                         BIGNUM* &sk, 
                         Twisted_ElGamal_CT &CT, 
                         BIGNUM* &m)
{ 
    //begin decryption  
    BIGNUM *sk_inverse = BN_new(); 
    BN_mod_inverse(sk_inverse, sk, order, bn_ctx);  // compute the inverse of sk in Z_q^* 

    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk_inverse, bn_ctx); // M = X^{sk^{-1}} = g^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -g^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = h^m

    //Brute_Search(m, pp.h, M);
    bool success; 
    //success = Preprocessing_Parallel_Shanks(m, pp.h, M); // use Shanks's algorithm to decrypt
    success = Preprocessing_Shanks(m, pp.h, M); // use Shanks's algorithm to decrypt

    BN_free(sk_inverse); 
    EC_POINT_free(M);
    return success;  
}


// Refresh ciphertext CT with given random coins r 
void Twisted_ElGamal_Refresh(Twisted_ElGamal_PP &pp, 
                             EC_POINT* &pk, 
                             BIGNUM* &sk, 
                             Twisted_ElGamal_CT &CT, 
                             Twisted_ElGamal_CT &CT_new, 
                             BIGNUM* &r)
{ 
    // begin partial decryption  
    BIGNUM *sk_inverse = BN_new(); 
    BN_mod_inverse(sk_inverse, sk, order, bn_ctx);  // compute the inverse of sk in Z_q^* 

    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk_inverse, bn_ctx); // M = X^{sk^{-1}} = g^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -g^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = h^m

    // begin re-encryption with the given randomness 
    EC_POINT_mul(group, CT_new.X, NULL, pk, r, bn_ctx); // CT_new.X = pk^r 
    EC_POINT_mul(group, CT_new.Y, r, NULL, NULL, bn_ctx); // CT_new.Y = g^r 

    EC_POINT_add(group, CT_new.Y, CT_new.Y, M, bn_ctx);    // M = h^m

    #ifdef DEBUG
        cout << "refresh ciphertext succeeds >>>"<< endl;
        Print_Twisted_ElGamal_CT(CT_new); 
    #endif

    BN_free(sk_inverse); 
    EC_POINT_free(M); 
}

// Encryption algorithm (2-recipients 1-message) with given random coins
// output X1 = pk1^r, X2 = pk2^r, Y = g^r h^m
// Here we make the randomness explict for the ease of generating the ZKP
void MR_Twisted_ElGamal_Enc(Twisted_ElGamal_PP &pp, 
                            EC_POINT* &pk1, 
                            EC_POINT* &pk2, 
                            BIGNUM* &m, 
                            BIGNUM* &r, 
                            MR_Twisted_ElGamal_CT &CT)
{ 
    EC_POINT_mul(group, CT.X1, NULL, pk1, r, bn_ctx); // CT_new.X1 = pk1^r
    EC_POINT_mul(group, CT.X2, NULL, pk2, r, bn_ctx); // CT_new.X2 = pk2^r
    EC_POINT_mul(group, CT.Y, r, pp.h, m, bn_ctx); // Y = g^r h^m
   
    #ifdef DEBUG
        cout << "2-recipient 1-message twisted ElGamal encryption finishes >>>"<< endl;
        Print_MR_Twisted_ElGamal_CT(CT); 
    #endif
}













