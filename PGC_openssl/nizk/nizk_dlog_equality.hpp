/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "stdio.h"
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace std;

// define structure of DLOG_EQ_Proof 
struct DLOG_Equality_PP
{
    string ss_reserve;          // acturally no pp here
};

struct DLOG_Equality_Instance
{
    EC_POINT *g1, *h1, *g2, *h2; 
}; 

struct DLOG_Equality_Witness
{
    BIGNUM *w; 
}; 

// define structure of DLOG_EQ_Proof 
struct DLOG_Equality_Proof
{
    EC_POINT *A1, *A2;     // P's first round message
    BIGNUM *z;          // V's response
};

void NIZK_DLOG_Equality_Instance_Init(DLOG_Equality_Instance &instance)
{
    instance.g1 = EC_POINT_new(group);
    instance.h1 = EC_POINT_new(group);
    instance.g2 = EC_POINT_new(group);
    instance.h2 = EC_POINT_new(group);
}

void NIZK_DLOG_Equality_Instance_Free(DLOG_Equality_Instance &instance)
{
    EC_POINT_free(instance.g1);
    EC_POINT_free(instance.h1);
    EC_POINT_free(instance.g2);
    EC_POINT_free(instance.h2);
}

void NIZK_DLOG_Equality_Witness_Init(DLOG_Equality_Witness &witness)
{
    witness.w = BN_new();
}

void NIZK_DLOG_Equality_Witness_Free(DLOG_Equality_Witness &witness)
{
    BN_free(witness.w);
}

void NIZK_DLOG_Equality_Proof_Init(DLOG_Equality_Proof &proof)
{
    proof.A1 = EC_POINT_new(group);
    proof.A2 = EC_POINT_new(group);
    proof.z = BN_new();
}

void NIZK_DLOG_Equality_Proof_Free(DLOG_Equality_Proof &proof)
{
    EC_POINT_free(proof.A1);
    EC_POINT_free(proof.A2);
    BN_free(proof.z);
}

void Print_DLOG_Equality_Instance(DLOG_Equality_Instance &instance)
{
    cout << "DLOG Equality Instance >>> " << endl; 
    print_gg(instance.g1, "instance.g1"); 
    print_gg(instance.h1, "instance.h1"); 
    print_gg(instance.g2, "instance.g2"); 
    print_gg(instance.h2, "instance.h2"); 
} 

void Print_DLOG_Equality_Witness(DLOG_Equality_Witness &witness)
{
    
    cout << "DLOG Equality Witness >>> " << endl; 
    print_zz(witness.w, "w"); 
} 

void Print_DLOG_Equality_Proof(DLOG_Equality_Proof &proof)
{
    Print_Splitline('-'); 
    cout << "NIZKPoK for DLOG Equality >>> " << endl; 
    print_gg(proof.A1, "proof.A1");
    print_gg(proof.A2, "proof.A2");
    print_zz(proof.z, "proof.z");
}

void Serialize_DLOG_Equality_Proof(DLOG_Equality_Proof &proof, ofstream &fout)
{
    Serialize_GG(proof.A1, fout); 
    Serialize_GG(proof.A2, fout);
    Serialize_ZZ(proof.z,  fout);
} 

void Deserialize_DLOG_Equality_Proof(DLOG_Equality_Proof &proof, ifstream &fin)
{
    Deserialize_GG(proof.A1, fin); 
    Deserialize_GG(proof.A2, fin);
    Deserialize_ZZ(proof.z,  fin);
} 


// Setup algorithm
void NIZK_DLOG_Equality_Setup(DLOG_Equality_PP &pp)
{ 
    pp.ss_reserve = "dummy";  
}

// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
void NIZK_DLOG_Equality_Prove(DLOG_Equality_PP &pp, 
                              DLOG_Equality_Instance &instance, 
                              string &aux_str, 
                              DLOG_Equality_Witness &witness, 
                              DLOG_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    string transcript_str = ""; 
    transcript_str += EC_POINT_ep2string(instance.g1) + EC_POINT_ep2string(instance.g2) + 
                      EC_POINT_ep2string(instance.h1) + EC_POINT_ep2string(instance.h2); 
    // begin to generate proof
    BIGNUM *a = BN_new(); 
    random_zz(a); // P's randomness used to generate A1, A2

    EC_POINT_mul(group, proof.A1, NULL, instance.g1, a, bn_ctx); // A1 = g1^a
    EC_POINT_mul(group, proof.A2, NULL, instance.g2, a, bn_ctx); // A2 = g2^a

    // update the transcript 
    transcript_str += EC_POINT_ep2string(proof.A1) + EC_POINT_ep2string(proof.A2) + aux_str; 
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_ZZ(e, transcript_str); // V's challenge in Zq; 

    // compute the response
    BN_mul(proof.z, e, witness.w, bn_ctx); 
    BN_mod_add(proof.z, proof.z, a, order, bn_ctx); // z = a+e*w mod q

    #ifdef DEBUG
    Print_DLOG_Equality_Proof(proof); 
    #endif

    BN_free(a); 
    BN_free(e); 
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool NIZK_DLOG_Equality_Verify(DLOG_Equality_PP &pp, 
                               DLOG_Equality_Instance &instance, 
                               string &aux_str, 
                               DLOG_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    string transcript_str = ""; 
    transcript_str += EC_POINT_ep2string(instance.g1) + EC_POINT_ep2string(instance.g2) + 
                      EC_POINT_ep2string(instance.h1) + EC_POINT_ep2string(instance.h2); 

    // update the transcript 
    transcript_str += EC_POINT_ep2string(proof.A1) + EC_POINT_ep2string(proof.A2) + aux_str; 
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_ZZ(e, transcript_str); // V's challenge in Zq; 

    bool V1, V2; 
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2]; 
    
    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group); 

    // check condition 1
    EC_POINT_mul(group, LEFT, NULL, instance.g1, proof.z, bn_ctx); // LEFT = g1^z

    vec_x[0] = bn_1; 
    vec_x[1] = e;     
    vec_A[0] = proof.A1; 
    vec_A[1] = instance.h1; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx);  // RIGHT = A1 h1^e  

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check g1^z = A1 h1^e
    
    // check condition 2
    EC_POINT_mul(group, LEFT, NULL, instance.g2, proof.z, bn_ctx); // LEFT = g2^z
    
    vec_x[0] = bn_1; 
    vec_x[1] = e;     
    vec_A[0] = proof.A2; 
    vec_A[1] = instance.h2; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx);  // RIGHT = A1 h1^e    

    V2 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check g2^z = A2 h2^e

    bool Validity = V1 && V2; 

    #ifdef DEBUG
    Print_Splitline('-'); 
    cout << boolalpha << "Condition 1 (LOG_EQ Proof) = " << V1 << endl; 
    cout << boolalpha << "Condition 2 (LOG_EQ Proof) = " << V2 << endl;
    if (Validity){ 
        cout<< "DLOG Equality Proof Accepts >>>" << endl; 
    }
    else{
        cout<< "DLOG Equality Proof Rejects >>>" << endl; 
    }
    #endif

    BN_free(e); 
    EC_POINT_free(LEFT); 
    EC_POINT_free(RIGHT);

    return Validity;
}



