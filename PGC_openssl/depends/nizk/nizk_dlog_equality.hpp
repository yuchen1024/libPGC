/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __DLOGEQ__
#define __DLOGEQ__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of DLOG_EQ_Proof 
struct DLOG_Equality_PP
{
    string ss_reserve;          // actually no pp here
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

void NIZK_DLOG_Equality_Instance_new(DLOG_Equality_Instance &instance)
{
    instance.g1 = EC_POINT_new(group);
    instance.h1 = EC_POINT_new(group);
    instance.g2 = EC_POINT_new(group);
    instance.h2 = EC_POINT_new(group);
}

void NIZK_DLOG_Equality_Instance_free(DLOG_Equality_Instance &instance)
{
    EC_POINT_free(instance.g1);
    EC_POINT_free(instance.h1);
    EC_POINT_free(instance.g2);
    EC_POINT_free(instance.h2);
}

void NIZK_DLOG_Equality_Witness_new(DLOG_Equality_Witness &witness)
{
    witness.w = BN_new();
}

void NIZK_DLOG_Equality_Witness_free(DLOG_Equality_Witness &witness)
{
    BN_free(witness.w);
}

void NIZK_DLOG_Equality_Proof_new(DLOG_Equality_Proof &proof)
{
    proof.A1 = EC_POINT_new(group);
    proof.A2 = EC_POINT_new(group);
    proof.z = BN_new();
}

void NIZK_DLOG_Equality_Proof_free(DLOG_Equality_Proof &proof)
{
    EC_POINT_free(proof.A1);
    EC_POINT_free(proof.A2);
    BN_free(proof.z);
}

void DLOG_Equality_Instance_print(DLOG_Equality_Instance &instance)
{
    cout << "DLOG Equality Instance >>> " << endl; 
    ECP_print(instance.g1, "instance.g1"); 
    ECP_print(instance.h1, "instance.h1"); 
    ECP_print(instance.g2, "instance.g2"); 
    ECP_print(instance.h2, "instance.h2"); 
} 

void DLOG_Equality_Witness_print(DLOG_Equality_Witness &witness)
{
    cout << "DLOG Equality Witness >>> " << endl; 
    BN_print(witness.w, "w"); 
} 

void DLOG_Equality_Proof_print(DLOG_Equality_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for DLOG Equality >>> " << endl; 
    ECP_print(proof.A1, "proof.A1");
    ECP_print(proof.A2, "proof.A2");
    BN_print(proof.z,  "proof.z");
}

void DLOG_Equality_Proof_serialize(DLOG_Equality_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.A1, fout); 
    ECP_serialize(proof.A2, fout);
    BN_serialize(proof.z,  fout);
} 

void DLOG_Equality_Proof_deserialize(DLOG_Equality_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.A1, fin); 
    ECP_deserialize(proof.A2, fin);
    BN_deserialize(proof.z,  fin);
} 


/* Setup algorithm: do nothing */ 
void NIZK_DLOG_Equality_Setup(DLOG_Equality_PP &pp)
{ 
}

/* allocate memory for PP */
void NIZK_DLOG_Equality_PP_new(DLOG_Equality_PP &pp)
{ 
    pp.ss_reserve = "dummy";  
}

/* free memory of PP */
void NIZK_DLOG_Equality_PP_free(DLOG_Equality_PP &pp)
{ 
    pp.ss_reserve = "";  
}

// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
void NIZK_DLOG_Equality_Prove(DLOG_Equality_PP &pp, 
                              DLOG_Equality_Instance &instance, 
                              DLOG_Equality_Witness &witness, 
                              string &transcript_str, 
                              DLOG_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    transcript_str += ECP_ep2string(instance.g1) + ECP_ep2string(instance.g2) + 
                      ECP_ep2string(instance.h1) + ECP_ep2string(instance.h2); 
    // begin to generate proof
    BIGNUM *a = BN_new(); 
    BN_random(a); // P's randomness used to generate A1, A2

    EC_POINT_mul(group, proof.A1, NULL, instance.g1, a, bn_ctx); // A1 = g1^a
    EC_POINT_mul(group, proof.A2, NULL, instance.g2, a, bn_ctx); // A2 = g2^a

    // update the transcript 
    transcript_str += ECP_ep2string(proof.A1) + ECP_ep2string(proof.A2); 
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e); // V's challenge in Zq; 

    // compute the response
    BN_mul(proof.z, e, witness.w, bn_ctx); 
    BN_mod_add(proof.z, proof.z, a, order, bn_ctx); // z = a+e*w mod q

    #ifdef DEBUG
    DLOG_Equality_Proof_print(proof); 
    #endif

    BN_free(a); 
    BN_free(e); 
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool NIZK_DLOG_Equality_Verify(DLOG_Equality_PP &pp, 
                               DLOG_Equality_Instance &instance, 
                               string &transcript_str, 
                               DLOG_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    transcript_str += ECP_ep2string(instance.g1) + ECP_ep2string(instance.g2) + 
                      ECP_ep2string(instance.h1) + ECP_ep2string(instance.h2); 

    // update the transcript 
    transcript_str += ECP_ep2string(proof.A1) + ECP_ep2string(proof.A2); 
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e); // V's challenge in Zq; 

    bool V1, V2; 
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2]; 
    
    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group); 

    // check condition 1
    EC_POINT_mul(group, LEFT, NULL, instance.g1, proof.z, bn_ctx); // LEFT = g1^z

    vec_x[0] = BN_1; 
    vec_x[1] = e;     
    vec_A[0] = proof.A1; 
    vec_A[1] = instance.h1; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx);  // RIGHT = A1 h1^e  

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check g1^z = A1 h1^e
    
    // check condition 2
    EC_POINT_mul(group, LEFT, NULL, instance.g2, proof.z, bn_ctx); // LEFT = g2^z
    
    vec_x[0] = BN_1; 
    vec_x[1] = e;     
    vec_A[0] = proof.A2; 
    vec_A[1] = instance.h2; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx);  // RIGHT = A1 h1^e    

    V2 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check g2^z = A2 h2^e

    bool Validity = V1 && V2; 

    #ifdef DEBUG
    SplitLine_print('-'); 
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

#endif