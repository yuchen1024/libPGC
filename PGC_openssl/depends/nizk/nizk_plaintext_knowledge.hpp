/****************************************************************************
this hpp implements NIZKPoK for twisted ElGamal ciphertext 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __PTKE__
#define __PTKE__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of PT_EQ_Proof 
struct Plaintext_Knowledge_PP
{
    EC_POINT *g; 
    EC_POINT *h; 
};

// structure of instance 
struct Plaintext_Knowledge_Instance
{
    EC_POINT *pk; 
    EC_POINT *X; 
    EC_POINT *Y; 
};

// structure of witness 
struct Plaintext_Knowledge_Witness
{
    BIGNUM *v; 
    BIGNUM *r; 
};

// structure of proof 
struct Plaintext_Knowledge_Proof
{
    EC_POINT *A, *B; // P's first round message
    BIGNUM *z1, *z2;  // P's response in Zq
};

void NIZK_Plaintext_Knowledge_Instance_new(Plaintext_Knowledge_Instance &instance)
{
    instance.pk = EC_POINT_new(group);
    instance.X = EC_POINT_new(group);
    instance.Y = EC_POINT_new(group);
}

void NIZK_Plaintext_Knowledge_Instance_free(Plaintext_Knowledge_Instance &instance)
{
    EC_POINT_free(instance.pk);
    EC_POINT_free(instance.X);
    EC_POINT_free(instance.Y);
}

void NIZK_Plaintext_Knowledge_Witness_new(Plaintext_Knowledge_Witness &witness)
{
    witness.v = BN_new();
    witness.r = BN_new(); 
}

void NIZK_Plaintext_Knowledge_Witness_free(Plaintext_Knowledge_Witness &witness)
{
    BN_free(witness.v);
    BN_free(witness.r); 
}

void NIZK_Plaintext_Knowledge_Proof_new(Plaintext_Knowledge_Proof &proof)
{
    proof.A = EC_POINT_new(group);
    proof.B = EC_POINT_new(group);
    proof.z1 = BN_new();
    proof.z2 = BN_new();
}

void NIZK_Plaintext_Knowledge_Proof_free(Plaintext_Knowledge_Proof &proof)
{
    EC_POINT_free(proof.A);
    EC_POINT_free(proof.B);
    BN_free(proof.z1);
    BN_free(proof.z2);
}

void Plaintext_Knowledge_Instance_print(Plaintext_Knowledge_Instance &instance)
{
    cout << "Plaintext Knowledge Instance >>> " << endl; 
    ECP_print(instance.pk, "instance.pk"); 
    ECP_print(instance.X, "instance.X"); 
    ECP_print(instance.Y, "instance.Y"); 
} 

void Plaintext_Knowledge_Witness_print(Plaintext_Knowledge_Witness &witness)
{
    cout << "Plaintext Knowledge Witness >>> " << endl; 
    BN_print(witness.v, "witness.v"); 
    BN_print(witness.r, "witness.r"); 
} 

void Plaintext_Knowledge_Proof_print(Plaintext_Knowledge_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for Plaintext Knowledge >>> " << endl; 

    ECP_print(proof.A, "proof.A"); 
    ECP_print(proof.B, "proof.B"); 
    BN_print(proof.z1, "proof.z1");
    BN_print(proof.z2, "proof.z2"); 
} 

void Plaintext_Knowledge_Proof_serialize(Plaintext_Knowledge_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.A, fout); 
    ECP_serialize(proof.B, fout);
    BN_serialize(proof.z1, fout); 
    BN_serialize(proof.z2, fout); 
}

void Plaintext_Knowledge_Proof_deserialize(Plaintext_Knowledge_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.A, fin); 
    ECP_deserialize(proof.B, fin);
    BN_deserialize(proof.z1, fin); 
    BN_deserialize(proof.z2, fin); 
}

/*  Setup algorithm */
void NIZK_Plaintext_Knowledge_Setup(Plaintext_Knowledge_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator);
    Hash_ECP_to_ECP(pp.g, pp.h); 

    #ifdef DEBUG
    cout << "generate public parameters of NIZK for plaintext knowledge >>>" << endl; 
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    #endif
}

/* allocate memory of PP */ 
void NIZK_Plaintext_Knowledge_PP_new(Plaintext_Knowledge_PP &pp)
{ 
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

/* free memory of PP */ 
void NIZK_Plaintext_Knowledge_PP_free(Plaintext_Knowledge_PP &pp)
{ 
    EC_POINT_free(pp.g);
    EC_POINT_free(pp.h);
}

// generate NIZK proof for C = Enc(pk, v; r) with witness (r, v)
void NIZK_Plaintext_Knowledge_Prove(Plaintext_Knowledge_PP &pp, 
                                    Plaintext_Knowledge_Instance &instance, 
                                    Plaintext_Knowledge_Witness &witness, 
                                    string &transcript_str,
                                    Plaintext_Knowledge_Proof &proof)
{   
    // initialize the transcript with instance 
    transcript_str += ECP_ep2string(instance.pk) + ECP_ep2string(instance.X) + 
                      ECP_ep2string(instance.Y); 
    
    BIGNUM *a = BN_new(); 
    BIGNUM *b = BN_new(); // the underlying randomness


    BN_random(a);
    EC_POINT_mul(group, proof.A, NULL, instance.pk, a, bn_ctx); // A = pk^a

    BN_random(b); 

    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = a; 
    vec_x[1] = b;  
    EC_POINTs_mul(group, proof.B, NULL, 2, vec_A, vec_x, bn_ctx); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += ECP_ep2string(proof.A) + ECP_ep2string(proof.B); 

    // computer the challenge
    BIGNUM *e = BN_new(); // V's challenge in Zq 
    Hash_String_to_BN(transcript_str, e); // apply FS-transform to generate the challenge
    
    // compute the response
    BN_mul(proof.z1, e, witness.r, bn_ctx); 
    BN_mod_add(proof.z1, proof.z1, a, order, bn_ctx); // z1 = a+e*r mod q

    BN_mul(proof.z2, e, witness.v, bn_ctx); 
    BN_mod_add(proof.z2, proof.z2, b, order, bn_ctx); // z2 = b+e*v mod q

    BN_free(a); 
    BN_free(b); 
    BN_free(e); 

    #ifdef DEBUG
    Plaintext_Knowledge_Proof_print(proof); 
    #endif
}


// check NIZKPoK for C = Enc(pk, v; r) 
bool NIZK_Plaintext_Knowledge_Verify(Plaintext_Knowledge_PP &pp, 
                                     Plaintext_Knowledge_Instance &instance, 
                                     string &transcript_str, 
                                     Plaintext_Knowledge_Proof &proof)
{    
    // initialize the transcript with instance 
    transcript_str += ECP_ep2string(instance.pk) + ECP_ep2string(instance.X) + 
                      ECP_ep2string(instance.Y); 

    // update the transcript with the first round message
    transcript_str += ECP_ep2string(proof.A) + ECP_ep2string(proof.B); 
    
    // recover the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e); // apply FS-transform to generate the challenge

    bool V1, V2; 
    EC_POINT *LEFT = EC_POINT_new(group); 
    EC_POINT *RIGHT = EC_POINT_new(group);

    // check condition 1
    EC_POINT_mul(group, LEFT, NULL, instance.pk, proof.z1, bn_ctx); // // LEFT  = pk^z1
    
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = proof.A; 
    vec_A[1] = instance.X; 
    vec_x[0] = BN_1; 
    vec_x[1] = e; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); // RIGHT = A X^e
    

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check pk^z1 = A X^e
    
    // check condition 2
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = proof.z1; 
    vec_x[1] = proof.z2;   
    EC_POINTs_mul(group, LEFT, NULL, 2, vec_A, vec_x, bn_ctx); // LEFT = g^z1 h^z2
    
    vec_A[0] = proof.B; 
    vec_A[1] = instance.Y; 
    vec_x[0] = BN_1; 
    vec_x[1] = e; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); // RIGHT = B Y^e 

    V2 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check g^z1 h^z2 = B Y^e

    bool Validity = V1 && V2;

    #ifdef DEBUG
    SplitLine_print('-'); 
    cout << "verify the NIZKPoK for plaintext knowledge >>>" << endl; 
    cout << boolalpha << "Condition 1 (Plaintext Knowledge proof) = " << V1 << endl; 
    cout << boolalpha << "Condition 2 (Plaintext Knowledge proof) = " << V2 << endl; 
    if (Validity) 
    { 
        cout<< "NIZKPoK for twisted ElGamal ciphertext accepts >>>" << endl; 
    }
    else 
    {
        cout<< "NIZKPoK for twisted ElGamal ciphertext rejects >>>" << endl; 
    }
    #endif

    BN_free(e); 
    EC_POINT_free(LEFT); 
    EC_POINT_free(RIGHT);

    return Validity;
}

#endif
