/***********************************************************************************
this hpp implements NIZKPoK for two twisited ElGamal ciphertexts 
(randomness reuse) encrypt the same message 
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
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

// define structure of PT_EQ_Proof 
struct Plaintext_Equality_PP
{
    EC_POINT *g; 
    EC_POINT *h; 
};


// structure of proof 
struct Plaintext_Equality_Instance
{
    EC_POINT *pk1, *pk2; 
    EC_POINT *X1, *X2, *Y; 
};

// structure of witness 
struct Plaintext_Equality_Witness
{
    BIGNUM *v; 
    BIGNUM *r; 
};


// structure of proof 
struct Plaintext_Equality_Proof
{
    EC_POINT *A1, *A2, *B; // P's first round message
    BIGNUM *z1, *z2;    // P's response in Zq
};


void NIZK_Plaintext_Equality_PP_Free(Plaintext_Equality_PP &pp)
{
    // EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h);
}

void NIZK_Plaintext_Equality_Instance_Init(Plaintext_Equality_Instance &instance)
{
    instance.pk1 = EC_POINT_new(group);
    instance.pk2 = EC_POINT_new(group);
    instance.X1  = EC_POINT_new(group);
    instance.X2  = EC_POINT_new(group);
    instance.Y   = EC_POINT_new(group);
}

void NIZK_Plaintext_Equality_Instance_Free(Plaintext_Equality_Instance &instance)
{
    EC_POINT_free(instance.pk1);
    EC_POINT_free(instance.pk2);
    EC_POINT_free(instance.X1);
    EC_POINT_free(instance.X2);
    EC_POINT_free(instance.Y);
}

void NIZK_Plaintext_Equality_Witness_Init(Plaintext_Equality_Witness &witness)
{
    witness.v = BN_new();
    witness.r = BN_new(); 
}

void NIZK_Plaintext_Equality_Witness_Free(Plaintext_Equality_Witness &witness)
{
    BN_free(witness.v);
    BN_free(witness.r); 
}

void NIZK_Plaintext_Equality_Proof_Init(Plaintext_Equality_Proof &proof)
{
    proof.A1 = EC_POINT_new(group); 
    proof.A2 = EC_POINT_new(group); 
    proof.B  = EC_POINT_new(group);
    proof.z1 = BN_new(); 
    proof.z2 = BN_new();
}

void NIZK_Plaintext_Equality_Proof_Free(Plaintext_Equality_Proof &proof)
{
    EC_POINT_free(proof.A1);
    EC_POINT_free(proof.A2);
    EC_POINT_free(proof.B);
    BN_free(proof.z1);
    BN_free(proof.z2);
}


void Print_Plaintext_Equality_Instance(Plaintext_Equality_Instance instance)
{
    cout << "Plaintext Equality Instance >>> " << endl; 
    print_gg(instance.pk1, "instance.pk1"); 
    print_gg(instance.pk2, "instance.pk2"); 
    print_gg(instance.X1, "instance.X1"); 
    print_gg(instance.X2, "instance.X2"); 
    print_gg(instance.Y, "instance.Y"); 
} 

void Print_Plaintext_Equality_Witness(Plaintext_Equality_Witness witness)
{
    cout << "Plaintext Equality Witness >>> " << endl; 
    print_zz(witness.v, "witness.v"); 
    print_zz(witness.r, "witness.r"); 
} 

void Print_Plaintext_Equality_Proof(Plaintext_Equality_Proof proof)
{
    Print_Splitline('-'); 
    cout << "NIZKPoK for Plaintext Equality >>> " << endl; 
    print_gg(proof.A1, "proof.A1"); 
    print_gg(proof.A2, "proof.A2"); 
    print_gg(proof.B, "proof.B"); 
    print_zz(proof.z1, "proof.z1"); 
    print_zz(proof.z2, "proof.z2"); 
} 

void Serialize_Plaintext_Equality_Proof(Plaintext_Equality_Proof proof, ofstream& fout)
{
    Serialize_GG(proof.A1, fout); 
    Serialize_GG(proof.A2, fout);
    Serialize_GG(proof.B,  fout);
    Serialize_ZZ(proof.z1, fout); 
    Serialize_ZZ(proof.z2, fout); 
} 

void Deserialize_Plaintext_Equality_Proof(Plaintext_Equality_Proof& proof, ifstream& fin)
{
    Deserialize_GG(proof.A1, fin); 
    Deserialize_GG(proof.A2, fin);
    Deserialize_GG(proof.B,  fin);
    Deserialize_ZZ(proof.z1, fin); 
    Deserialize_ZZ(proof.z2, fin); 
} 

// Setup algorithm
void NIZK_Plaintext_Equality_Setup(Plaintext_Equality_PP &pp)
{ 
    pp.g = (EC_POINT*)EC_GROUP_get0_generator(group);
    pp.h = EC_POINT_new(group); 
    random_gg(pp.h);  
}

// generate NIZK proof for C1 = Enc(pk1, v; r) and C2 = Enc(pk2, v; r) the witness is (r, v)
void NIZK_Plaintext_Equality_Prove(Plaintext_Equality_PP &pp, 
                                   Plaintext_Equality_Instance &instance, 
                                   Plaintext_Equality_Witness &witness, 
                                   Plaintext_Equality_Proof &proof)
{    
    // initialize the transcript with instance 
    string transcript_str = ""; 
    // update with instance
    transcript_str += EC_POINT_ep2string(instance.pk1) + EC_POINT_ep2string(instance.pk2) + 
                      EC_POINT_ep2string(instance.X1)  + EC_POINT_ep2string(instance.X2)  + 
                      EC_POINT_ep2string(instance.Y); 

    BIGNUM *a = BN_new(); 
    BIGNUM *b = BN_new(); // the randomness of first round message


    random_zz(a);
    EC_POINT_mul(group, proof.A1, NULL, instance.pk1, a, bn_ctx); // A1 = pk1^a
    EC_POINT_mul(group, proof.A2, NULL, instance.pk2, a, bn_ctx); // A2 = pk2^a

    random_zz(b);
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = a; 
    vec_x[1] = b; 
    EC_POINTs_mul(group, proof.B, NULL, 2, vec_A, vec_x, bn_ctx); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += EC_POINT_ep2string(proof.A1) + EC_POINT_ep2string(proof.A2) 
                    + EC_POINT_ep2string(proof.B);  
    // compute the challenge
    BIGNUM *e = BN_new(); // V's challenge in Zq
    Hash_String_ZZ(e, transcript_str); // apply FS-transform to generate the challenge

    // compute the response
    BN_mul(proof.z1, e, witness.r, bn_ctx); 
    BN_mod_add(proof.z1, proof.z1, a, order, bn_ctx); // z1 = a+e*r mod q

    BN_mul(proof.z2, e, witness.v, bn_ctx); 
    BN_mod_add(proof.z2, proof.z2, b, order, bn_ctx); // z2 = b+e*v mod q

    BN_free(a); 
    BN_free(b);
    BN_free(e); 

    #ifdef DEBUG
    Print_Plaintext_Equality_Proof(proof); 
    #endif
}


// check NIZK proof PI for C1 = Enc(pk1, m; r1) and C2 = Enc(pk2, m; r2) the witness is (r1, r2, m)
bool NIZK_Plaintext_Equality_Verify(Plaintext_Equality_PP &pp, 
                                    Plaintext_Equality_Instance &instance, 
                                    Plaintext_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    string transcript_str = ""; 
    // update with instance
    transcript_str += EC_POINT_ep2string(instance.pk1) + EC_POINT_ep2string(instance.pk2) + 
                      EC_POINT_ep2string(instance.X1)  + EC_POINT_ep2string(instance.X2)  + 
                      EC_POINT_ep2string(instance.Y); 

    // update the transcript
    transcript_str += EC_POINT_ep2string(proof.A1) + EC_POINT_ep2string(proof.A2) 
                    + EC_POINT_ep2string(proof.B);  
    
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_ZZ(e, transcript_str); // apply FS-transform to generate the challenge

    bool V1, V2, V3; 
    EC_POINT *LEFT  = EC_POINT_new(group); 
    EC_POINT *RIGHT = EC_POINT_new(group); 
 
    // check condition 1
    EC_POINT_mul(group, LEFT, NULL, instance.pk1, proof.z1, bn_ctx); // pk1^{z1}

    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = proof.A1; 
    vec_A[1] = instance.X1; 
    vec_x[0] = bn_1; 
    vec_x[1] = e; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); 

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check pk1^z1 = A1 X1^e

    // check condition 2
    EC_POINT_mul(group, LEFT, NULL, instance.pk2, proof.z1, bn_ctx); // pk2^{z1}
    
    vec_A[0] = proof.A2; 
    vec_A[1] = instance.X2; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); 

    V2 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); //check pk2^z1 = A2 X2^e

    // check condition 3
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = proof.z1; 
    vec_x[1] = proof.z2; 
    EC_POINTs_mul(group, LEFT, NULL, 2, vec_A, vec_x, bn_ctx); 

    vec_A[0] = proof.B; 
    vec_A[1] = instance.Y; 
    vec_x[0] = bn_1; 
    vec_x[1] = e; 
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); 
    
    V3 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); // check g^z1 h^z2 = B Y^e

    bool Validity = V1 && V2 && V3;
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Plaintext Equality proof) = " << V1 << endl; 
    cout << boolalpha << "Condition 2 (Plaintext Equality proof) = " << V2 << endl; 
    cout << boolalpha << "Condition 3 (Plaintext Equality proof) = " << V3 << endl; 

    if (Validity) 
    { 
        cout<< "NIZK proof for twisted ElGamal plaintexts equality accepts >>>" << endl; 
    }
    else 
    {
        cout<< "NIZK proof for twisted ElGamal plaintexts equality rejects >>>" << endl; 
    }
    #endif

    BN_free(e); 

    return Validity;
}



