/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
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


// define structure of DLOG_EQ_Proof 
struct DLOG_EQ_PP
{
    string ss_reserve;          // the modulus of group
};


// define structure of DLOG_EQ_Proof 
struct DLOG_EQ_Proof
{
    ECn A1, A2;     // P's first round message
    Big z;          // V's response
};

struct DLOG_EQ_Instance
{
    ECn g1, h1, g2, h2; 
}; 

struct DLOG_EQ_Witness
{
    Big w; 
}; 


// Setup algorithm
DLOG_EQ_PP DLOG_Equality_Setup()
{ 
    DLOG_EQ_PP pp; 
    pp.ss_reserve = "dummy"; 
    return pp; 
}

// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
DLOG_EQ_Proof DLOG_Equality_Prove(DLOG_EQ_PP pp, DLOG_EQ_Instance instance, DLOG_EQ_Witness witness)
{
    DLOG_EQ_Proof proof; 

    // begin to generate proof
    Big a = random_zz(); // P's randomness used to generate A1, A2
    proof.A1 = instance.g1, proof.A1 *= a; // A1 = g1^a
    proof.A2 = instance.g2, proof.A2 *= a; // A2 = g2^a

    vector<ECn> vec_A = {proof.A1, proof.A2}; // used for hash input 
    Big e = Hash_GGn_ZZ(vec_A); // V's challenge in Zq 

    proof.z = (a + e*witness.w)%q;  

    #ifdef DEBUG
    cout << "DLOG Equality Proof Generation Finished..." << endl;
    #endif

    return proof; 
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool DLOG_Equality_Verify(const DLOG_EQ_PP pp, const DLOG_EQ_Instance instance, const DLOG_EQ_Proof proof)
{
    vector<ECn> vec_A = {proof.A1, proof.A2}; // used for hash input 
    Big e = Hash_GGn_ZZ(vec_A);  // V's challenge in Zq 

    bool V1, V2; 
    ECn LEFT, RIGHT; 
    // check condition 1
    LEFT = instance.g1, LEFT *= proof.z;  
    RIGHT = mul(1, proof.A1, e, instance.h1);  

    V1 = (LEFT==RIGHT); //check g1^z = A1 H1^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (LOG_EQ Proof) = " << V1 << endl; 
    #endif
    
    // check condition 2
    LEFT = instance.g2, LEFT *= proof.z; 
    RIGHT = mul(1, proof.A2, e, instance.h2);   

    V2 = (LEFT==RIGHT); //check g2^z = A2 H2^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (LOG_EQ Proof) = " << V2 << endl;
    #endif

    bool Validity = V1 && V2; 

    #ifdef DEBUG
    if (Validity) { 
        cout<< "DLOG Equality Proof Accepts..." << endl; 
    }

    else {
        cout<< "DLOG Equality Proof Rejects..." << endl; 
    }
    #endif

    return Validity;
}


// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
DLOG_EQ_Proof DLOG_Equality_Auxiliary_Prove(const DLOG_EQ_PP pp, const DLOG_EQ_Instance instance, 
                                            const string msg_file, const DLOG_EQ_Witness witness)
{
    DLOG_EQ_Proof proof; 

    // begin to generate proof
    Big a = random_zz(); // P's randomness used to generate A1, A2
    proof.A1 = instance.g1, proof.A1 *= a; // A1 = g1^a
    proof.A2 = instance.g2, proof.A2 *= a; // A2 = g2^a

    Big msg_digest = Hash_File_ZZ(msg_file); 

    vector<ECn> vec_A = {proof.A1, proof.A2}; // used for hash input 
    Big e_prime = Hash_GGn_ZZ(vec_A); // V's challenge in Zq 
    vector<Big> vec_a = {e_prime, msg_digest}; 
    Big e = Hash_ZZn_ZZ(vec_a); 
    proof.z = (a + e*witness.w)%q;  

    #ifdef DEBUG
    cout << "DLOG Equality Proof Generation Finished..." << endl;
    #endif

    return proof; 
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool DLOG_Equality_Auxiliary_Verify(const DLOG_EQ_PP pp, const DLOG_EQ_Instance instance, 
                                    const string msg_file, const DLOG_EQ_Proof proof)
{
    Big msg_digest = Hash_File_ZZ(msg_file); 
    vector<ECn> vec_A = {proof.A1, proof.A2}; // used for hash input 
    Big e_prime = Hash_GGn_ZZ(vec_A); // V's challenge in Zq 
    vector<Big> vec_a = {e_prime, msg_digest}; 
    Big e = Hash_ZZn_ZZ(vec_a); 

    bool V1, V2; 
    ECn LEFT, RIGHT; 
    // check condition 1
    LEFT = instance.g1, LEFT *= proof.z;  
    RIGHT = mul(1, proof.A1, e, instance.h1);  

    V1 = (LEFT==RIGHT); //check g1^z = A1 H1^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (LOG_EQ Proof) = " << V1 << endl; 
    #endif
    
    // check condition 2
    LEFT = instance.g2, LEFT *= proof.z; 
    RIGHT = mul(1, proof.A2, e, instance.h2);   

    V2 = (LEFT==RIGHT); //check g2^z = A2 H2^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (LOG_EQ Proof) = " << V2 << endl;
    #endif

    bool Validity = V1 && V2; 

    #ifdef DEBUG
    if (Validity) { 
        cout<< "DLOG Equality Proof Accepts..." << endl; 
    }

    else {
        cout<< "DLOG Equality Proof Rejects..." << endl; 
    }
    #endif

    return Validity;
}

void Print_DLOG_EQ_Proof(DLOG_EQ_Proof proof)
{
    cout << "A1 = " << proof.A1 << endl;
    cout << "A2 = " << proof.A2 << endl;
    cout << "z  = " << proof.z  << endl; 
} 

void Serialize_DLOG_EQ_Proof(DLOG_EQ_Proof proof, ofstream& fout)
{
    Serialize_GG(proof.A1, fout); 
    Serialize_GG(proof.A2, fout);
    Serialize_ZZ(proof.z,  fout);
} 

void Deserialize_DLOG_EQ_Proof(DLOG_EQ_Proof& proof, ifstream& fin)
{
    Deserialize_GG(proof.A1, fin); 
    Deserialize_GG(proof.A2, fin);
    Deserialize_ZZ(proof.z,  fin);
} 