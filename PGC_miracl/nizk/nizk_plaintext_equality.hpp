/***********************************************************************************
this hpp implements NIZKPoK for two twisited ElGamal ciphertexts 
(randomness reuse) encrypt the same message 
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/

#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include "ecn.h"
#include "zzn.h"

// define structure of PT_EQ_Proof 
struct PT_EQ_PP
{
    ECn g, h; 
};


// structure of proof 
struct PT_EQ_Instance
{
    ECn pk1, pk2; 
    ECn X1, X2, Y; 
};

// structure of witness 
struct PT_EQ_Witness
{
    Big v, r; 
};


// structure of proof 
struct PT_EQ_Proof
{
    ECn A1, A2, B; // P's first round message
    Big z1, z2;    // P's response in Zq
};


// Setup algorithm
PT_EQ_PP PT_Equality_Setup()
{ 
    PT_EQ_PP pp; 
    pp.g = random_gg(); 
    pp.h = random_gg(); 
    return pp;  
}


// generate NIZK proof for C1 = Enc(pk1, v; r) and C2 = Enc(pk2, v; r) the witness is (r, v)
PT_EQ_Proof PT_Equality_Prove(const PT_EQ_PP pp, const PT_EQ_Instance instance, const PT_EQ_Witness witness)
{
    ECn T; // intermediate variables
    
    Big a, b; // the underlying randomness
    Big e; // V's challenge in Zq

    PT_EQ_Proof proof; 
    
    a = random_zz();
    proof.A1 = instance.pk1, proof.A1 *= a; // A1 = pk1^a
    proof.A2 = instance.pk2, proof.A2 *= a; // A2 = pk2^a

    b = random_zz();
    proof.B = mul(a, pp.g, b, pp.h); // B1 = g^a h^b

    vector<ECn> vec_A = {proof.A1, proof.A2, proof.B};

    e = Hash_GGn_ZZ(vec_A); // apply FS-transform to generate the challenge

    // compute the response
    proof.z1 = (a + e*witness.r)%q; 
    proof.z2 = (b + e*witness.v)%q; 

    #ifdef DEBUG
    cout << "Plaintext Equality Proof Generation Finished..." << endl;
    #endif

    return proof; 
}


// check NIZK proof PI for C1 = Enc(pk1, m; r1) and C2 = Enc(pk2, m; r2) the witness is (r1, r2, m)
bool PT_Equality_Verify(const PT_EQ_PP pp, const PT_EQ_Instance instance, const PT_EQ_Proof proof)
{
    Big x, y; // intermediate variables
    vector<ECn> vec_A = {proof.A1, proof.A2, proof.B};

    Big e = Hash_GGn_ZZ(vec_A); // recover the challenge

    bool V1, V2, V3; 
    ECn LEFT, RIGHT; 
 
    // check condition 1
    LEFT = instance.pk1, LEFT *= proof.z1;  //pk1^{z1}
    RIGHT = mul(1, proof.A1, e, instance.X1); 

    V1 = (LEFT==RIGHT); //check pk1^z1 = A1 X1^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (PT EQ proof) = " << V1 << endl; 
    #endif
    
    // check condition 2
    LEFT = instance.pk2, LEFT *= proof.z1; 
    RIGHT = mul(1, proof.A2, e, instance.X2); 

    V2 = (LEFT==RIGHT); //check pk2^z1 = A2 X2^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (PT EQ proof) = " << V2 << endl; 
    #endif

    // check condition 3
    LEFT = mul(proof.z1, pp.g, proof.z2, pp.h); 
    RIGHT = mul(1, proof.B, e, instance.Y); 
    
    V3 = (LEFT==RIGHT); // check g^z1 h^z2 = B Y^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 3 (PT EQ proof) = " << V3 << endl; 
    #endif

    bool Validity = V1 && V2 && V3;
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "NIZK proof for twisted ElGamal plaintexts equality accepts..." << endl; 
    }
    else 
    {
        cout<< "NIZK proof for twisted ElGamal plaintexts equality rejects..." << endl; 
    }
    #endif

    return Validity;
}

void Print_PT_EQ_Proof(PT_EQ_Proof proof)
{
    cout << "A1 = " << proof.A1 << endl;
    cout << "A2 = " << proof.A2 << endl;
    cout << "B  = " << proof.B  << endl;
    cout << "z1 = " << proof.z1 << endl;
    cout << "z2 = " << proof.z2 << endl; 
} 

void Serialize_PT_EQ_Proof(PT_EQ_Proof proof, ofstream& fout)
{
    Serialize_GG(proof.A1, fout); 
    Serialize_GG(proof.A2, fout);
    Serialize_GG(proof.B,  fout);
    Serialize_ZZ(proof.z1, fout); 
    Serialize_ZZ(proof.z2, fout); 
} 

void Deserialize_PT_EQ_Proof(PT_EQ_Proof& proof, ifstream& fin)
{
    Deserialize_GG(proof.A1, fin); 
    Deserialize_GG(proof.A2, fin);
    Deserialize_GG(proof.B,  fin);
    Deserialize_ZZ(proof.z1, fin); 
    Deserialize_ZZ(proof.z2, fin); 
} 


