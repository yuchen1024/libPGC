/****************************************************************************
this hpp implements NIZKPoK for twisted ElGamal ciphertext 
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


// define structure of PT_EQ_Proof 
struct CT_Valid_PP
{
    ECn g, h; 
};


// structure of proof 
struct CT_Valid_Instance
{
    ECn pk; 
    ECn X, Y; 
};

// structure of witness 
struct CT_Valid_Witness
{
    Big v, r; 
};


// structure of proof 
struct CT_Valid_Proof
{
    ECn A, B; // P's first round message
    Big z1, z2;    // P's response in Zq
};


// Setup algorithm
CT_Valid_PP CT_Validity_Setup()
{ 
    CT_Valid_PP pp; 
    pp.g = random_gg(); 
    pp.h = random_gg(); 
    return pp;  
}


// generate NIZK proof for C = Enc(pk, v; r) with witness (r, v)
CT_Valid_Proof CT_Validity_Prove(const CT_Valid_PP pp, const CT_Valid_Instance instance, 
                                 const CT_Valid_Witness witness)
{
    ECn T; // intermediate variables
    
    Big a, b; // the underlying randomness
    Big e; // V's challenge in Zq

    CT_Valid_Proof proof; 
    
    a = random_zz();
    proof.A = instance.pk, proof.A *= a; // A = pk^a

    b = random_zz();
    proof.B = mul(a, pp.g, b, pp.h); // B = g^a h^b

    vector<ECn> vec_A = {proof.A, proof.B};

    e = Hash_GGn_ZZ(vec_A); // apply FS-transform to generate the challenge

    // compute the response
    proof.z1 = (a + e*witness.r)%q; 
    proof.z2 = (b + e*witness.v)%q; 

    #ifdef DEBUG
    cout << "CT Validity Proof Generation Finished..." << endl;
    #endif

    return proof; 
}


// check NIZKPoK for C = Enc(pk, v; r) 
bool CT_Validity_Verify(const CT_Valid_PP pp, const CT_Valid_Instance instance, const CT_Valid_Proof proof)
{
    Big x, y; // intermediate variables
    vector<ECn> vec_A = {proof.A, proof.B};

    Big e = Hash_GGn_ZZ(vec_A); // recover the challenge

    bool V1, V2; 
    ECn LEFT, RIGHT; 
 
    // check condition 1
    LEFT = instance.pk, LEFT *= proof.z1;  //pk1^{z1}
    RIGHT = mul(1, proof.A, e, instance.X); 

    V1 = (LEFT==RIGHT); //check pk1^z1 = A1 X1^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (CT Valid proof) = " << V1 << endl; 
    #endif
    
    // check condition 2
    LEFT  = mul(proof.z1, pp.g, proof.z2, pp.h); 
    RIGHT = mul(1, proof.B, e, instance.Y); 

    V2 = (LEFT==RIGHT); //check g^z1 h^z2 = B Y^e
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (CT Valid proof) = " << V2 << endl; 
    #endif

    bool Validity = V1 && V2;
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "NIZK proof for twisted ElGamal ciphertext validity accepts..." << endl; 
    }
    else 
    {
        cout<< "NIZK proof for twisted ElGamal ciphertext validity rejects..." << endl; 
    }
    #endif

    return Validity;
}

void Print_CT_Valid_Proof(CT_Valid_Proof proof)
{
    cout << "A = " << proof.A << endl;
    cout << "B = " << proof.B << endl;
    cout << "z1 = " << proof.z1 << endl;
    cout << "z2 = " << proof.z2 << endl; 
} 

void Serialize_CT_Valid_Proof(CT_Valid_Proof proof, ofstream& fout)
{
    Serialize_GG(proof.A, fout); 
    Serialize_GG(proof.B, fout);
    Serialize_ZZ(proof.z1, fout); 
    Serialize_ZZ(proof.z2, fout); 
}

void Deserialize_CT_Valid_Proof(CT_Valid_Proof& proof, ifstream& fin)
{
    Deserialize_GG(proof.A, fin); 
    Deserialize_GG(proof.B, fin);
    Deserialize_ZZ(proof.z1, fin); 
    Deserialize_ZZ(proof.z2, fin); 
}