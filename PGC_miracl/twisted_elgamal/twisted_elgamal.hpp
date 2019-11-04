/****************************************************************************
this hpp implements twisted ElGamal encrypt scheme
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <iostream>
#include <fstream>
#include "ecn.h"
#include "zzn.h"

#include "calculate_dlog.hpp"

// define the structure of PP
struct Twisted_ElGamal_PP
{
    ECn g, h; // two random generators 
};

// define the structure of keypair
struct Twisted_ElGamal_KP
{
    ECn pk;  
    Big sk;   
};

// define the structure of ciphertext
struct Twisted_ElGamal_CT
{
    ECn X; // X = pk^r 
    ECn Y; // Y = G^m H^r 
};

// define the structure of 2R1M ciphertext (MR denotes multiple recipients)
struct MR_Twisted_ElGamal_CT
{
    ECn X1; // X = pk1^r
    ECn X2; // X = pk2^r 
    ECn Y; // Y = G^m H^r 
};


// Setup algorithm
Twisted_ElGamal_PP Twisted_ElGamal_Setup()
{ 
    Twisted_ElGamal_PP pp;
    pp.g = random_gg(); 
    pp.h = random_gg(); 

    #ifdef DEBUG
    cout << "generate the global public parameters >>>" << endl; 
    cout << "g = " << pp.g << endl; 
    cout << "h = " << pp.h << endl; 
    #endif

    #ifdef PREPROCESSING
    Serialize_Map(pp.h);
    #endif
    
    return pp;  
}

// KeyGen algorithm
Twisted_ElGamal_KP Twisted_ElGamal_KeyGen(const Twisted_ElGamal_PP pp)
{ 
    Twisted_ElGamal_KP keypair;  

    //generate the random coins 
    keypair.sk = random_zz();
    keypair.pk = pp.g; 
    keypair.pk *= keypair.sk;  

    #ifdef DEBUG
    cout << "sk = " << keypair.sk << endl; 
    cout << "pk = " << keypair.pk << endl;
    #endif

    return keypair; 
}

// Encryption algorithm: compute CT = Enc(pk, m; r)
Twisted_ElGamal_CT Twisted_ElGamal_Enc(const Twisted_ElGamal_PP pp, const ECn pk, const Big m)
{ 
    Twisted_ElGamal_CT CT; 

    // generate the random coins 
    Big r = random_zz();

    // begin encryption
    CT.X = pk, CT.X *= r;   // X = pk^r
    CT.Y = mul(r, pp.g, m, pp.h); // Y = g^r h^m
    
    #ifdef DEBUG
        cout << "twisted ElGamal encryption finishes..."<< endl;
    #endif

    return CT; 
}

// Encryption algorithm: compute CT = Enc(pk, m; r)
Twisted_ElGamal_CT Twisted_ElGamal_Enc(const Twisted_ElGamal_PP pp, const ECn pk, const Big m, const Big r)
{ 
    Twisted_ElGamal_CT CT; 

    // begin encryption
    CT.X = pk, CT.X *= r;   // X = pk^r
    CT.Y = mul(r, pp.g, m, pp.h); // Y = g^r h^m
    
    #ifdef DEBUG
        cout << "twisted ElGamal encryption finishes..."<< endl;
    #endif

    return CT; 
}


// Decryption algorithm: compute m = Dec(sk, CT)
Big Twisted_ElGamal_Dec(const Twisted_ElGamal_PP pp, const Big sk, Twisted_ElGamal_CT CT)
{ 
    //begin decryption 
    ECn M; 
    Big sk_inverse = inverse(sk, q); // compute the inverse of sk in Z_q^* 
    CT.X *= sk_inverse; 
    CT.Y -= CT.X, M = CT.Y;

    //Big m = Solve_DLOG(pp.G, M);
    //Big m = Shanks(pp.h, M, 32);  
    Big m = Preprocessing_Shanks(pp.h, M); 
    #ifdef DEBUG
        cout << "twisted ElGamal decryption finishes..."<< endl;
    #endif

    return m; 
}

// Refresh ciphertext CT with given random coins r 
Twisted_ElGamal_CT Twisted_ElGamal_Refresh(const Twisted_ElGamal_PP pp, const ECn pk, const Big sk, 
                                           Twisted_ElGamal_CT CT, const Big r)
{ 
    // begin partial decryption  
    ECn M; 
    Big sk_inverse = inverse(sk, q); // compute the inverse of sk in Z_q^* 
    CT.X *= sk_inverse; 
    CT.Y -= CT.X, M = CT.Y;

    // begin re-encryption with the given randomness 
    CT.X = pk, CT.X *= r; 
    CT.Y = pp.g,  CT.Y *= r, CT.Y += M; 

    #ifdef DEBUG
        cout << "refresh ciphertext succeeds..."<< endl;
    #endif

    return CT;  
}

// Encryption algorithm (2-recipients 1-message) with given random coins
// output X1 = pk1^r, X2 = pk2^r, Y = g^r h^m
MR_Twisted_ElGamal_CT MR_Twisted_ElGamal_Enc(const Twisted_ElGamal_PP pp, 
                                       const ECn pk1, const ECn pk2, const Big m, const Big r)
{ 
    MR_Twisted_ElGamal_CT CT; 

    // begin encryption
    CT.X1 = pk1, CT.X1 *= r;   // X1 = pk1^r
    CT.X2 = pk2, CT.X2 *= r;   // X2 = pk2^r
    CT.Y = mul(r, pp.g, m, pp.h); // Y = g^r h^m
    
    #ifdef DEBUG
        cout << "2-recipient 1-message twisted ElGamal encryption finishes..."<< endl;
    #endif

    return CT; 
}

void Print_Twisted_ElGamal_CT(Twisted_ElGamal_CT CT)
{
    cout << "X = " << CT.X << endl; 
    cout << "Y = " << CT.Y << endl; 
} 

void Print_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT CT)
{
    cout << "X1 = " << CT.X1 << endl;
    cout << "X2 = " << CT.X2 << endl;
    cout << "Y  = " << CT.Y << endl; 
} 

void Serialize_Twisted_ElGamal_CT(Twisted_ElGamal_CT CT, ofstream& fout)
{
    Serialize_GG(CT.X, fout); 
    Serialize_GG(CT.Y, fout); 
} 

void Deserialize_Twisted_ElGamal_CT(Twisted_ElGamal_CT& CT, ifstream& fin)
{
    Deserialize_GG(CT.X, fin); 
    Deserialize_GG(CT.Y, fin); 
} 


void Serialize_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT CT, ofstream& fout)
{
    Serialize_GG(CT.X1, fout); 
    Serialize_GG(CT.X2, fout);
    Serialize_GG(CT.Y,  fout); 
} 

void Deserialize_MR_Twisted_ElGamal_CT(MR_Twisted_ElGamal_CT& CT, ifstream& fin)
{
    Deserialize_GG(CT.X1, fin); 
    Deserialize_GG(CT.X2, fin); 
    Deserialize_GG(CT.Y, fin); 
} 



