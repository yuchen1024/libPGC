/****************************************************************************
this hpp implements the PGC functionality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <locale>
#include <ctime>
#include <cmath>
#include <chrono>
#include <unistd.h>
#include "ecn.h"
#include "zzn.h"

#include "../twisted_elgamal/twisted_elgamal.hpp"        // implement Twisted ElGamal  
#include "../nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../nizk/nizk_ct_validity.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../bulletproofs/aggregate_bulletproof.hpp"    // implement Log Size Bulletproof

#define DEMO           // demo mode
//define PREPROCESSING // ifdefined, then use Shanks algorithm to decrypt, else update balance in a tricky way 
//#define DEBUG        // show debug information 


const int NONCE_LEN = 8;  // nonce length

// define the structure for Account
struct PGC_PP{
    int RANGE_LEN; 
    int LOG_RANGE_LEN; 
    int m; // number of sub-argument (for now, we require m to be the power of 2)

    ECn g, h;
    ECn u; // used for inside innerproduct statement
    vector<ECn> vec_g; 
    vector<ECn> vec_h; // the pp of innerproduct part    
};

struct PGC_Account{
    string identity;     // id
    ECn pk;              // public key
    Big sk;              // secret key
    Twisted_ElGamal_CT balance;  // current balance
    Big m;               // dangerous (should only be used for speeding up the proof generation)
};

// define the structure for confidential transaction
struct PGC_CTx{
    // nonce uniquely determines a transaction
    Big nonce;                         // nonce

    // meta information
    Twisted_ElGamal_CT balance;        // current balance m
    ECn pk1, pk2;                      // sender = pk1, receiver = pk2
    MR_Twisted_ElGamal_CT transfer;    // transfer = (X1 = pk1^r, X2 = pk^2, Y = g^r h^v)
    Big v;                             // defined here only for test, should be remove in the real system  

    // valid proof
    PT_EQ_Proof sigma_pteq_proof;                   // NIZK proof for validity of transfer
    Bullet_Proof bullet_right_enough_proof;      // aggregrated range proof for v and m-v lie in the right range 
    Twisted_ElGamal_CT refresh_updated_balance;  // fresh encryption of updated balance (randomness is known)
    CT_Valid_Proof sigma_ctvalid_proof; 
    DLOG_EQ_Proof sigma_dlogeq_proof;                // fresh updated balance is correct
}; 


Bullet_PP Get_Bullet_PP(PGC_PP pp)
{
    Bullet_PP bullet_pp; 
    bullet_pp.RANGE_LEN = pp.RANGE_LEN; 
    bullet_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN;
    bullet_pp.m = pp.m;  

    bullet_pp.g = pp.g; 
    bullet_pp.h = pp.h; 
    bullet_pp.u = pp.u; 
    bullet_pp.vec_g = pp.vec_g; 
    bullet_pp.vec_h = pp.vec_h;

    return bullet_pp;  
}

Twisted_ElGamal_PP Get_Enc_PP(PGC_PP pp)
{
    Twisted_ElGamal_PP enc_pp;
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  

    return enc_pp; 
}

PT_EQ_PP Get_PT_EQ_PP(PGC_PP pp)
{
    PT_EQ_PP pteq_pp;
    pteq_pp.g = pp.g; 
    pteq_pp.h = pp.h;  

    return pteq_pp; 
}

DLOG_EQ_PP Get_DLOG_EQ_PP(PGC_PP pp)
{
    DLOG_EQ_PP dlogeq_pp;
    dlogeq_pp.ss_reserve = "dummy";  

    return dlogeq_pp;  
}

CT_Valid_PP Get_CT_Valid_PP(PGC_PP pp)
{
    CT_Valid_PP ctvalid_pp;
    ctvalid_pp.g = pp.g; 
    ctvalid_pp.h = pp.h; 

    return ctvalid_pp;  
}

// converts nonce to a length-32 HEX string with leading zeros
string nonce_to_string(Big x)
{
    stringstream ss; 
    ss << setfill('0') << setw(NUM_LEN/4) << x;
    return ss.str();  
}

// save the meta info of confidential transaction to "meta_file" 
void Serialize_Meta(const PGC_CTx newCTx, const string meta_file)
{   
    // store the meta info into "meta_file"
    ofstream fout; 
    fout.open(meta_file, ios::binary); 

    // save nonce
    Serialize_ZZ(newCTx.nonce, fout); 

    // save balance
    Serialize_Twisted_ElGamal_CT(newCTx.balance, fout); 

    // save pk1, pk2, transfer
    Serialize_GG(newCTx.pk1, fout); 
    Serialize_GG(newCTx.pk2, fout); 
    Serialize_MR_Twisted_ElGamal_CT(newCTx.transfer, fout);
    Serialize_ZZ(newCTx.v, fout);

    fout.close(); 
} 

// save the meta info of confidential transaction to "meta_file" 
void Deserialize_Meta(PGC_CTx& newCTx, const string meta_file)
{   
    // store the meta info into "meta_file"
    ifstream fin; 
    fin.open(meta_file, ios::binary); 

    // save nonce
    Deserialize_ZZ(newCTx.nonce, fin); 

    // save balance
    Deserialize_Twisted_ElGamal_CT(newCTx.balance, fin); 

    // save pk1, pk2, transfer
    Deserialize_GG(newCTx.pk1, fin); 
    Deserialize_GG(newCTx.pk2, fin); 
    Deserialize_MR_Twisted_ElGamal_CT(newCTx.transfer, fin);
    Deserialize_ZZ(newCTx.v, fin);

    fin.close(); 
} 

// save CTx into nonce.ctx file
void Serialize_CTx(const PGC_CTx newCTx, const string ctx_file)
{
    Serialize_Meta(newCTx, ctx_file);
     
    ofstream fout; 
    fout.open(ctx_file, ios::app | ios::binary);
    
    // save proofs
    Serialize_PT_EQ_Proof(newCTx.sigma_pteq_proof, fout);
    Serialize_Twisted_ElGamal_CT(newCTx.refresh_updated_balance, fout); 
    Serialize_DLOG_EQ_Proof(newCTx.sigma_dlogeq_proof, fout); 
    Serialize_CT_Valid_Proof(newCTx.sigma_ctvalid_proof, fout); 
    Serialize_Bullet_Proof(newCTx.bullet_right_enough_proof, fout); 
    fout.close();

    // calculate the size of ctx_file
    ifstream fin; 
    fin.open(ctx_file, ios::ate | ios::binary);
    cout << ctx_file << " size = " << fin.tellg() << " bytes" << endl;
    fin.close(); 
}

// recover CTx from nonce.ctx file
void Deserialize_CTx(PGC_CTx& newCTx, const string ctx_file)
{
    // Deserialize_CTx(newCTx, ctx_file); 
    ifstream fin; 
    fin.open(ctx_file, ios::binary); 

    // recover nonce
    Deserialize_ZZ(newCTx.nonce, fin);
    // recover balance
    Deserialize_Twisted_ElGamal_CT(newCTx.balance, fin);
    // recover pk1, pk2, transfer
    Deserialize_GG(newCTx.pk1, fin); 
    Deserialize_GG(newCTx.pk2, fin); 
    Deserialize_MR_Twisted_ElGamal_CT(newCTx.transfer, fin);
    Deserialize_ZZ(newCTx.v, fin); 

    Deserialize_PT_EQ_Proof(newCTx.sigma_pteq_proof, fin);
    Deserialize_Twisted_ElGamal_CT(newCTx.refresh_updated_balance, fin); 
    Deserialize_DLOG_EQ_Proof(newCTx.sigma_dlogeq_proof, fin); 
    Deserialize_CT_Valid_Proof(newCTx.sigma_ctvalid_proof, fin); 
    Deserialize_Bullet_Proof(newCTx.bullet_right_enough_proof, fin); 
    fin.close(); 
}


// This function implements Setup algorithm of PGC
PGC_PP PGC_Setup(int n, int m)
{
    // generate random generators for Bulletproof (InnerProduct Argument)  
    PGC_PP pp; 
    pp.RANGE_LEN = n; 
    pp.LOG_RANGE_LEN = log2(n); 
    pp.m = m; // number of sub-argument (for now, we require m to be the power of 2)

    pp.g = random_gg(); 
    pp.h = random_gg();
    pp.u = random_gg(); // used for inside innerproduct statement

    pp.vec_g.resize(n*m);
    pp.vec_h.resize(n*m);  

    for (int i = 0; i < n*m; i++)
    {
        pp.vec_g[i] = random_gg(); 
        pp.vec_h[i] = random_gg();
    }
    return pp; 
}

// create an account for input identity
PGC_Account Create_Account(const PGC_PP pp, const string identity, const Big init_balance)
{
    PGC_Account newAcct; 
    newAcct.identity = identity; 

    Twisted_ElGamal_PP enc_pp;
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    Twisted_ElGamal_KP keypair = Twisted_ElGamal_KeyGen(enc_pp); // generate a keypair for Alice
    newAcct.pk = keypair.pk; 
    newAcct.sk = keypair.sk;   

    newAcct.m = init_balance; 

    // initialize Alice's account value with 0 coins
    Big r = Hash_String_ZZ(newAcct.identity); 
    newAcct.balance = Twisted_ElGamal_Enc(enc_pp, newAcct.pk, init_balance, r);

    cout << identity << "'s account creation succeeds" << endl;
    cout << "pk = " << newAcct.pk << endl;

    mip->IOBASE = 10; 
    cout << identity << "'s initial balance = " << init_balance << endl;
    mip->IOBASE = 16;
 
    return newAcct;    
}

// update Account if CTx is valid
bool Update_Account(const PGC_PP pp, const PGC_CTx newCTx, PGC_Account& Acct_Alice, PGC_Account& Acct_Bob)
{
    Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 
    if (newCTx.pk1 != Acct_Alice.pk || newCTx.pk2 != Acct_Bob.pk)
    {
        cout << "sender and recipient addresses do not match" << endl;
        return false;  
    }
    else
    {
        Acct_Alice.balance.X -= newCTx.transfer.X1;
        Acct_Alice.balance.Y -= newCTx.transfer.Y;

        Acct_Bob.balance.X   += newCTx.transfer.X2;
        Acct_Bob.balance.Y   += newCTx.transfer.Y;

        #ifdef PREPROCESSING
        Acct_Alice.m = Twisted_ElGamal_Dec(enc_pp, Acct_Alice.sk, Acct_Alice.balance); 
        Acct_Bob.m = Twisted_ElGamal_Dec(enc_pp, Acct_Bob.sk, Acct_Bob.balance);
        #else
        Acct_Alice.m -= newCTx.v; 
        Acct_Bob.m   += newCTx.v; 
        #endif 

        return true; 
    }
} 

// reveal the balance 
Big Reveal_Balance(const PGC_PP pp, const PGC_Account Acct)
{
    // Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 
    // return Twisted_ElGamal_Dec(Acct.sk, Acct.balance); 
    return Acct.m; 
}

// generate a confidential transaction: pk1 transfers v coins to pk2 
PGC_CTx Create_CTx(PGC_PP pp, Big nonce, PGC_Account& Acct_Alice, Big v, ECn pk2)
{
    #ifdef DEMO
    cout << "begin to genetate CTx >>>>>>" << endl; 
    #endif
    Print_Splitline('-'); 

    PGC_CTx newCTx; 
    newCTx.nonce = nonce;
    string str_nonce = nonce_to_string(nonce);  // format string  
    cout << "nonce = " << str_nonce << endl; 
    string meta_file = str_nonce + ".meta"; 
    string ctx_file  = str_nonce + ".ctx"; 

    newCTx.pk1 = Acct_Alice.pk; 
    newCTx.pk2 = pk2; 

    Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 

    Big r = random_zz(); 
    newCTx.transfer = MR_Twisted_ElGamal_Enc(enc_pp, newCTx.pk1, newCTx.pk2, v, r); 

    Serialize_Meta(newCTx, meta_file); 

    #ifdef DEMO
    cout <<"1. generate meta info of CTx" << endl;  
    #endif

    // begin to generate the valid proof for ctx

    // generate NIZK proof for validity of transfer              
    PT_EQ_PP pteq_pp = Get_PT_EQ_PP(pp);
    PT_EQ_Instance pteq_instance; 
    pteq_instance.pk1 = newCTx.pk1; 
    pteq_instance.pk2 = newCTx.pk2; 
    pteq_instance.X1 = newCTx.transfer.X1;
    pteq_instance.X2 = newCTx.transfer.X2;
    pteq_instance.Y  = newCTx.transfer.Y;
    PT_EQ_Witness pteq_witness; 
    pteq_witness.r = r; 
    pteq_witness.v = v; 

    newCTx.sigma_pteq_proof = PT_Equality_Prove(pteq_pp, pteq_instance, pteq_witness);

    #ifdef DEMO
    cout << "2. generate NIZKPoK for plaintext equality" << endl;  
    #endif

    #ifdef DEMO
    cout << "3. compute updated balance" << endl;  
    #endif
    // compute the updated balance
    newCTx.balance = Acct_Alice.balance; 
    Twisted_ElGamal_CT updated_balance = newCTx.balance;
    updated_balance.X -= newCTx.transfer.X1; 
    updated_balance.Y -= newCTx.transfer.Y;

    #ifdef DEMO
    cout << "4. compute refreshed updated balance" << endl;  
    #endif
    // refresh the updated balance (with random coins r^*)
    Big r_star = random_zz();   
    newCTx.refresh_updated_balance = Twisted_ElGamal_Refresh(enc_pp, Acct_Alice.pk, Acct_Alice.sk, 
                                     updated_balance, r_star);


    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_EQ_PP dlogeq_pp = Get_DLOG_EQ_PP(pp); 
    DLOG_EQ_Instance dlogeq_instance; 
    dlogeq_instance.g1 = updated_balance.Y; 
    dlogeq_instance.g1-= newCTx.refresh_updated_balance.Y; // g1 = Y-Y^* = g^{r-r^*}
    dlogeq_instance.h1 = updated_balance.X; 
    dlogeq_instance.h1-= newCTx.refresh_updated_balance.X; // h1 = X-X^* = pk^{r-r^*}
    dlogeq_instance.g2 = enc_pp.g;                         // g2 = g
    dlogeq_instance.h2 = Acct_Alice.pk;                    // h2 = pk  
    DLOG_EQ_Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_Alice.sk; 

    newCTx.sigma_dlogeq_proof = DLOG_Equality_Auxiliary_Prove(dlogeq_pp, dlogeq_instance, 
                                                              meta_file, dlogeq_witness); 

    #ifdef DEMO
    cout << "5. generate NIZKPoK for correct refreshing and authenticate the meta info" << endl;  
    #endif

    CT_Valid_PP ctvalid_pp = Get_CT_Valid_PP(pp);
    CT_Valid_Instance ctvalid_instance; 
    ctvalid_instance.pk = Acct_Alice.pk; 
    ctvalid_instance.X = newCTx.refresh_updated_balance.X; 
    ctvalid_instance.Y = newCTx.refresh_updated_balance.Y; 
    CT_Valid_Witness ctvalid_witness; 
    ctvalid_witness.r = r_star;  
    ctvalid_witness.v = Acct_Alice.m - v; // m = Twisted_ElGamal_Dec(sk1, balance); 

    newCTx.sigma_ctvalid_proof = CT_Validity_Prove(ctvalid_pp, ctvalid_instance, ctvalid_witness); 

    #ifdef DEMO
    cout << "6. generate NIZKPoK for refreshed updated balance" << endl;  
    #endif

    // aggregrated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp = Get_Bullet_PP(pp);
    Bullet_Instance bullet_instance;
    bullet_instance.C.push_back(newCTx.transfer.Y);
    bullet_instance.C.push_back(newCTx.refresh_updated_balance.Y);

    Bullet_Witness bullet_witness; 
    bullet_witness.r.push_back(pteq_witness.r); 
    bullet_witness.r.push_back(ctvalid_witness.r);
    bullet_witness.v.push_back(pteq_witness.v);
    bullet_witness.v.push_back(ctvalid_witness.v);

    newCTx.bullet_right_enough_proof = Bullet_Prove(bullet_pp, bullet_instance, bullet_witness); 

    #ifdef DEMO
    cout << "7. generate range proofs for transfer amount and updated balance" << endl;    
    #endif

    #ifdef DEMO
    Print_Splitline('-'); 
    #endif

    #ifndef PREPROCESSING
    newCTx.v = v; 
    #endif

    return newCTx; 
}

// check if the given confidential transaction is valid 
bool Verify_CTx(const PGC_PP pp, const PGC_CTx newCTx)
{     
    #ifdef DEMO
    cout << "begin to verify CTx >>>>>>" << endl; 
    #endif

    string str_nonce = nonce_to_string(newCTx.nonce);   
    string meta_file = str_nonce + ".meta";
    string ctx_file  = str_nonce + ".ctx"; 

    bool Validity; 
    bool V1, V2, V3, V4; 
    
    PT_EQ_PP pteq_pp = Get_PT_EQ_PP(pp); 
    PT_EQ_Instance pteq_instance; 
    pteq_instance.pk1 = newCTx.pk1; 
    pteq_instance.pk2 = newCTx.pk2; 
    pteq_instance.X1 = newCTx.transfer.X1;
    pteq_instance.X2 = newCTx.transfer.X2;
    pteq_instance.Y  = newCTx.transfer.Y;

    V1 = PT_Equality_Verify(pteq_pp, pteq_instance, newCTx.sigma_pteq_proof);

    #ifdef DEMO
    if (V1) cout<< "NIZKPoK for plaintext equality accepts" << endl; 
    else cout<< "NIZKPoK for plaintext equality rejects" << endl; 
    #endif

    // refresh the updated balance (with random coins r^*)
    Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 
    Twisted_ElGamal_CT updated_balance = newCTx.balance;
    updated_balance.X -= newCTx.transfer.X1; 
    updated_balance.Y -= newCTx.transfer.Y;

    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_EQ_PP dlogeq_pp = Get_DLOG_EQ_PP(pp); 
    DLOG_EQ_Instance dlogeq_instance; 
    dlogeq_instance.g1 = updated_balance.Y; 
    dlogeq_instance.g1-= newCTx.refresh_updated_balance.Y; 
    dlogeq_instance.h1 = updated_balance.X; 
    dlogeq_instance.h1-= newCTx.refresh_updated_balance.X;
    dlogeq_instance.g2 = enc_pp.g; 
    dlogeq_instance.h2 = newCTx.pk1;  

    V2 = DLOG_Equality_Auxiliary_Verify(dlogeq_pp, dlogeq_instance, meta_file, newCTx.sigma_dlogeq_proof); 

    #ifdef DEMO
    if (V2) cout<< "NIZKPoK for refreshing correctness accepts and meta info is authenticated" << endl; 
    else cout<< "NIZKPoK for refreshing correctness rejects or meta info is unauthenticated" << endl; 
    #endif

    CT_Valid_PP ctvalid_pp = Get_CT_Valid_PP(pp);
    CT_Valid_Instance ctvalid_instance; 
    ctvalid_instance.pk = newCTx.pk1; 
    ctvalid_instance.X = newCTx.refresh_updated_balance.X; 
    ctvalid_instance.Y = newCTx.refresh_updated_balance.Y; 

    V3 = CT_Validity_Verify(ctvalid_pp, ctvalid_instance, newCTx.sigma_ctvalid_proof); 

    #ifdef DEMO
    if (V3) cout<< "NIZKPoK for refresh updated balance accepts" << endl; 
    else cout<< "NIZKPoK for refresh updated balance rejects" << endl; 
    #endif

    // aggregrated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp = Get_Bullet_PP(pp);
    Bullet_Instance bullet_instance;
    bullet_instance.C.push_back(newCTx.transfer.Y);
    bullet_instance.C.push_back(newCTx.refresh_updated_balance.Y);

    V4 = Bullet_Verify(bullet_pp, bullet_instance, newCTx.bullet_right_enough_proof); 

    #ifdef DEMO
    if (V4) cout<< "range proofs for transfer amount and updated balance accept" << endl; 
    else cout<< "range proofs for transfer amount and updated balance reject" << endl;   
    #endif

    Validity = V1 && V2 && V3 && V4; 

    #ifdef DEMO
    if (Validity) cout << ctx_file << " is valid <<<<<<" << endl; 
    else cout << ctx_file << " is invalid <<<<<<" << endl;
    #endif

    #ifdef DEMO
    Print_Splitline('-'); 
    #endif

    return Validity; 
}

/*
    print the details of a confidential transaction 
*/
void Print_CTx(const PGC_CTx newCTx)
{
    Print_Splitline('*'); 
    cout << "CTx contents >>>>>>" << endl; 

    cout << "nonce >>> " << nonce_to_string(newCTx.nonce) << endl; 
    cout << endl; 
    
    cout << "old balance >>>" << endl; 
    Print_Twisted_ElGamal_CT(newCTx.balance);
    cout << endl; 

    cout << "pk1 = " << newCTx.pk1 << endl; 
    cout << "pk2 = " << newCTx.pk2 << endl; 
    cout << endl;  

    cout << "transfer >>>" << endl;
    Print_MR_Twisted_ElGamal_CT(newCTx.transfer);
    cout << endl; 

    cout << "NIZKPoK for plaintext equality >>>" << endl; 
    Print_PT_EQ_Proof(newCTx.sigma_pteq_proof);
    cout << endl; 

    cout << "refresh updated balance >>>" << endl;
    Print_Twisted_ElGamal_CT(newCTx.refresh_updated_balance); 
    cout << endl; 

    cout << "NIZKPoK for refreshing correctness >>>" << endl; 
    Print_DLOG_EQ_Proof(newCTx.sigma_dlogeq_proof);
    cout << endl; 

    cout << "NIZKPoK of refresh updated balance >>>" << endl; 
    Print_CT_Valid_Proof(newCTx.sigma_ctvalid_proof); 
    cout << endl; 

    cout << "range proofs for transfer amount and updated balance >>> " << endl; 
    Print_Bullet_Proof(newCTx.bullet_right_enough_proof); 
    cout << endl; 

    Print_Splitline('*'); 
}


// generate a NIZK proof for CT = Enc(pk_1, pk_2, m) = (pk1^r, pk2^r, g^r h^v)
DLOG_EQ_Proof Testify_CTx(const PGC_PP pp, const PGC_CTx doubtCTx, const string party, const Big v, const Big sk)
{
    DLOG_EQ_PP dlogeq_pp = Get_DLOG_EQ_PP(pp); 
    Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 

    DLOG_EQ_Instance dlogeq_instance; 
    ECn T = enc_pp.h; 
    T *= v; 
    dlogeq_instance.g1 = doubtCTx.transfer.Y; 
    dlogeq_instance.g1-= T;  // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = enc_pp.g;
    if (party == "sender")
    {
        dlogeq_instance.h1 = doubtCTx.transfer.X1; // pk1^r
        dlogeq_instance.h2 = doubtCTx.pk1;  
    }
    else
    {
        dlogeq_instance.h1 = doubtCTx.transfer.X2;  // pk2^r
        dlogeq_instance.h2 = doubtCTx.pk2;  
    }
    DLOG_EQ_Witness dlogeq_witness; 
    dlogeq_witness.w = sk; 

    return DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness); 
} 


// check if the proposed NIZK proof PI for CT = Enc(pk, m) is valid 
bool Check_CTx(const PGC_PP pp, const PGC_CTx doubtCTx, const string party, const Big v, 
               const DLOG_EQ_Proof dlogeq_proof)
{ 
    DLOG_EQ_PP dlogeq_pp = Get_DLOG_EQ_PP(pp); 
    Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 

    DLOG_EQ_Instance dlogeq_instance; 
    ECn T = enc_pp.h; 
    T *= v; 
    dlogeq_instance.g1 = doubtCTx.transfer.Y; 
    dlogeq_instance.g1-= T;              // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = enc_pp.g;
    if (party == "sender")
    {
        dlogeq_instance.h1 = doubtCTx.transfer.X1;
        dlogeq_instance.h2 = doubtCTx.pk1;  
    }
    else
    {
        dlogeq_instance.h1 = doubtCTx.transfer.X2;
        dlogeq_instance.h2 = doubtCTx.pk2;  
    }

    return DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, dlogeq_proof); 
}








