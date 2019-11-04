/****************************************************************************
this hpp implements the PGC functionality 
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

#include "../twisted_elgamal/twisted_elgamal.hpp"        // implement Twisted ElGamal  
#include "../nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../bulletproofs/aggregate_bulletproof.hpp"    // implement Log Size Bulletproof

#define DEMO           // demo mode
//define PREPROCESSING // ifdefined, then use Shanks algorithm to decrypt, else update balance in a tricky way 
//#define DEBUG        // show debug information 

using namespace std; 

const uint64_t SN_LEN = 32;  // sn length

// define the structure for Account
struct PGC_PP{
    uint64_t RANGE_LEN; 
    uint64_t LOG_RANGE_LEN; 
    uint64_t m; // number of sub-argument (for now, we require m to be the power of 2)

    EC_POINT* g; 
    EC_POINT* h;
    EC_POINT* u; // used for inside innerproduct statement
    vector<EC_POINT*> vec_g; 
    vector<EC_POINT*> vec_h; // the pp of innerproduct part    
};

struct PGC_Account{
    string identity;     // id
    EC_POINT* pk;              // public key
    BIGNUM* sk;              // secret key
    Twisted_ElGamal_CT balance;  // current balance
    BIGNUM* m;               // dangerous (should only be used for speeding up the proof generation)
    BIGNUM* sn; 
};

// define the structure for confidential transaction
struct PGC_CTx{
    // sn uniquely defines a transaction
    BIGNUM* sn;                         // serial number

    // memo information
    Twisted_ElGamal_CT balance;        // the left balance of pk1 (not necessrially included)
    EC_POINT* pk1; EC_POINT* pk2;      // sender = pk1, receiver = pk2
    MR_Twisted_ElGamal_CT transfer;    // transfer = (X1 = pk1^r, X2 = pk^2, Y = g^r h^v)
    BIGNUM* v;                         // (defined here only for test, should be remove in the real system)  

    // valid proof
    Plaintext_Equality_Proof plaintext_equality_proof;     // NIZKPoK for transfer ciphertext (X1, X2, Y)
    Bullet_Proof bullet_right_enough_proof;      // aggregrated range proof for v and m-v lie in the right range 
    Twisted_ElGamal_CT refresh_updated_balance;  // fresh encryption of updated balance (randomness is known)
    Plaintext_Knowledge_Proof plaintext_knowledge_proof; // NIZKPoK for refresh ciphertext (X^*, Y^*)
    DLOG_Equality_Proof dlog_equality_proof;     // fresh updated balance is correct
};

void PGC_PP_Free(PGC_PP &pp)
{
    EC_POINT_free(pp.h);
    EC_POINT_free(pp.u); // used for inside innerproduct statement
    vec_gg_free(pp.vec_g); 
    vec_gg_free(pp.vec_h); // the pp of innerproduct part   
}

void PGC_Account_Init(PGC_Account &newAcct){
    newAcct.pk = EC_POINT_new(group);              // public key
    newAcct.sk = BN_new();                         // secret key
    Twisted_ElGamal_CT_Init(newAcct.balance);  // current balance
    newAcct.m = BN_new(); 
    newAcct.sn = BN_new(); 
};

void PGC_Account_Free(PGC_Account newAcct){
    EC_POINT_free(newAcct.pk);              // public key
    BN_free(newAcct.sk);                         // secret key
    Twisted_ElGamal_CT_Free(newAcct.balance);  // current balance
    BN_free(newAcct.m); 
    BN_free(newAcct.sn); 
};

void PGC_CTx_Init(PGC_CTx &newCTx)
{
    newCTx.sn = BN_new(); 
    newCTx.pk1 = EC_POINT_new(group);
    newCTx.pk2 = EC_POINT_new(group);
    Twisted_ElGamal_CT_Init(newCTx.balance); 
    MR_Twisted_ElGamal_CT_Init(newCTx.transfer); 
    newCTx.v = BN_new(); 

    NIZK_Plaintext_Equality_Proof_Init(newCTx.plaintext_equality_proof); 
    NIZK_Plaintext_Knowledge_Proof_Init(newCTx.plaintext_knowledge_proof); 
    NIZK_DLOG_Equality_Proof_Init(newCTx.dlog_equality_proof); 
    Bullet_Proof_Init(newCTx.bullet_right_enough_proof); 
    Twisted_ElGamal_CT_Init(newCTx.refresh_updated_balance); 
}

void PGC_CTx_Free(PGC_CTx &newCTx)
{
    BN_free(newCTx.sn); 
    EC_POINT_free(newCTx.pk1);
    EC_POINT_free(newCTx.pk2);
    Twisted_ElGamal_CT_Free(newCTx.balance); 
    MR_Twisted_ElGamal_CT_Free(newCTx.transfer); 
    BN_free(newCTx.v); 

    NIZK_Plaintext_Equality_Proof_Free(newCTx.plaintext_equality_proof); 
    NIZK_Plaintext_Knowledge_Proof_Free(newCTx.plaintext_knowledge_proof); 
    NIZK_DLOG_Equality_Proof_Free(newCTx.dlog_equality_proof); 
    Bullet_Proof_Free(newCTx.bullet_right_enough_proof); 
    Twisted_ElGamal_CT_Free(newCTx.refresh_updated_balance); 
}

void PGC_memo2string(string &aux_str, PGC_CTx &newCTx)
{
    aux_str += BN_bn2string(newCTx.sn); 
    aux_str += EC_POINT_ep2string(newCTx.balance.X) + EC_POINT_ep2string(newCTx.balance.Y); 
    aux_str += EC_POINT_ep2string(newCTx.pk1) + EC_POINT_ep2string(newCTx.pk2); 
    aux_str += EC_POINT_ep2string(newCTx.transfer.X1) + EC_POINT_ep2string(newCTx.transfer.X2) 
             + EC_POINT_ep2string(newCTx.transfer.Y);
    aux_str += BN_bn2string(newCTx.v);
}

void Get_Bullet_PP(PGC_PP &pp, Bullet_PP &bullet_pp)
{
    bullet_pp.RANGE_LEN = pp.RANGE_LEN; 
    bullet_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN;
    bullet_pp.m = pp.m;  

    bullet_pp.g = pp.g; 
    bullet_pp.h = pp.h; 
    bullet_pp.u = pp.u; 
    bullet_pp.vec_g = pp.vec_g; 
    bullet_pp.vec_h = pp.vec_h; 
}

void Get_Enc_PP(PGC_PP &pp, Twisted_ElGamal_PP &enc_pp)
{
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
}

void Get_Plaintext_Equality_PP(PGC_PP &pp, Plaintext_Equality_PP &pteq_pp)
{
    pteq_pp.g = pp.g; 
    pteq_pp.h = pp.h;  
}

void Get_DLOG_Equality_PP(PGC_PP &pp, DLOG_Equality_PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void Get_Plaintext_Knowledge_PP(PGC_PP &pp, Plaintext_Knowledge_PP &ptknowledge_pp)
{
    ptknowledge_pp.g = pp.g; 
    ptknowledge_pp.h = pp.h; 
}

// converts sn to a length-32 HEX string with leading zeros
string sn_to_string(BIGNUM* x)
{
    stringstream ss; 
    ss << setfill('0') << setw(SN_LEN) << BN_bn2hex(x);
    return ss.str();  
}


// save CTx into sn.ctx file
void Serialize_CTx(PGC_CTx &newCTx, string &ctx_file)
{
    ofstream fout; 
    fout.open(ctx_file, ios::binary); 
    // save sn
    Serialize_ZZ(newCTx.sn, fout); 
    // save balance
    
    // Serialize_Twisted_ElGamal_CT(newCTx.balance, fout); 
    
    // save pk1, pk2, transfer
    Serialize_GG(newCTx.pk1, fout); 
    Serialize_GG(newCTx.pk2, fout); 
    Serialize_MR_Twisted_ElGamal_CT(newCTx.transfer, fout);
    Serialize_ZZ(newCTx.v, fout);
    
    // save proofs
    Serialize_Plaintext_Equality_Proof(newCTx.plaintext_equality_proof, fout);
    Serialize_Twisted_ElGamal_CT(newCTx.refresh_updated_balance, fout); 
    Serialize_DLOG_Equality_Proof(newCTx.dlog_equality_proof, fout); 
    Serialize_Plaintext_Knowledge_Proof(newCTx.plaintext_knowledge_proof, fout); 
    Serialize_Bullet_Proof(newCTx.bullet_right_enough_proof, fout); 
    fout.close();

    // calculate the size of ctx_file
    ifstream fin; 
    fin.open(ctx_file, ios::ate | ios::binary);
    cout << ctx_file << " size = " << fin.tellg() << " bytes" << endl;
    fin.close(); 
}

// recover CTx from sn.ctx file
void Deserialize_CTx(PGC_CTx &newCTx, string &ctx_file)
{
    // Deserialize_CTx(newCTx, ctx_file); 
    ifstream fin; 
    fin.open(ctx_file, ios::binary); 

    // recover sn
    Deserialize_ZZ(newCTx.sn, fin);
    // recover balance
    
    //Deserialize_Twisted_ElGamal_CT(newCTx.balance, fin);
    
    // recover pk1, pk2, transfer
    Deserialize_GG(newCTx.pk1, fin); 
    Deserialize_GG(newCTx.pk2, fin); 
    Deserialize_MR_Twisted_ElGamal_CT(newCTx.transfer, fin);
    Deserialize_ZZ(newCTx.v, fin); 
    // recover proof
    Deserialize_Plaintext_Equality_Proof(newCTx.plaintext_equality_proof, fin);
    Deserialize_Twisted_ElGamal_CT(newCTx.refresh_updated_balance, fin); 
    Deserialize_DLOG_Equality_Proof(newCTx.dlog_equality_proof, fin); 
    Deserialize_Plaintext_Knowledge_Proof(newCTx.plaintext_knowledge_proof, fin); 
    Deserialize_Bullet_Proof(newCTx.bullet_right_enough_proof, fin); 
    fin.close(); 
}

// This function implements Setup algorithm of PGC
void PGC_Setup(int n, int m, PGC_PP &pp)
{
    // generate random generators for Bulletproof (InnerProduct Argument)  
    pp.RANGE_LEN = n; 
    pp.LOG_RANGE_LEN = log2(n); 
    pp.m = m; // number of sub-argument (for now, we require m to be the power of 2)

    pp.g = (EC_POINT*)EC_GROUP_get0_generator(group);
    pp.h = EC_POINT_new(group); random_gg(pp.h);
    pp.u = EC_POINT_new(group); random_gg(pp.u); // used for inside innerproduct statement

    pp.vec_g.resize(n*m); vec_gg_init(pp.vec_g); random_vec_gg(pp.vec_g); 
    pp.vec_h.resize(n*m); vec_gg_init(pp.vec_h); random_vec_gg(pp.vec_h);
}

// create an account for input identity
void Create_Account(PGC_PP &pp, string identity, 
                    BIGNUM* &init_balance, BIGNUM* &sn, 
                    PGC_Account &newAcct)
{
    newAcct.identity = identity;
    BN_copy(newAcct.sn, sn);  
    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP(pp, enc_pp); // enc_pp.g = pp.g, enc_pp.h = pp.h;  

    Twisted_ElGamal_KP keypair; 
    Twisted_ElGamal_KP_Init(keypair); 
    Twisted_ElGamal_KeyGen(enc_pp, keypair); // generate a keypair for Alice
    EC_POINT_copy(newAcct.pk, keypair.pk); 
    BN_copy(newAcct.sk, keypair.sk);  
    Twisted_ElGamal_KP_Free(keypair);  

    BN_copy(newAcct.m, init_balance); 

    // initialize Alice's account value with 0 coins
    BIGNUM* r = BN_new(); 
    Hash_String_ZZ(r, newAcct.identity); 
    Twisted_ElGamal_Enc(enc_pp, newAcct.pk, init_balance, r, newAcct.balance);

    cout << identity << "'s account creation succeeds" << endl;
    print_gg(newAcct.pk, "pk"); 

    cout << identity << "'s initial balance = "; 
    bn_dec_print(init_balance);  
}

// update Account if CTx is valid
bool Update_Account(PGC_PP &pp, PGC_CTx &newCTx, PGC_Account &Acct_Alice, PGC_Account &Acct_Bob)
{
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP(pp, enc_pp); 
    if (EC_POINT_cmp(group, newCTx.pk1, Acct_Alice.pk, bn_ctx) 
        || EC_POINT_cmp(group, newCTx.pk2, Acct_Bob.pk, bn_ctx))
    {
        cout << "sender and recipient addresses do not match" << endl;
        return false;  
    }
    else
    {
        BN_add(Acct_Alice.sn, Acct_Alice.sn, bn_1); 
        // Acct_Alice.balance.X -= newCTx.transfer.X1;
        EC_POINT_sub(Acct_Alice.balance.X, Acct_Alice.balance.X, newCTx.transfer.X1); 
        // Acct_Alice.balance.Y -= newCTx.transfer.Y;
        EC_POINT_sub(Acct_Alice.balance.Y, Acct_Alice.balance.Y, newCTx.transfer.Y); 

        EC_POINT_sub(Acct_Bob.balance.X, Acct_Bob.balance.X, newCTx.transfer.X2); 
        EC_POINT_sub(Acct_Bob.balance.Y, Acct_Bob.balance.Y, newCTx.transfer.Y); 

        #ifdef PREPROCESSING
        Twisted_ElGamal_Dec(enc_pp, Acct_Alice.sk, Acct_Alice.balance, Acct_Alice.m); 
        Twisted_ElGamal_Dec(enc_pp, Acct_Bob.sk, Acct_Bob.balance, Acct_Bob.m);
        #else
        BN_mod_sub(Acct_Alice.m, Acct_Alice.m, newCTx.v, order, bn_ctx); 
        BN_mod_add(Acct_Bob.m, Acct_Bob.m, newCTx.v, order, bn_ctx); 
        #endif 

        return true; 
    }
} 

// reveal the balance 
void Reveal_Balance(PGC_PP pp, PGC_Account Acct, BIGNUM* m)
{
    // Twisted_ElGamal_PP enc_pp = Get_Enc_PP(pp); 
    // return Twisted_ElGamal_Dec(Acct.sk, Acct.balance); 
    BN_copy(m, Acct.m); 
}

// generate a confidential transaction: pk1 transfers v coins to pk2 
void Create_CTx(PGC_PP &pp, PGC_Account &Acct_Alice, BIGNUM* &v, EC_POINT* &pk2, PGC_CTx &newCTx)
{
    #ifdef DEMO
    cout << "begin to genetate CTx >>>>>>" << endl; 
    #endif
    Print_Splitline('-'); 

    BN_copy(newCTx.sn, Acct_Alice.sn);
    string str_sn = sn_to_string(newCTx.sn);  // format string  
    cout << "sn = " << str_sn << endl; 
    string ctx_file  = str_sn + ".ctx"; 

    EC_POINT_copy(newCTx.pk1, Acct_Alice.pk); 
    EC_POINT_copy(newCTx.pk2, pk2); 

    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP(pp, enc_pp); 

    BIGNUM* r = BN_new(); 
    random_zz(r); 

    BN_copy(newCTx.v, v); 
    MR_Twisted_ElGamal_Enc(enc_pp, newCTx.pk1, newCTx.pk2, v, r, newCTx.transfer); 
    // Print_MR_Twisted_ElGamal_CT(newCTx.transfer); 

    EC_POINT_copy(newCTx.balance.X, Acct_Alice.balance.X);
    EC_POINT_copy(newCTx.balance.Y, Acct_Alice.balance.Y);
    // Print_Twisted_ElGamal_CT(newCTx.balance);

    #ifdef DEMO
    cout <<"1. generate memo info of CTx" << endl;  
    #endif

    // begin to generate the valid proof for ctx
    string aux_str = ""; 
    PGC_memo2string(aux_str, newCTx); 

    // generate NIZK proof for validity of transfer              
    Plaintext_Equality_PP pteq_pp; 
    Get_Plaintext_Equality_PP(pp, pteq_pp);
    
    Plaintext_Equality_Instance pteq_instance;
    NIZK_Plaintext_Equality_Instance_Init(pteq_instance); 
    EC_POINT_copy(pteq_instance.pk1, newCTx.pk1); 
    EC_POINT_copy(pteq_instance.pk2, newCTx.pk2); 
    EC_POINT_copy(pteq_instance.X1, newCTx.transfer.X1);
    EC_POINT_copy(pteq_instance.X2, newCTx.transfer.X2);
    EC_POINT_copy(pteq_instance.Y, newCTx.transfer.Y);
    
    Plaintext_Equality_Witness pteq_witness; 
    NIZK_Plaintext_Equality_Witness_Init(pteq_witness); 
    BN_copy(pteq_witness.r, r); 
    BN_copy(pteq_witness.v, v); 

    NIZK_Plaintext_Equality_Prove(pteq_pp, pteq_instance, pteq_witness, newCTx.plaintext_equality_proof);

    #ifdef DEMO
    cout << "2. generate NIZKPoK for plaintext equality" << endl;  
    #endif

    #ifdef DEMO
    cout << "3. compute updated balance" << endl;  
    #endif
    // compute the updated balance
    newCTx.balance.X = Acct_Alice.balance.X;
    newCTx.balance.Y = Acct_Alice.balance.Y;

    Twisted_ElGamal_CT updated_balance; 
    Twisted_ElGamal_CT_Init(updated_balance);
    EC_POINT_sub(updated_balance.X, newCTx.balance.X, newCTx.transfer.X1); 
    EC_POINT_sub(updated_balance.Y, newCTx.balance.Y, newCTx.transfer.Y); 

    #ifdef DEMO
    cout << "4. compute refreshed updated balance" << endl;  
    #endif
    // refresh the updated balance (with random coins r^*)
    BIGNUM* r_star = BN_new(); 
    random_zz(r_star);   
    Twisted_ElGamal_Refresh(enc_pp, Acct_Alice.pk, Acct_Alice.sk, 
                            updated_balance, newCTx.refresh_updated_balance, r_star);


    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP(pp, dlogeq_pp); 
    
    DLOG_Equality_Instance dlogeq_instance;
    NIZK_DLOG_Equality_Instance_Init(dlogeq_instance); 
    // g1 = Y-Y^* = g^{r-r^*}    
    EC_POINT_sub(dlogeq_instance.g1, updated_balance.Y, newCTx.refresh_updated_balance.Y); 
    // h1 = X-X^* = pk^{r-r^*}
    EC_POINT_sub(dlogeq_instance.h1, updated_balance.X, newCTx.refresh_updated_balance.X); 
    
    EC_POINT_copy(dlogeq_instance.g2, enc_pp.g);                         // g2 = g
    EC_POINT_copy(dlogeq_instance.h2, Acct_Alice.pk);                    // h2 = pk  
    DLOG_Equality_Witness dlogeq_witness; 
    NIZK_DLOG_Equality_Witness_Init(dlogeq_witness); 
    BN_copy(dlogeq_witness.w, Acct_Alice.sk); 

    BIGNUM* challenge = BN_new(); 
    Hash_String_ZZ(challenge, aux_str); 

    //Print_DLOG_Equality_Instance(dlogeq_instance); 
    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, aux_str, dlogeq_witness, newCTx.dlog_equality_proof); 


    #ifdef DEMO
    cout << "5. generate NIZKPoK for correct refreshing and authenticate the memo info" << endl;  
    #endif

    Plaintext_Knowledge_PP ptke_pp;
    Get_Plaintext_Knowledge_PP(pp, ptke_pp);

    Plaintext_Knowledge_Instance ptke_instance; 
    NIZK_Plaintext_Knowledge_Instance_Init(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, Acct_Alice.pk); 
    EC_POINT_copy(ptke_instance.X, newCTx.refresh_updated_balance.X); 
    EC_POINT_copy(ptke_instance.Y, newCTx.refresh_updated_balance.Y); 
    
    Plaintext_Knowledge_Witness ptke_witness; 
    NIZK_Plaintext_Knowledge_Witness_Init(ptke_witness);
    BN_copy(ptke_witness.r, r_star); 

    BN_mod_sub(ptke_witness.v, Acct_Alice.m, v, order, bn_ctx); // m = Twisted_ElGamal_Dec(sk1, balance); 

    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, newCTx.plaintext_knowledge_proof); 
    

    #ifdef DEMO
    cout << "6. generate NIZKPoK for refreshed updated balance" << endl;  
    #endif

    // aggregrated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp; 
    Get_Bullet_PP(pp, bullet_pp);
    Bullet_Instance bullet_instance;
    Bullet_Instance_Init(bullet_instance, 2); 
    EC_POINT_copy(bullet_instance.C[0], newCTx.transfer.Y);
    EC_POINT_copy(bullet_instance.C[1], newCTx.refresh_updated_balance.Y);

    Bullet_Witness bullet_witness; 
    Bullet_Witness_Init(bullet_witness, 2); 
    BN_copy(bullet_witness.r[0], pteq_witness.r); 
    BN_copy(bullet_witness.r[1], ptke_witness.r); 
    BN_copy(bullet_witness.v[0], pteq_witness.v);
    BN_copy(bullet_witness.v[1], ptke_witness.v);

    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, newCTx.bullet_right_enough_proof); 

    #ifdef DEMO
    cout << "7. generate range proofs for transfer amount and updated balance" << endl;    
    #endif

    #ifdef DEMO
    Print_Splitline('-'); 
    #endif

    #ifndef PREPROCESSING
    BN_copy(newCTx.v, v); 
    #endif

    Twisted_ElGamal_CT_Free(updated_balance);

    NIZK_Plaintext_Equality_Instance_Free(pteq_instance); 
    NIZK_Plaintext_Equality_Witness_Free(pteq_witness);

    NIZK_DLOG_Equality_Instance_Free(dlogeq_instance);
    NIZK_DLOG_Equality_Witness_Free(dlogeq_witness);

    NIZK_Plaintext_Knowledge_Instance_Free(ptke_instance); 
    NIZK_Plaintext_Knowledge_Witness_Free(ptke_witness); 

    Bullet_Instance_Free(bullet_instance); 
    Bullet_Witness_Free(bullet_witness);

    //cout << memo_file << endl;
    Serialize_CTx(newCTx, ctx_file);  
}

// check if the given confidential transaction is valid 
bool Verify_CTx(PGC_PP pp, PGC_CTx newCTx)
{     
    #ifdef DEMO
    cout << "begin to verify CTx >>>>>>" << endl; 
    #endif

    string str_sn = sn_to_string(newCTx.sn);   
    string ctx_file  = str_sn + ".ctx"; 

    bool Validity; 
    bool V1, V2, V3, V4; 
    
    Plaintext_Equality_PP pteq_pp;
    Get_Plaintext_Equality_PP(pp, pteq_pp); 

    Plaintext_Equality_Instance pteq_instance; 
    NIZK_Plaintext_Equality_Instance_Init(pteq_instance); 
    EC_POINT_copy(pteq_instance.pk1, newCTx.pk1);
    EC_POINT_copy(pteq_instance.pk2, newCTx.pk2);
    EC_POINT_copy(pteq_instance.X1, newCTx.transfer.X1);
    EC_POINT_copy(pteq_instance.X2, newCTx.transfer.X2);
    EC_POINT_copy(pteq_instance.Y, newCTx.transfer.Y);

    V1 = NIZK_Plaintext_Equality_Verify(pteq_pp, pteq_instance, newCTx.plaintext_equality_proof);
    
    NIZK_Plaintext_Equality_Instance_Free(pteq_instance);

    #ifdef DEMO
    if (V1) cout<< "NIZKPoK for plaintext equality accepts" << endl; 
    else cout<< "NIZKPoK for plaintext equality rejects" << endl; 
    #endif

    // check V2
    string aux_str = ""; 
    PGC_memo2string(aux_str, newCTx); 

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP(pp, enc_pp); 

    Twisted_ElGamal_CT updated_balance; 
    Twisted_ElGamal_CT_Init(updated_balance);
    EC_POINT_sub(updated_balance.X, newCTx.balance.X, newCTx.transfer.X1); 
    EC_POINT_sub(updated_balance.Y, newCTx.balance.Y, newCTx.transfer.Y); 

    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP(pp, dlogeq_pp);

    DLOG_Equality_Instance dlogeq_instance; 
    NIZK_DLOG_Equality_Instance_Init(dlogeq_instance); 

    EC_POINT_sub(dlogeq_instance.g1, updated_balance.Y, newCTx.refresh_updated_balance.Y); 
    EC_POINT_sub(dlogeq_instance.h1, updated_balance.X, newCTx.refresh_updated_balance.X); 
    EC_POINT_copy(dlogeq_instance.g2, enc_pp.g); 
    EC_POINT_copy(dlogeq_instance.h2, newCTx.pk1);  

    //Print_DLOG_Equality_Instance(dlogeq_instance); 

    BIGNUM* challenge = BN_new(); 
    Hash_String_ZZ(challenge, aux_str); 
    print_zz(challenge, "challenge");

    V2 = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, aux_str, newCTx.dlog_equality_proof); 

    Twisted_ElGamal_CT_Free(updated_balance);
    NIZK_DLOG_Equality_Instance_Free(dlogeq_instance); 

    #ifdef DEMO
    if (V2) cout<< "NIZKPoK for refreshing correctness accepts and memo info is authenticated" << endl; 
    else cout<< "NIZKPoK for refreshing correctness rejects or memo info is unauthenticated" << endl; 
    #endif

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP(pp, ptke_pp);

    Plaintext_Knowledge_Instance ptke_instance; 
    NIZK_Plaintext_Knowledge_Instance_Init(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, newCTx.pk1); 
    EC_POINT_copy(ptke_instance.X, newCTx.refresh_updated_balance.X); 
    EC_POINT_copy(ptke_instance.Y, newCTx.refresh_updated_balance.Y); 

    V3 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, newCTx.plaintext_knowledge_proof); 

    NIZK_Plaintext_Knowledge_Instance_Free(ptke_instance); 

    #ifdef DEMO
    if (V3) cout<< "NIZKPoK for refresh updated balance accepts" << endl; 
    else cout<< "NIZKPoK for refresh updated balance rejects" << endl; 
    #endif

    // aggregrated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp; 
    Get_Bullet_PP(pp, bullet_pp);

    Bullet_Instance bullet_instance;
    Bullet_Instance_Init(bullet_instance, 2); 
    EC_POINT_copy(bullet_instance.C[0], newCTx.transfer.Y);
    EC_POINT_copy(bullet_instance.C[1], newCTx.refresh_updated_balance.Y);

    V4 = Bullet_Verify(bullet_pp, bullet_instance, newCTx.bullet_right_enough_proof); 

    Bullet_Instance_Free(bullet_instance); 

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
void Print_CTx(PGC_CTx newCTx)
{
    Print_Splitline('*'); 
    cout << "CTx contents >>>>>>" << endl; 

    cout << "sn >>> " << sn_to_string(newCTx.sn) << endl; 
    cout << endl; 
    
    cout << "old balance >>>" << endl; 
    Print_Twisted_ElGamal_CT(newCTx.balance);
    cout << endl; 

    print_gg(newCTx.pk1, "pk1"); 
    print_gg(newCTx.pk2, "pk2"); 
    cout << endl;  

    cout << "transfer >>>" << endl;
    Print_MR_Twisted_ElGamal_CT(newCTx.transfer);
    cout << endl; 

    cout << "NIZKPoK for plaintext equality >>>" << endl; 
    Print_Plaintext_Equality_Proof(newCTx.plaintext_equality_proof);
    cout << endl; 

    cout << "refresh updated balance >>>" << endl;
    Print_Twisted_ElGamal_CT(newCTx.refresh_updated_balance); 
    cout << endl; 

    cout << "NIZKPoK for refreshing correctness >>>" << endl; 
    Print_DLOG_Equality_Proof(newCTx.dlog_equality_proof);
    cout << endl; 

    cout << "NIZKPoK of refresh updated balance >>>" << endl; 
    Print_Plaintext_Knowledge_Proof(newCTx.plaintext_knowledge_proof); 
    cout << endl; 

    cout << "range proofs for transfer amount and updated balance >>> " << endl; 
    Print_Bullet_Proof(newCTx.bullet_right_enough_proof); 
    cout << endl; 

    Print_Splitline('*'); 
}

void Print_PGC_PP(PGC_PP pp)
{
    cout << "RANGE_LEN = " << pp.RANGE_LEN << endl; 
    cout << "LOG_RANGE_LEN = " << pp.LOG_RANGE_LEN << endl; 
    cout << "m = " << pp.m << endl; // number of sub-argument (for now, we require m to be the power of 2)

    print_gg(pp.g, "g"); 
    print_gg(pp.h, "h");
    print_gg(pp.u, "u"); 
    print_vec_gg(pp.vec_g, "vec_g"); 
    print_vec_gg(pp.vec_h, "vec_h"); 
}

// generate a NIZK proof for CT = Enc(pk_1, pk_2, m) = (pk1^r, pk2^r, g^r h^v)
void Justify_CTx(PGC_PP &pp, PGC_CTx &doubtCTx, string party, BIGNUM* &v, BIGNUM* &sk, 
                 DLOG_Equality_Proof &dlogeq_proof)
{
    DLOG_Equality_PP dlogeq_pp;
    Get_DLOG_Equality_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance; 
    NIZK_DLOG_Equality_Instance_Init(dlogeq_instance); 
    EC_POINT* T = EC_POINT_new(group); 
    EC_POINT_mul(group, T, NULL, enc_pp.h, v, bn_ctx); 
    
    EC_POINT_copy(dlogeq_instance.g1, doubtCTx.transfer.Y); 
    EC_POINT_sub(dlogeq_instance.g1, dlogeq_instance.g1, T); // g1 = g^r h^v - h^v = g^r
    EC_POINT_copy(dlogeq_instance.g2, enc_pp.g); 
    if (party == "sender")
    {
        EC_POINT_copy(dlogeq_instance.h1, doubtCTx.transfer.X1); // pk1^r
        EC_POINT_copy(dlogeq_instance.h2, doubtCTx.pk1);  
    }
    else
    {
        EC_POINT_copy(dlogeq_instance.h1, doubtCTx.transfer.X2);  // pk2^r
        EC_POINT_copy(dlogeq_instance.h2, doubtCTx.pk2);  
    }
    DLOG_Equality_Witness dlogeq_witness; 
    NIZK_DLOG_Equality_Witness_Init(dlogeq_witness);
    BN_copy(dlogeq_witness.w, sk); 

    EC_POINT_free(T);

    string indicator = ""; 
    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, indicator, dlogeq_witness, dlogeq_proof); 
} 


// check if the proposed NIZK proof PI for CT = Enc(pk, m) is valid 
bool Check_CTx(PGC_PP &pp, PGC_CTx &doubtCTx, string party, BIGNUM* &v, 
               DLOG_Equality_Proof &dlogeq_proof)
{ 
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance; 
    NIZK_DLOG_Equality_Instance_Init(dlogeq_instance);
    EC_POINT* T = EC_POINT_new(group); 
    EC_POINT_mul(group, T, NULL, enc_pp.h, v, bn_ctx); //T *= v;
    EC_POINT_sub(dlogeq_instance.g1, doubtCTx.transfer.Y, T);  // g1 = g^r h^v - h^v = g^r
    EC_POINT_copy(dlogeq_instance.g2, enc_pp.g);
    if (party == "sender")
    {
        EC_POINT_copy(dlogeq_instance.h1, doubtCTx.transfer.X1);
        EC_POINT_copy(dlogeq_instance.h2, doubtCTx.pk1);  
    }
    else
    {
        EC_POINT_copy(dlogeq_instance.h1, doubtCTx.transfer.X2);
        EC_POINT_copy(dlogeq_instance.h2, doubtCTx.pk2);  
    }
    bool validity;
    string indicator = "";
    validity = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, indicator, dlogeq_proof); 
    NIZK_DLOG_Equality_Instance_Free(dlogeq_instance); 
    EC_POINT_free(T); 

    return validity; 
}








