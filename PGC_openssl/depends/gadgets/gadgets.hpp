/***********************************************************************************
this hpp implements two useful gadgets for proving encrypted message lie in the range 
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef __GADGETS__
#define __GADGETS__

#include "../twisted_elgamal/twisted_elgamal.hpp"        // implement Twisted ElGamal  
#include "../nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../bulletproofs/aggregate_bulletproof.hpp"    // implement Log Size Bulletproof


struct Gadget_PP{  
    size_t RANGE_LEN; // the maximum coin value is 2^RANGE_LEN 
    size_t LOG_RANGE_LEN; // this parameter will be used by Bulletproof
    size_t TUNNING; 
    size_t IO_THREAD_NUM; 
    size_t DEC_THREAD_NUM; // used by twisted ElGamal

    EC_POINT *g; 
    EC_POINT *h;
    EC_POINT *u; // used for inside innerproduct statement
    vector<EC_POINT *> vec_g; 
    vector<EC_POINT *> vec_h; // the pp of innerproduct part     
};

void Get_Enc_PP_from_Gadget_PP(Gadget_PP &pp, Twisted_ElGamal_PP &enc_pp)
{
    enc_pp.MSG_LEN = pp.RANGE_LEN;  
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    enc_pp.TUNNING = pp.TUNNING; 
    enc_pp.DEC_THREAD_NUM = pp.DEC_THREAD_NUM; 
    enc_pp.IO_THREAD_NUM = pp.IO_THREAD_NUM; 
}

void Get_Bullet_PP_from_Gadget_PP(Gadget_PP &pp, Bullet_PP &bullet_pp)
{
    bullet_pp.RANGE_LEN = pp.RANGE_LEN; 
    bullet_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN; 
    bullet_pp.AGG_NUM = 1; 

    bullet_pp.g = pp.g; 
    bullet_pp.h = pp.h;  
    bullet_pp.u = pp.u; 
    bullet_pp.vec_g = pp.vec_g; 
    bullet_pp.vec_h = pp.vec_h; 
}

void Get_DLOG_Equality_PP_from_Gadget_PP(Gadget_PP &pp, DLOG_Equality_PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void Get_Plaintext_Knowledge_PP_from_Gadget_PP(Gadget_PP &pp, Plaintext_Knowledge_PP &ptknowledge_pp)
{
    ptknowledge_pp.g = pp.g; 
    ptknowledge_pp.h = pp.h; 
}

/* 
    the default range size is LARGE_LEN, the exact range size is SMALL_LEN 
    this function get the difference
*/
void Get_range_size_diff(size_t &LARGE_LEN, size_t &SMALL_LEN, BIGNUM *&range_size_diff)
{
    BIGNUM *large_range_size = BN_new(); 
    BN_set_word(large_range_size, pow(2, LARGE_LEN)); 
    BIGNUM *small_range_size = BN_new(); 
    BN_set_word(small_range_size, pow(2, SMALL_LEN)); 
    BN_sub(range_size_diff, large_range_size, small_range_size);
    BN_free(large_range_size); 
    BN_free(small_range_size);   
}

/* adjust Bullet instance */
void Adjust_Bullet_Instance(Bullet_PP &bullet_pp, BIGNUM *&bn_diff, Bullet_Instance &bullet_instance)
{
    EC_POINT *Y = EC_POINT_new(group); 
    EC_POINT_mul(group, Y, NULL, bullet_pp.h, bn_diff, bn_ctx);
    EC_POINT_add(group, bullet_instance.C[0], bullet_instance.C[0], Y, bn_ctx); 
    EC_POINT_free(Y); 
}

/* adjust Bullet witness */
void Adjust_Bullet_Witness(BIGNUM *&bn_diff, Bullet_Witness &bullet_witness)
{
    BN_add(bullet_witness.v[0], bullet_witness.v[0], bn_diff); 
}


struct Gadget1_Proof{  
    Plaintext_Knowledge_Proof ptke_proof; 
    Bullet_Proof bullet_proof;     
};

void Gadget1_Proof_new(Gadget1_Proof &proof)
{
    NIZK_Plaintext_Knowledge_Proof_new(proof.ptke_proof); 
    Bullet_Proof_new(proof.bullet_proof); 
}

void Gadget1_Proof_free(Gadget1_Proof &proof)
{
    NIZK_Plaintext_Knowledge_Proof_free(proof.ptke_proof); 
    Bullet_Proof_free(proof.bullet_proof); 
}

struct Gadget2_Proof{
    Twisted_ElGamal_CT refresh_CT; 
    DLOG_Equality_Proof dlogeq_proof;  
    Plaintext_Knowledge_Proof ptke_proof; 
    Bullet_Proof bullet_proof;     
};

void Gadget2_Proof_new(Gadget2_Proof &proof)
{
    Twisted_ElGamal_CT_new(proof.refresh_CT); 
    NIZK_DLOG_Equality_Proof_new(proof.dlogeq_proof); 
    NIZK_Plaintext_Knowledge_Proof_new(proof.ptke_proof); 
    Bullet_Proof_new(proof.bullet_proof); 
}

void Gadget2_Proof_free(Gadget2_Proof &proof)
{
    Twisted_ElGamal_CT_free(proof.refresh_CT); 
    NIZK_DLOG_Equality_Proof_free(proof.dlogeq_proof); 
    NIZK_Plaintext_Knowledge_Proof_free(proof.ptke_proof); 
    Bullet_Proof_free(proof.bullet_proof); 
}

void Gadget1_Prove(Gadget_PP &gadget_pp, EC_POINT *&pk, Twisted_ElGamal_CT &CT, BIGNUM *&sk, 
                   BIGNUM *&r, BIGNUM *&m, size_t &RANGE_LEN, Gadget1_Proof &proof)
{
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(gadget_pp, enc_pp);  

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(gadget_pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    NIZK_Plaintext_Knowledge_Instance_new(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, pk); 
    EC_POINT_copy(ptke_instance.X, CT.X);
    EC_POINT_copy(ptke_instance.Y, CT.Y);

    Plaintext_Knowledge_Witness ptke_witness;
    NIZK_Plaintext_Knowledge_Witness_new(ptke_witness);
    BN_copy(ptke_witness.v, m);
    BN_copy(ptke_witness.r, r);

    string transcript_str = ""; 
    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof);  
    
    NIZK_Plaintext_Knowledge_Instance_free(ptke_instance); 
    NIZK_Plaintext_Knowledge_Witness_free(ptke_witness); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(gadget_pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    Bullet_Instance_new(bullet_pp, bullet_instance); 
    EC_POINT_copy(bullet_instance.C[0], CT.Y); 

    Bullet_Witness bullet_witness;
    Bullet_Witness_new(bullet_pp, bullet_witness); 
    BN_copy(bullet_witness.r[0], r);
    BN_copy(bullet_witness.v[0], m);

    BIGNUM *bn_diff = BN_new(); 
    Get_range_size_diff(bullet_pp.RANGE_LEN, RANGE_LEN, bn_diff); 
    Adjust_Bullet_Instance(bullet_pp, bn_diff, bullet_instance); 
    Adjust_Bullet_Witness(bn_diff, bullet_witness); 
    BN_free(bn_diff); 

    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
    Bullet_Instance_free(bullet_instance); 
    Bullet_Witness_free(bullet_witness); 
}

bool Gadget1_Verify(Gadget_PP &gadget_pp, EC_POINT *&pk, Twisted_ElGamal_CT &CT, 
                    size_t &RANGE_LEN, Gadget1_Proof &proof)
{
    bool V1, V2; 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(gadget_pp, enc_pp);  

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(gadget_pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    NIZK_Plaintext_Knowledge_Instance_new(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, pk); 
    EC_POINT_copy(ptke_instance.X, CT.X);
    EC_POINT_copy(ptke_instance.Y, CT.Y);

    string transcript_str = ""; 
    V1 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof);  
    NIZK_Plaintext_Knowledge_Instance_free(ptke_instance); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(gadget_pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    Bullet_Instance_new(bullet_pp, bullet_instance); 
    EC_POINT_copy(bullet_instance.C[0], CT.Y); 

    BIGNUM *bn_diff = BN_new(); 
    Get_range_size_diff(bullet_pp.RANGE_LEN, RANGE_LEN, bn_diff); 
    Adjust_Bullet_Instance(bullet_pp, bn_diff, bullet_instance); 
    BN_free(bn_diff); 

    V2 = Bullet_Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof);
    Bullet_Instance_free(bullet_instance); 

    return V1 && V2; 
}


void Gadget2_Prove(Gadget_PP &gadget_pp, EC_POINT *&pk, Twisted_ElGamal_CT &CT, BIGNUM *&sk, 
                   size_t &RANGE_LEN, Gadget2_Proof &proof)
{
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(gadget_pp, enc_pp);  
    BIGNUM *r_star = BN_new(); 
    BN_random(r_star); 
    Twisted_ElGamal_ReRand(enc_pp, pk, sk, CT, proof.refresh_CT, r_star); 

    BIGNUM *m = BN_new(); 
    Twisted_ElGamal_Parallel_Dec(enc_pp, sk, CT, m); 

    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_Gadget_PP(gadget_pp, dlogeq_pp); 
    DLOG_Equality_Instance dlogeq_instance;
    NIZK_DLOG_Equality_Instance_new(dlogeq_instance); 
    EC_POINT_copy(dlogeq_instance.g1, enc_pp.g); 
    EC_POINT_copy(dlogeq_instance.h1, pk); 
    EC_POINT_sub(dlogeq_instance.g2, proof.refresh_CT.Y, CT.Y);  
    EC_POINT_sub(dlogeq_instance.h2, proof.refresh_CT.X, CT.X);

    DLOG_Equality_Witness dlogeq_witness;
    NIZK_DLOG_Equality_Witness_new(dlogeq_witness);
    BN_copy(dlogeq_witness.w, sk);  

    string transcript_str = ""; 
    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, proof.dlogeq_proof);  

    NIZK_DLOG_Equality_Instance_free(dlogeq_instance); 
    NIZK_DLOG_Equality_Witness_free(dlogeq_witness); 
    
    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(gadget_pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    NIZK_Plaintext_Knowledge_Instance_new(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, pk); 
    EC_POINT_copy(ptke_instance.X, proof.refresh_CT.X); 
    EC_POINT_copy(ptke_instance.Y, proof.refresh_CT.Y);

    Plaintext_Knowledge_Witness ptke_witness; 
    NIZK_Plaintext_Knowledge_Witness_new(ptke_witness); 
    BN_copy(ptke_witness.v, m); 
    BN_copy(ptke_witness.r, r_star); 

    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof); 

    NIZK_Plaintext_Knowledge_Instance_free(ptke_instance); 
    NIZK_Plaintext_Knowledge_Witness_free(ptke_witness); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(gadget_pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    Bullet_Instance_new(bullet_pp, bullet_instance); 
    EC_POINT_copy(bullet_instance.C[0], proof.refresh_CT.Y); 

    Bullet_Witness bullet_witness;
    Bullet_Witness_new(bullet_pp, bullet_witness); 
    BN_copy(bullet_witness.r[0], r_star);
    BN_copy(bullet_witness.v[0], m);

    BIGNUM *bn_diff = BN_new(); 
    Get_range_size_diff(bullet_pp.RANGE_LEN, RANGE_LEN, bn_diff); 
    Adjust_Bullet_Instance(bullet_pp, bn_diff, bullet_instance); 
    Adjust_Bullet_Witness(bn_diff, bullet_witness); 
    BN_free(bn_diff); 

    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
    Bullet_Instance_free(bullet_instance); 
    Bullet_Witness_free(bullet_witness); 

    BN_free(r_star);
    BN_free(m); 
}

bool Gadget2_Verify(Gadget_PP &gadget_pp, EC_POINT *&pk, Twisted_ElGamal_CT &CT, 
                    size_t &RANGE_LEN, Gadget2_Proof &proof)
{
    bool V1, V2, V3; 

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(gadget_pp, enc_pp);  

    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_Gadget_PP(gadget_pp, dlogeq_pp); 
    DLOG_Equality_Instance dlogeq_instance;
    NIZK_DLOG_Equality_Instance_new(dlogeq_instance); 
    EC_POINT_copy(dlogeq_instance.g1, enc_pp.g); 
    EC_POINT_copy(dlogeq_instance.h1, pk); 
    EC_POINT_sub(dlogeq_instance.g2, proof.refresh_CT.Y, CT.Y);  
    EC_POINT_sub(dlogeq_instance.h2, proof.refresh_CT.X, CT.X);

    string transcript_str = ""; 
    V1 = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, transcript_str, proof.dlogeq_proof);  
    NIZK_DLOG_Equality_Instance_free(dlogeq_instance); 

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(gadget_pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    NIZK_Plaintext_Knowledge_Instance_new(ptke_instance); 
    EC_POINT_copy(ptke_instance.pk, pk); 
    EC_POINT_copy(ptke_instance.X, proof.refresh_CT.X); 
    EC_POINT_copy(ptke_instance.Y, proof.refresh_CT.Y);

    V2 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof); 
    NIZK_Plaintext_Knowledge_Instance_free(ptke_instance); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(gadget_pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    Bullet_Instance_new(bullet_pp, bullet_instance); 
    EC_POINT_copy(bullet_instance.C[0], proof.refresh_CT.Y);

    BIGNUM *bn_diff = BN_new(); 
    Get_range_size_diff(bullet_pp.RANGE_LEN, RANGE_LEN, bn_diff); 
    Adjust_Bullet_Instance(bullet_pp, bn_diff, bullet_instance); 
    BN_free(bn_diff);  

    V3 = Bullet_Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof);
    Bullet_Instance_free(bullet_instance);  

    return V1 && V2 && V3; 
}

#endif
