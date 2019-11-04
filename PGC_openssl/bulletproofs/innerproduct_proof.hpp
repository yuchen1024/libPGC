/***********************************************************************************
this hpp implements the inner product proof system  
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
#include <algorithm> 
#include <vector>
#include <cmath>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace std; 

// define the structure of InnerProduct Proof
struct InnerProduct_PP
{
    uint64_t VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
    uint64_t LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 
    
    // size of the vector = VECTOR_LEN
    vector<EC_POINT*> vec_g; 
    vector<EC_POINT*> vec_h; 
};

//P = vec_g^vec_a vec_h^vec_b u^<vec_a, vec_b>
struct InnerProduct_Instance
{
    EC_POINT *u; 
    EC_POINT *P; 
};

struct InnerProduct_Witness
{
    // size of the vector = VECTOR_LEN
    vector<BIGNUM*> vec_a; 
    vector<BIGNUM*> vec_b; 
};

struct InnerProduct_Proof
{
    // size of the vector = LOG_VECTOR_LEN
    vector<EC_POINT*> vec_L; 
    vector<EC_POINT*> vec_R; 
    BIGNUM *a; 
    BIGNUM *b;     
};

void Serialize_InnerProduct_Proof(InnerProduct_Proof &proof, ofstream &fout)
{
    Serialize_vec_GG(proof.vec_L, fout);
    Serialize_vec_GG(proof.vec_R, fout);

    Serialize_ZZ(proof.a, fout); 
    Serialize_ZZ(proof.b, fout); 
}

void Deserialize_InnerProduct_Proof(InnerProduct_Proof &proof, ifstream &fin)
{
    Deserialize_vec_GG(proof.vec_L, fin);
    Deserialize_vec_GG(proof.vec_R, fin);

    Deserialize_ZZ(proof.a, fin); 
    Deserialize_ZZ(proof.b, fin); 
}

void Print_InnerProduct_PP(InnerProduct_PP &pp)
{
    cout << "vector length = " << pp.VECTOR_LEN << endl;   
    cout << "log vector length = " << pp.LOG_VECTOR_LEN << endl;   
    
    // size of the vector = VECTOR_LEN
    print_vec_gg(pp.vec_g, "g"); 
    print_vec_gg(pp.vec_h, "h"); 

};

void Print_InnerProduct_Witness(InnerProduct_Witness &witness)
{
    print_vec_zz(witness.vec_a, "a"); 
    print_vec_zz(witness.vec_b, "b"); 
};

void Print_InnerProduct_Instance(InnerProduct_Instance &instance)
{
    print_gg(instance.P, "ip_instance.P"); 
    print_gg(instance.u, "ip_instance.u"); 
};

void Print_InnerProduct_Proof(InnerProduct_Proof &proof)
{
    print_vec_gg(proof.vec_L, "L");
    print_vec_gg(proof.vec_R, "R");
    print_zz(proof.a, "proof.a"); 
    print_zz(proof.b, "proof.b"); 
};

void InnerProduct_PP_Init(InnerProduct_PP &pp, uint64_t VECTOR_LEN)
{
    pp.vec_g.resize(VECTOR_LEN); 
    pp.vec_h.resize(VECTOR_LEN); 
    for(size_t i = 0; i < VECTOR_LEN; i++)
    {
        pp.vec_g[i] = EC_POINT_new(group); 
        pp.vec_h[i] = EC_POINT_new(group);
    }
}

void InnerProduct_Instance_Init(InnerProduct_Instance &instance)
{
    instance.u = EC_POINT_new(group); 
    instance.P = EC_POINT_new(group);
}

void InnerProduct_Witness_Init(InnerProduct_Witness &witness, uint64_t VECTOR_LEN)
{
    witness.vec_a.resize(VECTOR_LEN); 
    witness.vec_b.resize(VECTOR_LEN); 
    for(size_t i = 0; i < VECTOR_LEN; i++)
    {
        witness.vec_a[i] = BN_new(); 
        witness.vec_b[i] = BN_new();
    }
}

void InnerProduct_Proof_Init(InnerProduct_Proof &proof)
{
    proof.a = BN_new(); 
    proof.b = BN_new(); 
}

void InnerProduct_PP_Free(InnerProduct_PP &pp)
{
    for(size_t i = 0; i < pp.VECTOR_LEN; i++)
    {
        EC_POINT_free(pp.vec_g[i]); 
        EC_POINT_free(pp.vec_h[i]);
    }
}

void InnerProduct_Instance_Free(InnerProduct_Instance &instance)
{
    EC_POINT_free(instance.u); 
    EC_POINT_free(instance.P);
}

void InnerProduct_Witness_Free(InnerProduct_Witness &witness)
{
    for(size_t i = 0; i < witness.vec_a.size(); i++)
    {
        BN_free(witness.vec_a[i]); 
        BN_free(witness.vec_b[i]);
    }
}

void InnerProduct_Proof_Free(InnerProduct_Proof &proof)
{
    for(size_t i = 0; i < proof.vec_L.size(); i++)
    {
        EC_POINT_free(proof.vec_L[i]); 
        EC_POINT_free(proof.vec_R[i]);
    }
    BN_free(proof.a); 
    BN_free(proof.b); 
}

//vector operations

// generate a random ZZ vector
void gen_random_vec_zz(vector<BIGNUM *>& vec_a)
{
    for(size_t i = 0; i < vec_a.size(); i++)
    {
        random_zz(vec_a[i]); 
    }
}

// compute the jth bit of a big integer i (count from little endian to big endian)
inline uint64_t big_parse_binary(BIGNUM* i, uint64_t j)
{
    BIGNUM *bn_bit = BN_new(); 
    BN_copy(bn_bit, i); 

    BN_rshift(bn_bit, bn_bit, j);
    BN_mod(bn_bit, bn_bit, bn_2, bn_ctx);

    uint64_t bit; 
    if (BN_is_one(bn_bit)) bit = 1; 
    else bit = 0;
    BN_free(bn_bit); 
    return bit;  
}


// compute the jth bit of a small integer num \in [0, 2^{m-1}] (count from big endian to little endian)
inline uint64_t small_parse_binary(uint64_t num, uint64_t j, uint64_t m)
{ 
    uint64_t cursor = 1 << (m-1); // set cursor = 2^{m-1} = 1||0...0---(m-1)
    
    for (uint64_t i = 0; i < j; i++)
    { 
        cursor = cursor >> 1;
    }
    if ((num&cursor) != 0) return 1;
    else return 0;   
}

// generate a^n = (a^0, a^1, a^2, ..., a^{n-1})
inline void gen_vec_zz_power(vector<BIGNUM*> &result, BIGNUM* &a)
{
    BN_one(result[0]); // set result[0] = 1
    for (size_t i = 1; i < result.size(); i++)
    {
        BN_mod_mul(result[i], a, result[i-1], order, bn_ctx); // result[i] = result[i-1]*a % order
    }
}

// assign left or right part of a Zn vector
inline void vec_zz_assign(vector<BIGNUM*> &result, vector<BIGNUM*> &vec_a, string selector)
{
    size_t start_point; 
    if (selector == "left") start_point = 0; 
    if (selector == "right") start_point = vec_a.size()/2; 
    
    for(size_t i = 0; i < result.size(); i++){
        BN_copy(result[i], vec_a[start_point + i]); 
    }
}

// assign left or right part of an ECn vector
inline void vec_gg_assign(vector<EC_POINT*> &result, vector<EC_POINT*> &vec_g, string selector)
{
    size_t start_point; 
    if (selector == "left") start_point = 0; 
    if (selector == "right") start_point = vec_g.size()/2; 
    
    for(size_t i = 0; i < result.size(); i++){
        EC_POINT_copy(result[i], vec_g[start_point + i]); 
    }
}

// sum_i^n a[i]*b[i]
inline void inner_product(BIGNUM* &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    BN_zero(result); // set result = 0

    BIGNUM *product = BN_new(); 

    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }   
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mul(product, vec_a[i], vec_b[i], bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
        BN_add(result, result, product);     // result = (result+product) mod order
    }
    BN_mod(result, result, order, bn_ctx);
}

// g[i] = g[i]+h[i]
inline void vec_gg_add(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_g, vector<EC_POINT *> &vec_h)
{
    if (vec_g.size()!= vec_h.size()) 
    {
        throw "vector size does not match!";
    }
    for (size_t i = 0; i < vec_g.size(); i++) 
    {
        EC_POINT_add(group, result[i], vec_g[i], vec_h[i], bn_ctx); 
    }
}

// a[i] = (a[i]+b[i]) mod order
inline void vec_zz_add(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_add(result[i], vec_a[i], vec_b[i], order, bn_ctx);   
    }
}

// a[i] = (a[i]-b[i]) mod order
inline void vec_zz_sub(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_sub(result[i], vec_a[i], vec_b[i], order, bn_ctx);
    } 
}

// c[i] = a[i]*b[i] mod order
inline void vec_zz_product(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_mul(result[i], vec_a[i], vec_b[i], order, bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
    }
}

// compute the inverse of a[i]
inline void vec_zz_inverse(vector<BIGNUM *> &vec_a_inverse, vector<BIGNUM *> &vec_a)
{
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_inverse(vec_a_inverse[i], vec_a[i], order, bn_ctx); 
    }
}

// vec_g = c * vec_g
inline void vec_gg_scalar(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_g, BIGNUM* &c)
{
    for (size_t i = 0; i < vec_g.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_g[i], c, bn_ctx); // result[i] = vec_g[i]^c
    } 
}

// vec_a = c * vec_a
inline void vec_zz_scalar(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, BIGNUM* &c)
{
    for (size_t i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_mul(result[i], vec_a[i], c, order, bn_ctx);
    } 
}

inline void vec_zz_negative(vector<BIGNUM*> &result)
{
    for (size_t i = 0; i < result.size(); i++) 
    {
        BN_mod_negative(result[i]);
    } 
}

// g[i] = a[i]*g[i]
inline void vec_gg_product(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_g, vector<BIGNUM *> &vec_a)
{
    if (vec_g.size() != vec_a.size()) 
    {
        throw "vector size does not match!";
    } 
    for (size_t i = 0; i < vec_g.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_g[i], vec_a[i], bn_ctx); // result[i] = vec_g[i]^vec_a[i]
    } 
}

// sum_{i=1^n} a[i]*g[i]
inline void vec_gg_mul(EC_POINT* &result, vector<EC_POINT *> &vec_g, vector<BIGNUM *> &vec_a)
{
    if (vec_g.size() != vec_a.size()) {
        throw "vector size does not match!";
    }
    EC_POINTs_mul(group, result, NULL, vec_g.size(), 
    (const EC_POINT**)vec_g.data(), (const BIGNUM**)vec_a.data(), bn_ctx); // return result = h_i^e_i
}

/* 
    this module is used to enable fast verification (cf pp.15)
*/
void compute_vec_ss(vector<BIGNUM *> &vec_s, vector<BIGNUM *> &vec_x, vector<BIGNUM *> &vec_x_inverse)
{
    int m = vec_x.size(); 
    int n = vec_s.size(); //int n = pow(2, m); 
    
    // compute s[0], ..., s[i-1]
    // vector<BIGNUM *> vec_s(n);
    int i, j, flag; 
    for (i = 0; i < n; i++)
    {
        BN_one(vec_s[i]); // set bn_1 = 1
        for (j = 0; j < m; j++)
        {
            flag = small_parse_binary(i, j, m); 
            if (flag == 1){
                BN_mod_mul(vec_s[i], vec_s[i], vec_x[j], order, bn_ctx);
            } 
            else{
                BN_mod_mul(vec_s[i], vec_s[i], vec_x_inverse[j], order, bn_ctx);
            } 
        }
    }
} 

// (Protocol 2 on pp.15)
void InnerProduct_Setup(uint64_t n, InnerProduct_PP &pp)
{
    InnerProduct_PP_Init(pp, n); 
    pp.VECTOR_LEN = n; 
    pp.LOG_VECTOR_LEN = log2(n); 
    random_vec_gg(pp.vec_g);
    random_vec_gg(pp.vec_h);
}

// Generate an argument PI for Relation 3 on pp.13: P = g^a h^b u^<a,b> 
// transcript_str is introduced to be used as a sub-protocol
void InnerProduct_Prove(InnerProduct_PP pp, 
                        InnerProduct_Instance instance, 
                        InnerProduct_Witness witness,
                        string& transcript_str,  
                        InnerProduct_Proof &proof)
{
    if (pp.vec_g.size()!=pp.vec_h.size()) 
    {
        throw "vector size does not match!";
    }

    uint64_t n = pp.VECTOR_LEN; // the current size of vec_G and vec_H

    // the last round
    if (n == 1)
    {
        BN_copy(proof.a, witness.vec_a[0]);
        BN_copy(proof.b, witness.vec_b[0]); 
 
        #ifdef DEBUG
        cout<< "Inner Product Proof Generation Finishes >>>" << endl;
        #endif 

        return; 
    }
    else{
        n = n/2; 
    
        // prepare the log(n)-th round message
        vector<BIGNUM*> vec_aL(n), vec_aR(n), vec_bL(n), vec_bR(n);
        vec_zz_init(vec_aL); 
        vec_zz_init(vec_aR); 
        vec_zz_init(vec_bL); 
        vec_zz_init(vec_bR);  
        
        vector<EC_POINT*> vec_gL(n), vec_gR(n), vec_hL(n), vec_hR(n);
        vec_gg_init(vec_gL); 
        vec_gg_init(vec_gR); 
        vec_gg_init(vec_hL); 
        vec_gg_init(vec_hR);  

        // prepare aL, aR, bL, bR
        vec_zz_assign(vec_aL, witness.vec_a, "left");
        vec_zz_assign(vec_aR, witness.vec_a, "right"); 
        vec_zz_assign(vec_bL, witness.vec_b, "left"); 
        vec_zz_assign(vec_bR, witness.vec_b, "right");

        vec_gg_assign(vec_gL, pp.vec_g, "left"); 
        vec_gg_assign(vec_gR, pp.vec_g, "right"); 
        vec_gg_assign(vec_hL, pp.vec_h, "left"); 
        vec_gg_assign(vec_hR, pp.vec_h, "right");

        // compute cL, cR
        BIGNUM *cL = BN_new(); 
        inner_product(cL, vec_aL, vec_bR); // Eq (21) 
        BIGNUM *cR = BN_new(); 
        inner_product(cR, vec_aR, vec_bL); // Eq (22)

        // compute L, R
        EC_POINT *temp_epsum  = EC_POINT_new(group);         
        EC_POINT *temp_ep1 = EC_POINT_new(group); 
        EC_POINT *temp_ep2 = EC_POINT_new(group); 

        vector<EC_POINT*> vec_A; 
        vector<BIGNUM*> vec_a; 

        EC_POINT *L = EC_POINT_new(group); 

        vec_A.insert(vec_A.end(), vec_gR.begin(), vec_gR.end()); 
        vec_A.insert(vec_A.end(), vec_hL.begin(), vec_hL.end());
        vec_A.emplace_back(instance.u); 

        vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
        vec_a.insert(vec_a.end(), vec_bR.begin(), vec_bR.end());
        vec_a.emplace_back(cL); 

        vec_gg_mul(L, vec_A, vec_a);  // Eq (23) 

        vec_A.clear(); vec_a.clear(); 

        EC_POINT *R = EC_POINT_new(group); 

        vec_A.insert(vec_A.end(), vec_gL.begin(), vec_gL.end()); 
        vec_A.insert(vec_A.end(), vec_hR.begin(), vec_hR.end());
        vec_A.emplace_back(instance.u); 

        vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 
        vec_a.insert(vec_a.end(), vec_bL.begin(), vec_bL.end());
        vec_a.emplace_back(cR); 

        vec_gg_mul(R, vec_A, vec_a);  // Eq (24)

        (proof.vec_L).push_back(L); 
        (proof.vec_R).push_back(R);  // store the n-th round L and R values

        // compute the challenge
        transcript_str += EC_POINT_ep2string(L) + EC_POINT_ep2string(R); 
        BIGNUM *x = BN_new(); 
        Hash_String_ZZ(x, transcript_str); // compute the n-th round challenge Eq (26,27)
        BIGNUM *x_inverse = BN_new(); 
        BN_mod_inverse(x_inverse, x, order, bn_ctx);  

        // generate new pp
        InnerProduct_PP pp_new;
        pp_new.VECTOR_LEN = pp.VECTOR_LEN/2; 
        pp_new.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN - 1; 
        InnerProduct_PP_Init(pp_new, pp_new.VECTOR_LEN); 

        // compute vec_g
        vec_gg_scalar(vec_gL, vec_gL, x_inverse); 
        vec_gg_scalar(vec_gR, vec_gR, x); 
        vec_gg_add(pp_new.vec_g, vec_gL, vec_gR); // Eq (29)
        // compute vec_h
        vec_gg_scalar(vec_hL, vec_hL, x); 
        vec_gg_scalar(vec_hR, vec_hR, x_inverse); 
        vec_gg_add(pp_new.vec_h, vec_hL, vec_hR); // Eq (30)

        // generate new instance
        InnerProduct_Instance instance_new; 
        InnerProduct_Instance_Init(instance_new); 

        EC_POINT_copy(instance_new.u, instance.u); // instance_new.u = instance.u 
 
        BIGNUM *x_square = BN_new(); 
        BIGNUM *x_inverse_square = BN_new(); 
        BN_mod_sqr(x_square, x, order, bn_ctx); // vec_x[0] = x^2 mod q
        BN_mod_sqr(x_inverse_square, x_inverse, order, bn_ctx); // vec_x[0] = x^2 mod q

        vec_A.clear(); vec_a.clear(); 
        vec_A.resize(3); vec_a.resize(3);
        vec_A[0] = L; vec_A[1] = instance.P; vec_A[2] = R; 
        vec_a[0] = x_square; vec_a[1] = bn_1; vec_a[2] = x_inverse_square; 

        vec_gg_mul(instance_new.P, vec_A, vec_a); // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        // generate new witness
        InnerProduct_Witness witness_new; 
        InnerProduct_Witness_Init(witness_new, pp_new.VECTOR_LEN); 
    
        vec_zz_scalar(vec_aL, vec_aL, x); 
        vec_zz_scalar(vec_aR, vec_aR, x_inverse); 
        vec_zz_add(witness_new.vec_a, vec_aL, vec_aR); // Eq (33)

        vec_zz_scalar(vec_bL, vec_bL, x_inverse); 
        vec_zz_scalar(vec_bR, vec_bR, x); 
        vec_zz_add(witness_new.vec_b, vec_bL, vec_bR); // Eq (34)

        // recursively invoke the InnerProduct proof
        InnerProduct_Prove(pp_new, instance_new, witness_new, transcript_str, proof); 

        //cout << "begin to free " << n << " memory" << endl; 
        InnerProduct_PP_Free(pp_new); 
        InnerProduct_Instance_Free(instance_new);
        InnerProduct_Witness_Free(witness_new);  

        // free temporary variables
        BN_free(cL); 
        BN_free(cR);
        BN_free(x), BN_free(x_inverse); 
        BN_free(x_square), BN_free(x_inverse_square); 

        vec_zz_free(vec_aL); 
        vec_zz_free(vec_aR); 
        vec_zz_free(vec_bL); 
        vec_zz_free(vec_bR);  
        
        vec_gg_free(vec_gL); 
        vec_gg_free(vec_gR); 
        vec_gg_free(vec_hL); 
        vec_gg_free(vec_hR);  
    }
}

/*
    Check if PI is a valid proof for inner product statement (G1^w = H1 and G2^w = H2)
*/
bool InnerProduct_Verify(InnerProduct_PP &pp, 
                         InnerProduct_Instance &instance, 
                         string &transcript_str, 
                         InnerProduct_Proof &proof)
{
    bool Validity;

    // recover the challenge
    vector<BIGNUM *> vec_x(pp.LOG_VECTOR_LEN); // the vector of challenge 
    vector<BIGNUM *> vec_x_inverse(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    vector<BIGNUM *> vec_x_square(pp.LOG_VECTOR_LEN); // the vector of challenge 
    vector<BIGNUM *> vec_x_inverse_square(pp.LOG_VECTOR_LEN); // the vector of challenge inverse

    vec_zz_init(vec_x); 
    vec_zz_init(vec_x_inverse); 
    vec_zz_init(vec_x_square); 
    vec_zz_init(vec_x_inverse_square); 

    //cout << "recover the challenges" << endl; 
    for (size_t i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        transcript_str += EC_POINT_ep2string(proof.vec_L[i]) + EC_POINT_ep2string(proof.vec_R[i]); 
        Hash_String_ZZ(vec_x[i], transcript_str); // reconstruct the challenge

        BN_mod_sqr(vec_x_square[i], vec_x[i], order, bn_ctx); 
        BN_mod_inverse(vec_x_inverse[i], vec_x[i], order, bn_ctx);  
        BN_mod_sqr(vec_x_inverse_square[i], vec_x_inverse[i], order, bn_ctx); 
    }

    // define the left and right side of the equation on top of pp.17 (with slight modification)
    vector<EC_POINT*> vec_A; 
    vector<BIGNUM*> vec_a; 

    // compute left
    vector<BIGNUM *> vec_s(pp.VECTOR_LEN); 
    vector<BIGNUM *> vec_s_inverse(pp.VECTOR_LEN); 
    vec_zz_init(vec_s); 
    vec_zz_init(vec_s_inverse); 

    compute_vec_ss(vec_s, vec_x, vec_x_inverse); // page 15: the s vector
    vec_zz_inverse(vec_s_inverse, vec_s);  // the s^{-1} vector
    vec_zz_scalar(vec_s, vec_s, proof.a); 
    vec_zz_scalar(vec_s_inverse, vec_s_inverse, proof.b); 

    vec_A.assign(pp.vec_g.begin(), pp.vec_g.end()); 
    vec_a.assign(vec_s.begin(), vec_s.end()); // pp.vec_g, vec_s

    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end());
    vec_a.insert(vec_a.end(), vec_s_inverse.begin(), vec_s_inverse.end()); // pp.vec_h, vec_s_inverse

    vec_A.emplace_back(instance.u); 
    BIGNUM *temp_bn = BN_new(); 
    BN_mod_mul(temp_bn, proof.a, proof.b, order, bn_ctx);
    vec_a.emplace_back(temp_bn); // LEFT = u^{ab}

    EC_POINT* LEFT = EC_POINT_new(group);

    vec_gg_mul(LEFT, vec_A, vec_a); 

    // compute right
    EC_POINT *RIGHT = EC_POINT_new(group); 

    vec_A.clear(); vec_a.clear(); 
    vec_A.emplace_back(instance.P); 
    vec_A.insert(vec_A.end(), proof.vec_L.begin(), proof.vec_L.end()); 
    vec_A.insert(vec_A.end(), proof.vec_R.begin(), proof.vec_R.end()); 

    vec_a.emplace_back(bn_1); 
    vec_a.insert(vec_a.end(), vec_x_square.begin(), vec_x_square.end()); 
    vec_a.insert(vec_a.end(), vec_x_inverse_square.begin(), vec_x_inverse_square.end()); 

    vec_gg_mul(RIGHT, vec_A, vec_a);  

    // the equation on top of page 17
    if (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0) 
    {
        Validity = true;
        #ifdef DEBUG 
        cout<< "Inner Product Proof Accept >>>" << endl; 
        #endif
    }
    else {
        Validity = false;
        #ifdef DEBUG
        cout<< "Inner Product Proof Reject >>>" << endl; 
        #endif
    }

    // free temporary variables
    EC_POINT_free(LEFT); 
    EC_POINT_free(RIGHT); 

    vec_zz_free(vec_x); 
    vec_zz_free(vec_x_inverse); 
    vec_zz_free(vec_x_square); 
    vec_zz_free(vec_x_inverse_square); 

    vec_zz_free(vec_s); 
    vec_zz_free(vec_s_inverse); 
    BN_free(temp_bn); 

    return Validity;
}






