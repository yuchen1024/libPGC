/***********************************************************************************
this hpp implements the inner product proof system  
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef __IP__
#define __IP__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define the structure of InnerProduct Proof
struct InnerProduct_PP
{
    size_t VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
    size_t LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 
    
    // size of the vector = VECTOR_LEN
    vector<EC_POINT *> vec_g; 
    vector<EC_POINT *> vec_h; 
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
    vector<BIGNUM *> vec_a; 
    vector<BIGNUM *> vec_b; 
};

struct InnerProduct_Proof
{
    // size of the vector = LOG_VECTOR_LEN
    vector<EC_POINT *> vec_L; 
    vector<EC_POINT *> vec_R; 
    BIGNUM *a; 
    BIGNUM *b;     
};

void InnerProduct_Proof_serialize(InnerProduct_Proof &proof, ofstream &fout)
{
    ECP_vec_serialize(proof.vec_L, fout);
    ECP_vec_serialize(proof.vec_R, fout);

    BN_serialize(proof.a, fout); 
    BN_serialize(proof.b, fout); 
}

void InnerProduct_Proof_deserialize(InnerProduct_Proof &proof, ifstream &fin)
{
    ECP_vec_deserialize(proof.vec_L, fin);
    ECP_vec_deserialize(proof.vec_R, fin);

    BN_deserialize(proof.a, fin); 
    BN_deserialize(proof.b, fin); 
}

void InnerProduct_PP_print(InnerProduct_PP &pp)
{
    cout << "vector length = " << pp.VECTOR_LEN << endl;   
    cout << "log vector length = " << pp.LOG_VECTOR_LEN << endl;   
    
    // size of the vector = VECTOR_LEN
    ECP_vec_print(pp.vec_g, "g"); 
    ECP_vec_print(pp.vec_h, "h"); 

};

void InnerProduct_Witness_print(InnerProduct_Witness &witness)
{
    BN_vec_print(witness.vec_a, "a"); 
    BN_vec_print(witness.vec_b, "b"); 
};

void InnerProduct_Instance_print(InnerProduct_Instance &instance)
{
    ECP_print(instance.P, "ip_instance.P"); 
    ECP_print(instance.u, "ip_instance.u"); 
};

void InnerProduct_Proof_print(InnerProduct_Proof &proof)
{
    ECP_vec_print(proof.vec_L, "L");
    ECP_vec_print(proof.vec_R, "R");
    BN_print(proof.a, "proof.a"); 
    BN_print(proof.b, "proof.b"); 
};

void InnerProduct_PP_new(InnerProduct_PP &pp, size_t VECTOR_LEN)
{
    pp.vec_g.resize(VECTOR_LEN); ECP_vec_new(pp.vec_g);
    pp.vec_h.resize(VECTOR_LEN); ECP_vec_new(pp.vec_h);
}

void InnerProduct_PP_free(InnerProduct_PP &pp)
{
    ECP_vec_free(pp.vec_g); 
    ECP_vec_free(pp.vec_h);
}

void InnerProduct_Instance_new(InnerProduct_Instance &instance)
{
    instance.u = EC_POINT_new(group); 
    instance.P = EC_POINT_new(group);
}

void InnerProduct_Instance_free(InnerProduct_Instance &instance)
{
    EC_POINT_free(instance.u); 
    EC_POINT_free(instance.P);
}

void InnerProduct_Witness_new(InnerProduct_Witness &witness, uint64_t VECTOR_LEN)
{
    witness.vec_a.resize(VECTOR_LEN); 
    witness.vec_b.resize(VECTOR_LEN); 
    BN_vec_new(witness.vec_a); 
    BN_vec_new(witness.vec_b); 
}

void InnerProduct_Witness_free(InnerProduct_Witness &witness)
{
    BN_vec_free(witness.vec_a); 
    BN_vec_free(witness.vec_b); 
}

void InnerProduct_Proof_new(InnerProduct_Proof &proof)
{
    proof.a = BN_new(); 
    proof.b = BN_new(); 
}

void InnerProduct_Proof_free(InnerProduct_Proof &proof)
{
    BN_free(proof.a); 
    BN_free(proof.b); 

    ECP_vec_free(proof.vec_L); 
    ECP_vec_free(proof.vec_R);

    proof.vec_L.resize(0); 
    proof.vec_R.resize(0); 
}


/* compute the jth bit of a big integer i (count from little endian to big endian) */
inline uint64_t BN_parse_binary(BIGNUM *BN_i, uint64_t j)
{
    BIGNUM *BN_bit = BN_new(); 
    BN_copy(BN_bit, BN_i); 

    BN_rshift(BN_bit, BN_bit, j);
    BN_mod(BN_bit, BN_bit, BN_2, bn_ctx);

    uint64_t bit; 
    if (BN_is_one(BN_bit)) bit = 1; 
    else bit = 0;
    BN_free(BN_bit); 
    return bit;  
}


/* compute the jth bit of a small integer num \in [0, 2^{m-1}] (count from big endian to little endian) */ 
inline uint64_t int_parse_binary(size_t num, size_t j, size_t m)
{ 
    size_t cursor = 1 << (m-1); // set cursor = 2^{m-1} = 1||0...0---(m-1)
    
    for (auto i = 0; i < j; i++)
    { 
        cursor = cursor >> 1;
    }
    if ((num&cursor) != 0) return 1;
    else return 0;   
}

/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */ 
inline void BN_vec_gen_power(vector<BIGNUM *> &result, BIGNUM *&a)
{
    BN_one(result[0]); // set result[0] = 1
    for (auto i = 1; i < result.size(); i++)
    {
        BN_mod_mul(result[i], a, result[i-1], order, bn_ctx); // result[i] = result[i-1]*a % order
    }
}

/* assign left or right part of a Zn vector */ 
inline void BN_vec_assign(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, string selector)
{
    size_t start_index; 
    if (selector == "left") start_index = 0; 
    if (selector == "right") start_index = vec_a.size()/2; 
    
    for(auto i = 0; i < result.size(); i++){
        BN_copy(result[i], vec_a[start_index + i]); 
    }
}

// assign left or right part of an ECn vector
inline void ECP_vec_assign(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_g, string selector)
{
    size_t start_index; 
    if (selector == "left") start_index = 0; 
    if (selector == "right") start_index = vec_g.size()/2; 
    
    for(auto i = 0; i < result.size(); i++){
        EC_POINT_copy(result[i], vec_g[start_index + i]); 
    }
}

/* sum_i^n a[i]*b[i] */
inline void BN_vec_inner_product(BIGNUM *&result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    BN_zero(result); // set result = 0

    BIGNUM *product = BN_new(); 

    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }   
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mul(product, vec_a[i], vec_b[i], bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
        BN_add(result, result, product);     // result = (result+product) mod order
    }
    BN_mod(result, result, order, bn_ctx);
}

/* g[i] = g[i]+h[i] */ 
inline void ECP_vec_add(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, vector<EC_POINT *> &vec_B)
{
    if (vec_A.size()!= vec_B.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    for (auto i = 0; i < vec_A.size(); i++) 
    {
        EC_POINT_add(group, result[i], vec_A[i], vec_B[i], bn_ctx); 
    }
}

/* a[i] = (a[i]+b[i]) mod order */
inline void BN_vec_add(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_add(result[i], vec_a[i], vec_b[i], order, bn_ctx);   
    }
}

/* a[i] = (a[i]-b[i]) mod order */ 
inline void BN_vec_sub(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_sub(result[i], vec_a[i], vec_b[i], order, bn_ctx);
    } 
}

/* c[i] = a[i]*b[i] mod order */ 
inline void BN_vec_product(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_mul(result[i], vec_a[i], vec_b[i], order, bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
    }
}

/* compute the inverse of a[i] */ 
inline void BN_vec_inverse(vector<BIGNUM *> &vec_a_inverse, vector<BIGNUM *> &vec_a)
{
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_inverse(vec_a_inverse[i], vec_a[i], order, bn_ctx); 
    }
}

/* vec_g = c * vec_g */ 
inline void ECP_vec_scalar(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, BIGNUM* &c)
{
    for (auto i = 0; i < vec_A.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_A[i], c, bn_ctx); // result[i] = vec_g[i]^c
    } 
}

/* result[i] = c * a[i] */  
inline void BN_vec_scalar(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, BIGNUM* &c)
{
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_mul(result[i], vec_a[i], c, order, bn_ctx);
    } 
}

/* result[i] = -result[i] */  
inline void BN_vec_negative(vector<BIGNUM *> &result)
{
    for (auto i = 0; i < result.size(); i++) 
    {
        BN_mod_negative(result[i]);
    } 
}

/* result[i] = A[i]*a[i] */ 
inline void ECP_vec_product(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
    if (vec_A.size() != vec_a.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    } 
    for (auto i = 0; i < vec_A.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_A[i], vec_a[i], bn_ctx); 
    } 
}

/* result = sum_{i=1^n} a[i]*A[i] */ 
inline void ECP_vec_mul(EC_POINT* &result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
    if (vec_A.size() != vec_a.size()) {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    EC_POINTs_mul(group, result, NULL, vec_A.size(), 
                  (const EC_POINT**)vec_A.data(), (const BIGNUM**)vec_a.data(), bn_ctx); 
}

/* this module is used to enable fast verification (cf pp.15) */
void compute_vec_ss(vector<BIGNUM *> &vec_s, vector<BIGNUM *> &vec_x, vector<BIGNUM *> &vec_x_inverse)
{
    size_t m = vec_x.size(); 
    size_t n = vec_s.size(); //int n = pow(2, m); 
    
    // compute s[0], ..., s[i-1]
    // vector<BIGNUM *> vec_s(n); 
    uint64_t flag; 
    for (auto i = 0; i < n; i++)
    {
        BN_one(vec_s[i]); // set s[i] = 1
        for (auto j = 0; j < m; j++)
        {
            flag = int_parse_binary(i, j, m); 
            if (flag == 1){
                BN_mod_mul(vec_s[i], vec_s[i], vec_x[j], order, bn_ctx);
            } 
            else{
                BN_mod_mul(vec_s[i], vec_s[i], vec_x_inverse[j], order, bn_ctx);
            } 
        }
    }
} 


/* (Protocol 2 on pp.15) */
void InnerProduct_Setup(InnerProduct_PP &pp, size_t VECTOR_LEN, bool INITIAL_FLAG)
{
    pp.VECTOR_LEN = VECTOR_LEN;
    pp.LOG_VECTOR_LEN = log2(VECTOR_LEN);  

    if(INITIAL_FLAG == true){
        ECP_vec_random(pp.vec_g);
        ECP_vec_random(pp.vec_h);
    }
}

/* 
    Generate an argument PI for Relation 3 on pp.13: P = g^a h^b u^<a,b> 
    transcript_str is introduced to be used as a sub-protocol 
*/
void InnerProduct_Prove(InnerProduct_PP pp, 
                        InnerProduct_Instance instance, 
                        InnerProduct_Witness witness,
                        string &transcript_str,  
                        InnerProduct_Proof &proof)
{
    if (pp.vec_g.size()!=pp.vec_h.size()) 
    {
        cout << "vector size does not match!";
        exit(EXIT_FAILURE); 
    }

    size_t n = pp.VECTOR_LEN; // the current size of vec_G and vec_H

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
        BN_vec_new(vec_aL); 
        BN_vec_new(vec_aR); 
        BN_vec_new(vec_bL); 
        BN_vec_new(vec_bR);  
        
        vector<EC_POINT*> vec_gL(n), vec_gR(n), vec_hL(n), vec_hR(n);
        ECP_vec_new(vec_gL); 
        ECP_vec_new(vec_gR); 
        ECP_vec_new(vec_hL); 
        ECP_vec_new(vec_hR);  

        // prepare aL, aR, bL, bR
        BN_vec_assign(vec_aL, witness.vec_a, "left");
        BN_vec_assign(vec_aR, witness.vec_a, "right"); 
        BN_vec_assign(vec_bL, witness.vec_b, "left"); 
        BN_vec_assign(vec_bR, witness.vec_b, "right");

        ECP_vec_assign(vec_gL, pp.vec_g, "left"); 
        ECP_vec_assign(vec_gR, pp.vec_g, "right"); 
        ECP_vec_assign(vec_hL, pp.vec_h, "left"); 
        ECP_vec_assign(vec_hR, pp.vec_h, "right");

        // compute cL, cR
        BIGNUM *cL = BN_new(); 
        BN_vec_inner_product(cL, vec_aL, vec_bR); // Eq (21) 
        BIGNUM *cR = BN_new(); 
        BN_vec_inner_product(cR, vec_aR, vec_bL); // Eq (22)

        // compute L, R
        EC_POINT *temp_ecpsum  = EC_POINT_new(group);         
        EC_POINT *temp_ecp1 = EC_POINT_new(group); 
        EC_POINT *temp_ecp2 = EC_POINT_new(group); 

        vector<EC_POINT *> vec_A; 
        vector<BIGNUM *> vec_a; 

        EC_POINT *L = EC_POINT_new(group); 

        vec_A.insert(vec_A.end(), vec_gR.begin(), vec_gR.end()); 
        vec_A.insert(vec_A.end(), vec_hL.begin(), vec_hL.end());
        vec_A.emplace_back(instance.u); 

        vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
        vec_a.insert(vec_a.end(), vec_bR.begin(), vec_bR.end());
        vec_a.emplace_back(cL); 

        ECP_vec_mul(L, vec_A, vec_a);  // Eq (23) 

        vec_A.clear(); vec_a.clear(); 

        EC_POINT *R = EC_POINT_new(group); 

        vec_A.insert(vec_A.end(), vec_gL.begin(), vec_gL.end()); 
        vec_A.insert(vec_A.end(), vec_hR.begin(), vec_hR.end());
        vec_A.emplace_back(instance.u); 

        vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 
        vec_a.insert(vec_a.end(), vec_bL.begin(), vec_bL.end());
        vec_a.emplace_back(cR); 

        ECP_vec_mul(R, vec_A, vec_a);  // Eq (24)

        proof.vec_L.push_back(L); 
        proof.vec_R.push_back(R);  // store the n-th round L and R values

        // compute the challenge
        transcript_str += ECP_ep2string(L) + ECP_ep2string(R); 
        BIGNUM *x = BN_new(); 
        Hash_String_to_BN(transcript_str, x); // compute the n-th round challenge Eq (26,27)
        BIGNUM *x_inverse = BN_new(); 
        BN_mod_inverse(x_inverse, x, order, bn_ctx);  

        // generate new pp
        InnerProduct_PP pp_sub;
        // pp_sub.VECTOR_LEN = pp.VECTOR_LEN/2; 
        // pp_sub.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN - 1; 
        InnerProduct_PP_new(pp_sub, pp.VECTOR_LEN/2); 
        InnerProduct_Setup(pp_sub, pp.VECTOR_LEN/2, false);

        // compute vec_g
        ECP_vec_scalar(vec_gL, vec_gL, x_inverse); 
        ECP_vec_scalar(vec_gR, vec_gR, x); 
        ECP_vec_add(pp_sub.vec_g, vec_gL, vec_gR); // Eq (29)
        // compute vec_h
        ECP_vec_scalar(vec_hL, vec_hL, x); 
        ECP_vec_scalar(vec_hR, vec_hR, x_inverse); 
        ECP_vec_add(pp_sub.vec_h, vec_hL, vec_hR); // Eq (30)

        // generate new instance
        InnerProduct_Instance instance_sub; 
        InnerProduct_Instance_new(instance_sub); 

        EC_POINT_copy(instance_sub.u, instance.u); // instance_new.u = instance.u 
 
        BIGNUM *x_square = BN_new(); 
        BIGNUM *x_inverse_square = BN_new(); 
        BN_mod_sqr(x_square, x, order, bn_ctx); // vec_x[0] = x^2 mod q
        BN_mod_sqr(x_inverse_square, x_inverse, order, bn_ctx); // vec_x[0] = x^2 mod q

        vec_A.clear(); vec_a.clear(); 
        vec_A.resize(3); vec_a.resize(3);
        vec_A[0] = L; vec_A[1] = instance.P; vec_A[2] = R; 
        vec_a[0] = x_square; vec_a[1] = BN_1; vec_a[2] = x_inverse_square; 

        ECP_vec_mul(instance_sub.P, vec_A, vec_a); // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        // generate new witness
        InnerProduct_Witness witness_sub; 
        InnerProduct_Witness_new(witness_sub, pp_sub.VECTOR_LEN); 
    
        BN_vec_scalar(vec_aL, vec_aL, x); 
        BN_vec_scalar(vec_aR, vec_aR, x_inverse); 
        BN_vec_add(witness_sub.vec_a, vec_aL, vec_aR); // Eq (33)

        BN_vec_scalar(vec_bL, vec_bL, x_inverse); 
        BN_vec_scalar(vec_bR, vec_bR, x); 
        BN_vec_add(witness_sub.vec_b, vec_bL, vec_bR); // Eq (34)

        // recursively invoke the InnerProduct proof
        InnerProduct_Prove(pp_sub, instance_sub, witness_sub, transcript_str, proof); 
        //cout << "begin to free " << n << " memory" << endl; 
        InnerProduct_PP_free(pp_sub); 
        InnerProduct_Instance_free(instance_sub);
        InnerProduct_Witness_free(witness_sub);  

        // free temporary variables
        BN_free(cL); 
        BN_free(cR);
        BN_free(x), BN_free(x_inverse); 
        BN_free(x_square), BN_free(x_inverse_square); 

        BN_vec_free(vec_aL); 
        BN_vec_free(vec_aR); 
        BN_vec_free(vec_bL); 
        BN_vec_free(vec_bR);  
        
        ECP_vec_free(vec_gL); 
        ECP_vec_free(vec_gR); 
        ECP_vec_free(vec_hL); 
        ECP_vec_free(vec_hR);  
    }
}

/* Check if PI is a valid proof for inner product statement (G1^w = H1 and G2^w = H2) */
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

    BN_vec_new(vec_x); 
    BN_vec_new(vec_x_inverse); 
    BN_vec_new(vec_x_square); 
    BN_vec_new(vec_x_inverse_square); 

    for (auto i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        transcript_str += ECP_ep2string(proof.vec_L[i]) + ECP_ep2string(proof.vec_R[i]); 
        Hash_String_to_BN(transcript_str, vec_x[i]); // reconstruct the challenge

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
    BN_vec_new(vec_s); 
    BN_vec_new(vec_s_inverse); 

    compute_vec_ss(vec_s, vec_x, vec_x_inverse); // page 15: the s vector
    BN_vec_inverse(vec_s_inverse, vec_s);  // the s^{-1} vector
    BN_vec_scalar(vec_s, vec_s, proof.a); 
    BN_vec_scalar(vec_s_inverse, vec_s_inverse, proof.b); 

    vec_A.assign(pp.vec_g.begin(), pp.vec_g.end()); 
    vec_a.assign(vec_s.begin(), vec_s.end()); // pp.vec_g, vec_s

    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end());
    vec_a.insert(vec_a.end(), vec_s_inverse.begin(), vec_s_inverse.end()); // pp.vec_h, vec_s_inverse

    vec_A.emplace_back(instance.u); 
    BIGNUM *temp_bn = BN_new(); 
    BN_mod_mul(temp_bn, proof.a, proof.b, order, bn_ctx);
    vec_a.emplace_back(temp_bn); // LEFT = u^{ab}

    EC_POINT* LEFT = EC_POINT_new(group);

    ECP_vec_mul(LEFT, vec_A, vec_a); 

    // compute right
    EC_POINT *RIGHT = EC_POINT_new(group); 

    vec_A.clear(); vec_a.clear(); 
    vec_A.emplace_back(instance.P); 
    vec_A.insert(vec_A.end(), proof.vec_L.begin(), proof.vec_L.end()); 
    vec_A.insert(vec_A.end(), proof.vec_R.begin(), proof.vec_R.end()); 

    vec_a.emplace_back(BN_1); 
    vec_a.insert(vec_a.end(), vec_x_square.begin(), vec_x_square.end()); 
    vec_a.insert(vec_a.end(), vec_x_inverse_square.begin(), vec_x_inverse_square.end()); 

    ECP_vec_mul(RIGHT, vec_A, vec_a);  

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

    BN_vec_free(vec_x); 
    BN_vec_free(vec_x_inverse); 
    BN_vec_free(vec_x_square); 
    BN_vec_free(vec_x_inverse_square); 

    BN_vec_free(vec_s); 
    BN_vec_free(vec_s_inverse); 
    BN_free(temp_bn); 

    return Validity;
}

#endif






