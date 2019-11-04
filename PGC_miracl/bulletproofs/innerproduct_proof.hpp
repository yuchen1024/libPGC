/***********************************************************************************
this hpp implements the inner product proof system  
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/

#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include <cmath>
#include "ecn.h"
#include "zzn.h"


// define the structure of InnerProduct Proof
struct InnerProduct_PP
{
    // size of the vector = VECTOR_LEN
    vector<ECn> vec_g; 
    vector<ECn> vec_h; 

    int VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
    int LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 
};

//P = vec_g^vec_a vec_h^vec_b u^<vec_a, vec_b>
struct InnerProduct_Instance
{
    ECn u; 
    ECn P; 
};

struct InnerProduct_Witness
{
    // size of the vector = VECTOR_LEN
    vector<Big> vec_a; 
    vector<Big> vec_b; 
};

struct InnerProduct_Proof
{
    // size of the vector = LOG_VECTOR_LEN
    vector<ECn> vec_L; 
    vector<ECn> vec_R; 
    Big a; 
    Big b;     
};


//vector operations

// print an ECn vector
void print_vec_gg(vector<ECn> vec_g)
{
    int i, n = vec_g.size(); 
    for (i = 0; i < n; i++)
    {
        cout << "G[" << i << "]=" << vec_g[i] << endl; 
    }
}

// print a ZZ vector
void print_vec_zz(vector<Big> vec_a)
{
    int i, n = vec_a.size(); 
    for (i = 0; i < n; i++)
    {
        cout << "A[" << i << "]=" << vec_a[i] << endl; 
    }
}

// generate a random ZZ vector
vector<Big> gen_random_vec_zz(int n)
{
    int i; 
    vector<Big> vec_a(n); 
    for(i = 0; i < n; i++)
    {
        vec_a[i] = random_zz(); 
    }
    return vec_a; 
}

// compute the jth bit of a big integer i (count from little endian to big endian)
inline Big big_parse_binary(Big i, int j)
{
    int k = 0;
    for (k = 0; k<j; k++)
    {
        i = i/2;
    } 
    return i%2; 
}

// compute the jth bit of a small integer num \in [0, 2^{m-1}] (count from big endian to little endian)
inline int small_parse_binary(int num, int j, int m)
{ 
    int cursor = 1 << (m-1); // set cursor = 2^{m-1} = 1||0...0---(m-1)
    
    int i;
    for (i = 0; i < j; i++)
    { 
        cursor = cursor >> 1;
    }
    if ((num&cursor) != 0) return 1;
    else return 0;   
}

// generate a^n = (a^0, a^1, a^2, ..., a^{n-1})
inline vector<Big> gen_vec_zz_power(Big a, int n)
{
    int i; 
    vector<Big> result(n); 
    for (i = 0; i< n; i++)
    {
        result[i] = pow(a, i, q);
    }
    return result;
}

// assign left or right part of a Zn vector
inline vector<Big> vec_zz_assign(vector<Big> vec_a, string selector)
{
    int i; 
    int n = vec_a.size()/2; 
    vector<Big> vec_b(n); 
    if (selector == "left") 
    {
        vec_b.assign(vec_a.begin(), vec_a.begin()+n); 
    }

    if (selector == "right") 
    {
        vec_b.assign(vec_a.begin()+n, vec_a.end()); 
    }
    return vec_b; 
}

// assign left or right part of an ECn vector
inline vector<ECn> vec_gg_assign(vector<ECn> vec_g, string selector)
{
    int i; 
    int n = vec_g.size()/2; 
    vector<ECn> vec_h(n); 
    if (selector == "left") 
    {
        vec_h.assign(vec_g.begin(), vec_g.begin()+n);
    }

    if (selector == "right") 
    { 
        vec_h.assign(vec_g.begin()+n, vec_g.end());
    }
    return vec_h; 
}

// sum_i^n a[i]*b[i]
inline Big inner_product(vector<Big> vec_a, vector<Big> vec_b)
{
    Big result = 0; 
    int i; 
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    int n = vec_a.size(); 
    for (i = 0; i<n; i++) 
    {
        result += vec_a[i] * vec_b[i];  
        result %= q; 
    }
    return result; 
}

// g[i] = g[i]+h[i]
inline vector<ECn> vec_gg_add(vector<ECn> vec_g, vector<ECn> vec_h)
{
    int i, n; 
    if (vec_g.size()!= vec_h.size()) 
    {
        throw "vector size does not match!";
    }
    n = vec_g.size();  
    for (i = 0; i < n; i++) 
    {
        vec_g[i] += vec_h[i]; 
    }
    return vec_g; 
}

// a[i] = a[i]+b[i]
inline vector<Big> vec_zz_add(vector<Big> vec_a, vector<Big> vec_b)
{
    int i, n; 
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    n = vec_a.size();  
    for (i = 0; i < n; i++) 
    {
        vec_a[i] = (vec_a[i] + vec_b[i])%q; 
        //vec_a[i] = (vec_a[i] + q)%q; 
    }

    return vec_a; 
}

// a[i] = a[i]-b[i]
inline vector<Big> vec_zz_sub(vector<Big> vec_a, vector<Big> vec_b)
{
    int i, n; 
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    n = vec_a.size(); 
    for (i = 0; i<n; i++) 
    {
        vec_a[i] = (vec_a[i] - vec_b[i])%q; 
        //vec_a[i] %= q; 
    }
    return vec_a; 
}

// c[i] = a[i]*b[i]
inline vector<Big> vec_zz_product(vector<Big> vec_a, vector<Big> vec_b)
{
    int i; 
    if (vec_a.size() != vec_b.size()) 
    {
        throw "vector size does not match!";
    }
    int n = vec_a.size(); 
    for (i = 0; i < n; i++) 
    {
        vec_a[i] = (vec_a[i]*vec_b[i])%q; 
    }
    return vec_a; 
}

// compute the inverse of a[i]
inline vector<Big> vec_zz_invert(vector<Big> vec_a)
{
    int i; 
    int n = vec_a.size(); 
    vector<Big> vec_a_inverse(n); 
    for (i = 0; i<n; i++) 
    {
        vec_a_inverse[i] = inverse(vec_a[i], q); 
    }
    return vec_a_inverse; 
}

// vec_g = c * vec_g
inline vector<ECn> vec_gg_scalar(vector<ECn> vec_g, Big c)
{
    int n = vec_g.size();
    int i; 
    for (i = 0; i<n; i++) 
    {
        vec_g[i] *= c;  
    } 
    return vec_g; 
}

// vec_a = c * vec_a
inline vector<Big> vec_zz_scalar(vector<Big> vec_a, Big c)
{
    int n = vec_a.size();
    int i; 
    for (i = 0; i<n; i++) 
    {
        vec_a[i] *= c; 
        vec_a[i] %= q; 
    } 
    return vec_a; 
}

// g[i] = a[i]*g[i]
inline vector<ECn> vec_gg_product(vector<ECn> vec_g, vector<Big> vec_a)
{
    int i; 
    if (vec_g.size() != vec_a.size()) 
    {
        throw "vector size does not match!";
    }
    int n = vec_g.size();  
    for (i = 0; i < n; i++) 
    {
        vec_g[i] *= vec_a[i]; 
    }
    return vec_g; 
}

// sum_i=1^n a[i]*g[i]
inline ECn vec_gg_mul(vector<ECn> vec_g, vector<Big> vec_a)
{
    int i; 
    if (vec_g.size() != vec_a.size()) {
        throw "vector size does not match!";
    }
    int n = vec_g.size();  
    ECn result = ZeroPoint;  

    for (i = 0; i < n; i++) {
        vec_g[i] *= vec_a[i]; // A[i] = a[i]*A[i]
        result += vec_g[i];  
    } 
    return result; 

    // int size_t = vec_g.size(); 
    //cout << vec_g.size() << endl; 

    // ECn result = mul(size_t, vec_a.data(), vec_g.data()); 
    // return result; 
}

/* 
    this module is used to enable fast verification (cf pp.15)
*/
vector<Big> compute_vec_ss(const vector<Big> vec_x, const vector<Big> vec_x_inverse)
{
    int m = vec_x.size(); 
    int n = pow(2, m); 
    // compute s[0], ..., s[i-1]
    vector<Big> vec_s(n, 1); 
    int i, j, flag; 
    for (i = 0; i < n; i++)
    {
        for (j = 0; j < m; j++)
        {
            flag = small_parse_binary(i, j, m); 
            if (flag == 1) vec_s[i] = (vec_s[i] * vec_x[j])%q;
            else vec_s[i] = (vec_s[i] * vec_x_inverse[j])%q; 
        }
    }
    return vec_s; 
} 


// generate a random instance-witness pair
void gen_random_instance_witness(InnerProduct_PP pp, 
InnerProduct_Instance &instance, InnerProduct_Witness &witness)
{
    int i; 
    witness.vec_a.resize(pp.VECTOR_LEN); 
    witness.vec_b.resize(pp.VECTOR_LEN);
    for(i = 0; i < pp.VECTOR_LEN; i++)
    {
        //cout << "i=" << i << " " << witness.vec_a.size() << endl; 
        witness.vec_a[i] = random_zz(); 
        witness.vec_b[i] = random_zz();
    }
    instance.u = random_gg();
    Big c = inner_product(witness.vec_a, witness.vec_b); 

    instance.P = instance.u; 
    instance.P *= c; 
    instance.P += vec_gg_mul(pp.vec_g, witness.vec_a); 
    instance.P += vec_gg_mul(pp.vec_h, witness.vec_b);  

    cout << "generate random (instance, witness) pair" << endl;  
}


// (Protocol 2 on pp.15)

InnerProduct_PP InnerProduct_Setup(int n)
{
    InnerProduct_PP pp;
    pp.VECTOR_LEN = n; 
    pp.LOG_VECTOR_LEN = log2(n); 
    pp.vec_g.resize(n); 
    pp.vec_h.resize(n);
    int i; 
    for (i = 0; i < n; i++)
    {
        pp.vec_g[i] = random_gg(); 
        pp.vec_h[i] = random_gg();
    }
    return pp; 
}

// Generate an argument PI for Relation 3 on pp.13: P = g^a h^b u^<a,b> 
bool InnerProduct_Prove(InnerProduct_PP pp, InnerProduct_Instance instance, 
InnerProduct_Witness witness, InnerProduct_Proof &proof)
{
    if (pp.vec_g.size()!=pp.vec_h.size()) 
    {
        throw "vector size does not match!";
    }

    int n = pp.VECTOR_LEN; // the current size of vec_G and vec_H

    // the last round
    if (n == 1)
    {
        proof.a  = witness.vec_a[0];
        proof.b  = witness.vec_b[0]; 

        #ifdef DEBUG
        cout<< "Inner Product Proof Generation Succeeds..." << endl;
        #endif 

        return true; 
    }
    else{
        n = n/2; 

        InnerProduct_PP pp_new; 
        InnerProduct_Instance instance_new; 
        InnerProduct_Witness witness_new; 

        vector<Big> vec_aL, vec_aR, vec_bL, vec_bR;
        vector<ECn> vec_gL, vec_gR, vec_hL, vec_hR;  

        // compute aL, aR, bL, bR
        vec_aL = vec_zz_assign(witness.vec_a, "left"); 
        vec_aR = vec_zz_assign(witness.vec_a, "right"); 
        vec_bL = vec_zz_assign(witness.vec_b, "left"); 
        vec_bR = vec_zz_assign(witness.vec_b, "right");

        vec_gL = vec_gg_assign(pp.vec_g, "left"); 
        vec_gR = vec_gg_assign(pp.vec_g, "right"); 
        vec_hL = vec_gg_assign(pp.vec_h, "left"); 
        vec_hR = vec_gg_assign(pp.vec_h, "right");

        Big cL = inner_product(vec_aL, vec_bR); // Eq (21) 
        Big cR = inner_product(vec_aR, vec_bL); // Eq (22)
        
        ECn L = instance.u; 
        L *= cL; // u^{cL}
        L += vec_gg_mul(vec_gR, vec_aL); 
        L += vec_gg_mul(vec_hL, vec_bR); // Eq (23) 

        ECn R = instance.u; 
        R *= cR; // u^{cR}
        R += vec_gg_mul(vec_gL, vec_aR); 
        R += vec_gg_mul(vec_hR, vec_bL); // Eq (24)

        (proof.vec_L).push_back(L); 
        (proof.vec_R).push_back(R);  // store the n-th round L and R values

        vector<ECn> vec_HASH_x = {L, R}; 
        Big x = Hash_GGn_ZZ(vec_HASH_x); // compute the n-th round challenge Eq (26,27)
        Big x_inverse = inverse(x, q); 

        pp_new.VECTOR_LEN = pp.VECTOR_LEN/2; 
        pp_new.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN - 1; 

        vec_gL = vec_gg_scalar(vec_gL, x_inverse); 
        vec_gR = vec_gg_scalar(vec_gR, x); 
        pp_new.vec_g = vec_gg_add(vec_gL, vec_gR); // Eq (29)

        vec_hL = vec_gg_scalar(vec_hL, x); 
        vec_hR = vec_gg_scalar(vec_hR, x_inverse); 
        pp_new.vec_h = vec_gg_add(vec_hL, vec_hR); // Eq (30)

        L *= (x * x); // compute L^{x^2}
        R *= (x_inverse * x_inverse); // compute R^{x^{-2}}
        instance_new.P = instance.P; 
        instance_new.P += L; 
        instance_new.P += R; // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        instance_new.u = instance.u; 

        vec_aL = vec_zz_scalar(vec_aL, x); 
        vec_aR = vec_zz_scalar(vec_aR, x_inverse); 
        witness_new.vec_a = vec_zz_add(vec_aL, vec_aR); // Eq (33)

        vec_bL = vec_zz_scalar(vec_bL, x_inverse); 
        vec_bR = vec_zz_scalar(vec_bR, x); 
        witness_new.vec_b = vec_zz_add(vec_bL, vec_bR); // Eq (34)

        InnerProduct_Prove(pp_new, instance_new, witness_new, proof); //
    }

    return true; 
}

/*
    Check if PI is a valid proof for inner product statement (G1^w = H1 and G2^w = H2)
*/

bool InnerProduct_Verify(InnerProduct_PP pp, InnerProduct_Instance instance, InnerProduct_Proof proof)
{
    bool Validity; 
    ECn LEFT, RIGHT; // define the left and right side of the equation on top of pp.17
 
    vector<Big> vec_x(pp.LOG_VECTOR_LEN); // the vector of challenge 
    vector<Big> vec_x_inverse(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    vector<Big> vec_x_square(pp.LOG_VECTOR_LEN); // the vector of challenge 
    vector<Big> vec_x_inverse_square(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    
    int i; 

    //cout << "recover the challenges" << endl; 
    vector<ECn> vec_HASH_x(2); 
    for (i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        vec_HASH_x[0] = proof.vec_L[i]; 
        vec_HASH_x[1] = proof.vec_R[i];  
        vec_x[i] = Hash_GGn_ZZ(vec_HASH_x); // reconstruct the challenge
        vec_x_square[i] = pow(vec_x[i], 2, q); 
        vec_x_inverse[i] = inverse(vec_x[i], q); 
        vec_x_inverse_square[i] = pow(vec_x_inverse[i], 2, q);
    }

    // compute right
    //cout << "the right value" << endl; 
    RIGHT = instance.P; 
    for (i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {
        proof.vec_L[i] *= vec_x_square[i]; // L_j^{x_j^2}
        proof.vec_R[i] *= vec_x_inverse_square[i]; // R_j^{x_j^{-2}} 
        RIGHT += proof.vec_L[i];
        RIGHT += proof.vec_R[i];
    }  

    // compute left
    //cout << "the left value" << endl; 
    vector<Big> vec_s = compute_vec_ss(vec_x, vec_x_inverse); // page 15: the s vector
    vector<Big> vec_s_inverse = vec_zz_invert(vec_s);  // the s^{-1} vector

    ECn G, H, U; 

    G = vec_gg_mul(pp.vec_g, vec_zz_scalar(vec_s, proof.a));
    H = vec_gg_mul(pp.vec_h, vec_zz_scalar(vec_s_inverse, proof.b)); 
    
    LEFT = instance.u; 
    LEFT *= (proof.a * proof.b); // LEFT = u^{ab} 
    LEFT += G; 
    LEFT += H;

    // the equation on top of page 17
    if (LEFT == RIGHT) 
    {
        Validity = TRUE;
        #ifdef DEBUG 
        cout<< "Inner Product Proof Accept..." << endl; 
        #endif
    }

    else {
        Validity = FALSE;
        #ifdef DEBUG
        cout<< "Inner Product Proof Reject..." << endl; 
        #endif
    }

    return Validity;
}


////////////////////////////////////////////////////////////////////////////////////////////

bool Naive_InnerProduct_Verify(InnerProduct_PP pp, InnerProduct_Instance instance, InnerProduct_Proof &proof)
{
    int n = pp.VECTOR_LEN;
    int round_n = pp.LOG_VECTOR_LEN; 
    int l = proof.vec_L.size(); // the size of proof (also the original log vector size of InnerProduct Proof)
    // Eq (16)
    if (n == 1)
    {
        ECn LEFT, RIGHT;  // define the left and right side of Eq (15)
        bool Validity;    // define the bool variable

        LEFT = instance.P; 
        RIGHT = instance.u; 
        RIGHT *= proof.a * proof.b; 
        RIGHT += mul(proof.a, pp.vec_g[0], proof.b, pp.vec_h[0]);  
        
        if (LEFT == RIGHT) 
        {
            Validity = TRUE; 
            #ifdef DEBUG
            cout<< "Inner Product Proof Accept..." << endl; 
            #endif
        }

        else 
        {
            Validity = FALSE;
            #ifdef DEBUG
            cout<< "Inner Product Proof Reject..." << endl; 
            #endif
        }

        return Validity; 
    }
    else
    {
        InnerProduct_PP pp_new; 
        InnerProduct_Instance instance_new; 
        ECn L = proof.vec_L[l - round_n]; 
        ECn R = proof.vec_R[l - round_n]; // Eq (24)

        vector<ECn> vec_HASH_x = {L, R};  
        Big x = Hash_GGn_ZZ(vec_HASH_x);  // Eq (26)
        Big x_inverse = inverse(x, q);

        // prepare gL, gR, hL, hR
        vector<ECn> vec_gL = vec_gg_assign(pp.vec_g, "left"); 
        vector<ECn> vec_gR = vec_gg_assign(pp.vec_g, "right"); 
        vector<ECn> vec_hL = vec_gg_assign(pp.vec_h, "left"); 
        vector<ECn> vec_hR = vec_gg_assign(pp.vec_h, "right");

        pp_new.VECTOR_LEN = pp.VECTOR_LEN/2; 
        pp_new.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN-1; 

        vec_gL = vec_gg_scalar(vec_gL, x_inverse); 
        vec_gR = vec_gg_scalar(vec_gR, x); 
        pp_new.vec_g = vec_gg_add(vec_gL, vec_gR); // Eq (29)

        vec_hL = vec_gg_scalar(vec_hL, x); 
        vec_hR = vec_gg_scalar(vec_hR, x_inverse); 
        pp_new.vec_h = vec_gg_add(vec_hL, vec_hR); // Eq (30)

        L *= (x * x); // compute L^{x^2}
        R *= (x_inverse * x_inverse); // compute R^{x^{-2}}
        instance_new.u = instance.u; 
        instance_new.P = instance.P; 
        instance_new.P += L; 
        instance_new.P += R; // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        return Naive_InnerProduct_Verify(pp_new, instance_new, proof);
    } 
}





