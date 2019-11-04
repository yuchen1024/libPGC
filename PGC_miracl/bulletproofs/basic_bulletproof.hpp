/***********************************************************************************
this hpp implements the basic Bulletproofs  
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

#include "innerproduct_proof.hpp" 


// define the structure of Bulletproofs
struct Bullet_PP
{
    ECn g, h;
    
    int RANGE_LEN; 
    // size of the vector = RANGE_LEN
    vector<ECn> vec_g; 
    vector<ECn> vec_h; 
};

struct Bullet_Instance
{
    ECn C;  // C = g^r h^v
}; 

struct Bullet_Witness
{
    Big r, v;   
}; 

struct Bullet_Proof
{
    ECn A, S, T1, T2;  
    Big taux, mu, tx; 
    vector<Big> llx; 
    vector<Big> rrx;     
};

Bullet_PP Bullet_Setup(int n)
{
    Bullet_PP pp;
    pp.RANGE_LEN = n; 
    pp.g = random_gg(); 
    pp.h = random_gg(); 
    pp.vec_g.resize(n);
    pp.vec_h.resize(n);  
 
    for (int i = 0; i < n; i++)
    {
        pp.vec_g[i] = random_gg(); 
        pp.vec_h[i] = random_gg();
    }
    return pp; 
}

// statement C = g^r h^v and v \in [0, 2^n-1]
Bullet_Proof Bullet_Prove(const Bullet_PP pp, const Bullet_Instance instance, const Bullet_Witness witness)
{
    Bullet_Proof proof; 

    vector<Big> vec_zz_temp(pp.RANGE_LEN, 1); 

    vector<Big> vec_aL(pp.RANGE_LEN); // Eq (41) --naL is the binary representation of v
    for(int i = 0; i < pp.RANGE_LEN; i++)
    {
        vec_aL[i] = big_parse_binary(witness.v, i); 
    }

    vector<Big> vec_1_power(pp.RANGE_LEN, 1); // vec_unary = 1^n
    vector<Big> vec_aR = vec_zz_sub(vec_aL, vec_1_power); // Eq (42) -- aR = aL - 1^n

    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    Big alpha = random_zz(); 
    proof.A = pp.h;
    proof.A *= alpha; // h^alpha
    proof.A += vec_gg_mul(pp.vec_g, vec_aL);  // G^aL
    proof.A += vec_gg_mul(pp.vec_h, vec_aR);  // H^aR

    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    vector<Big> vec_sL = gen_random_vec_zz(pp.RANGE_LEN);
    vector<Big> vec_sR = gen_random_vec_zz(pp.RANGE_LEN);

    // Eq (47) compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    Big rho = random_zz(); 
    proof.S = pp.h;
    proof.S *= rho; // h^alpha
    proof.S += vec_gg_mul(pp.vec_g, vec_sL);  // g^sL
    proof.S += vec_gg_mul(pp.vec_h, vec_sR);  // h^sR

    // Eq (49, 50) compute y and z
    vector<ECn> vec_HASH_y = {proof.A, proof.S}; 
    Big y = Hash_GGn_ZZ(vec_HASH_y);

    vector<ECn> vec_HASH_z = {proof.S, proof.A}; 
    Big z = Hash_GGn_ZZ(vec_HASH_z);

    Big z_square = (z*z)%q;
    Big z_cubic = (z_square*z)%q; 

    // prepare the vector polynomials
    
    // compute l(X)
    vector<Big> vec_z_unary = vec_zz_scalar(vec_1_power, z); // z \cdot 1^n
    vector<Big> poly_ll0 = vec_zz_sub(vec_aL, vec_z_unary);  
    vector<Big> poly_ll1 = vec_sL;

    /* compute r(X) */
    vec_zz_temp = vec_zz_add(vec_z_unary, vec_aR); // vec_t = aR + z1^n
    vector<Big> vec_y_power = gen_vec_zz_power(y, pp.RANGE_LEN); // y^n
    vector<Big> poly_rr0 = vec_zz_product(vec_y_power, vec_zz_temp); // y^n(aR + z1^n)
    vector<Big> vec_2_power = gen_vec_zz_power(2, pp.RANGE_LEN); // 2^n
    poly_rr0 = vec_zz_add(poly_rr0, vec_zz_scalar(vec_2_power, z_square)); 
    vector<Big> poly_rr1 = vec_zz_product(vec_y_power, vec_sR); //y^nsR X


    // compute t(X) 
    Big t0 = inner_product(poly_ll0, poly_rr0); 
    Big t1 = (inner_product(poly_ll1, poly_rr0) + inner_product(poly_ll0, poly_rr1))%q; 
    Big t2 = inner_product(poly_ll1, poly_rr1); 

    // P picks tau1 and tau2
    Big tau1 = random_zz(); 
    Big tau2 = random_zz();

    // Eq (53) -- commit to t1, t2
    proof.T1 = mul(tau1, pp.g, t1, pp.h);
    proof.T2 = mul(tau2, pp.g, t2, pp.h);

    // Eq (56) -- compute the challenge x
    vector<ECn> vec_HASH_x = {proof.T1, proof.T2}; 
    Big x = Hash_GGn_ZZ(vec_HASH_x); 
    Big x_square = (x*x)%q; 

    // compute the value of l(x) and r(x) at point x
    proof.llx = vec_zz_add(poly_ll0, vec_zz_scalar(poly_ll1, x)); 
    proof.rrx = vec_zz_add(poly_rr0, vec_zz_scalar(poly_rr1, x)); 
    proof.tx = inner_product(proof.llx, proof.rrx) %q;  // Eq (60)     

    proof.taux = (tau2*x_square + tau1*x + z_square*witness.r) %q; // Eq (61) -- blinding value for hat{t}
    proof.mu = (alpha + rho*x) %q; // Eq (62) 

    #ifdef DEBUG
    cout << "Bulletproof generation succeeds..." << endl; 
    #endif

    return proof; 
}

bool Bullet_Verify(Bullet_PP pp, Bullet_Instance instance, Bullet_Proof proof)
{
    bool V1, V2, V3, Validity; // variables for checking results


    vector<ECn> vec_HASH_y = {proof.A, proof.S}; 
    Big y = Hash_GGn_ZZ(vec_HASH_y);   
    Big y_inverse = inverse(y, q);   //recover the challenge y from PI

    vector<ECn> vec_HASH_z = {proof.S, proof.A}; 
    Big z = Hash_GGn_ZZ(vec_HASH_z); 
    Big z_square = (z*z)%q; 
    Big z_cubic = (z*z_square)%q;    //recover the challenge z from PI

    vector<ECn> vec_HASH_x = {proof.T1, proof.T2}; 
    Big x = Hash_GGn_ZZ(vec_HASH_x); 
    Big x_square = (x*x)%q;          //recover the challenge x from PI

    vector<Big> vec_1_power(pp.RANGE_LEN, 1); // vec_unary = 1^n
    vector<Big> vec_2_power = gen_vec_zz_power(2, pp.RANGE_LEN); 
    vector<Big> vec_y_power = gen_vec_zz_power(y, pp.RANGE_LEN); 

    Big delta_yz = (z-z_square)*inner_product(vec_1_power, vec_y_power) 
                   - z_cubic*inner_product(vec_1_power, vec_2_power); 
    delta_yz %= q; // Eq (39)

    ECn LEFT1, RIGHT1; 
    // check Eq (65)    
    LEFT1 = mul(proof.taux, pp.g, proof.tx, pp.h); // LEFT = g^{\taux} h^\hat{t}
    RIGHT1 = mul(z_square, instance.C, delta_yz, pp.h); 
    RIGHT1 += mul(x, proof.T1, x_square, proof.T2); // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2}

    V1 = (LEFT1 == RIGHT1); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (BulletProof) = " << V1 << endl; 
    #endif

    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, pp.RANGE_LEN); // y^n
    vector<ECn> vec_h_new = vec_gg_product(pp.vec_h, vec_y_inverse_power); 

    ECn LEFT2 = mul(1, proof.A, x, proof.S); // LEFT = A+S^x
    LEFT2 += vec_gg_mul(pp.vec_g, vec_zz_scalar(vec_1_power, -z)); // LEFT += g^{-1 z^n}  
    LEFT2 += vec_gg_mul(vec_h_new, vec_zz_add(vec_zz_scalar(vec_y_power, z), vec_zz_scalar(vec_2_power, z_square)));  

    ECn RIGHT2 = pp.h; 
    RIGHT2 *= proof.mu; 
    RIGHT2 += vec_gg_mul(pp.vec_g, proof.llx);
    RIGHT2 += vec_gg_mul(vec_h_new, proof.rrx);  // set RIGHT = h^mu vec_g^llx vec_h'^rrx    

    V2 = (LEFT2 == RIGHT2); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (Bulletproof) = " << V2 << endl; 
    #endif

    Big LEFT3 = proof.tx; 
    Big RIGHT3 = inner_product(proof.llx, proof.rrx); 

    V3 = (LEFT3 == RIGHT3); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 3 (Bulletproof) = " << V3 << endl; 
    #endif

    Validity = V1 && V2 && V3;
     
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "BulletProof accepts..." << endl; 
    }
    else 
    {
        cout<< "BulletProof rejects..." << endl; 
    }
    #endif

    return Validity; 
}

