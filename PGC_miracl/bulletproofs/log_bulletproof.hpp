/***********************************************************************************
this hpp implements the logarithmic size Bulletproofs  
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
    int LOG_RANGE_LEN; 
    ECn u; // used for inside innerproduct statement
    // size of the vector = RANGE_LEN
    vector<ECn> vec_g; 
    vector<ECn> vec_h; // the pp of innerproduct part    
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
    InnerProduct_Proof ip_proof;    
};

Bullet_PP Bullet_Setup(int n)
{
    Bullet_PP pp;
    pp.RANGE_LEN = n; 
    pp.LOG_RANGE_LEN = log2(n); 
    pp.g = random_gg(); 
    pp.h = random_gg(); 
    pp.u = random_gg(); 
    pp.vec_g.resize(n);
    pp.vec_h.resize(n);  

    for (int i = 0; i < n; i++)
    {
        pp.vec_g[i] = random_gg(); 
        pp.vec_h[i] = random_gg();
    }
    
    #ifdef DEBUG
    Print_Splitline('*'); 
    cout << "generate pp successfully" << endl;
    Print_Splitline('*'); 
    #endif

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
    vector<Big> llx = vec_zz_add(poly_ll0, vec_zz_scalar(poly_ll1, x)); 
    vector<Big> rrx = vec_zz_add(poly_rr0, vec_zz_scalar(poly_rr1, x)); 
    proof.tx = inner_product(llx, rrx) %q;  // Eq (60)     

    proof.taux = (tau2*x_square + tau1*x + z_square*witness.r) %q; // Eq (61) -- blinding value for hat{t}
    proof.mu = (alpha + rho*x) %q; // Eq (62)


    // transmit llx and rrx via inner product proof
    Big y_inverse = inverse(y, q); 
    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, pp.RANGE_LEN); // y^{-i+1}
    vector<ECn> vec_h_new = vec_gg_product(pp.vec_h, vec_y_inverse_power); 

    InnerProduct_PP ip_pp; 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN; 
    ip_pp.LOG_VECTOR_LEN = pp.LOG_RANGE_LEN; 
    ip_pp.vec_g = pp.vec_g; 
    ip_pp.vec_h = vec_h_new; 

    vector<ECn> vec_HASH_e = {proof.A, proof.S, proof.T1, proof.T2}; 
    Big e = Hash_GGn_ZZ(vec_HASH_e);  

    InnerProduct_Witness ip_witness;
    ip_witness.vec_a = llx; 
    ip_witness.vec_b = rrx;   

    InnerProduct_Instance ip_instance;
    ip_instance.u = pp.u;
    ip_instance.u *= e; // u = u^e 
    ip_instance.P = ip_instance.u;
    ip_instance.P *= proof.tx;  // P = u^<l, r>
    ip_instance.P += vec_gg_mul(ip_pp.vec_g, ip_witness.vec_a); 
    ip_instance.P += vec_gg_mul(ip_pp.vec_h, ip_witness.vec_b); // P = g^l h'r u^<l, r>


    InnerProduct_Prove(ip_pp, ip_instance, ip_witness, proof.ip_proof); 

    #ifdef DEBUG
    cout << "Bullet proof generation succeeds..." << endl; 
    #endif

    return proof; 
}

bool Bullet_Verify(Bullet_PP pp, Bullet_Instance instance, Bullet_Proof proof)
{
    bool V1, V2, Validity; // variables for checking results

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

    vector<ECn> vec_HASH_e = {proof.A, proof.S, proof.T1, proof.T2}; 
    Big e = Hash_GGn_ZZ(vec_HASH_e);  

    vector<Big> vec_1_power(pp.RANGE_LEN, 1); // vec_unary = 1^n
    vector<Big> vec_2_power = gen_vec_zz_power(2, pp.RANGE_LEN); 
    vector<Big> vec_y_power = gen_vec_zz_power(y, pp.RANGE_LEN); 

    Big delta_yz = (z-z_square)*inner_product(vec_1_power, vec_y_power) 
                   - z_cubic*inner_product(vec_1_power, vec_2_power); 
    delta_yz %= q; // Eq (39)

    ECn LEFT, RIGHT; 
    // check Eq (65)    
    LEFT = mul(proof.taux, pp.g, proof.tx, pp.h); // LEFT = g^{\taux} h^\hat{t}
    RIGHT = mul(z_square, instance.C, delta_yz, pp.h); 
    RIGHT += mul(x, proof.T1, x_square, proof.T2); // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2}

    V1 = (LEFT==RIGHT); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Log Size BulletProof) = " << V1 << endl; 
    #endif

    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, pp.RANGE_LEN); // y^n
    vector<ECn> vec_h_new = vec_gg_product(pp.vec_h, vec_y_inverse_power); 

    // check Eq (66,67,68) using Inner Product Argument
    InnerProduct_PP ip_pp; 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN; 
    ip_pp.LOG_VECTOR_LEN = pp.LOG_RANGE_LEN; 
    ip_pp.vec_g = pp.vec_g;
    ip_pp.vec_h = vec_h_new;  

    InnerProduct_Proof ip_proof = proof.ip_proof;

    InnerProduct_Instance ip_instance;
    ip_instance.u = pp.u; 
    ip_instance.u *= e; // u = u^e   
    ip_instance.P = mul(1, proof.A, x, proof.S); // LEFT = A+S^x
    ip_instance.P += vec_gg_mul(ip_pp.vec_g, vec_zz_scalar(vec_1_power, -z)); // LEFT += g^{-1 z^n}  
    ip_instance.P += vec_gg_mul(ip_pp.vec_h, vec_zz_add(vec_zz_scalar(vec_y_power, z), vec_zz_scalar(vec_2_power, z_square)));  

    ip_instance.P += mul(-proof.mu, pp.h, proof.tx, ip_instance.u); // set P_new = P h^{-u} U^<l, r>   


    V2 = InnerProduct_Verify(ip_pp, ip_instance, ip_proof); 

    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (Log Size Bulletproof) = " << V2 << endl; 
    #endif

    Validity = V1 && V2;
     
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "log size Bulletproof accepts..." << endl; 
    }
    else 
    {
        cout<< "log size Bulletproof rejects..." << endl; 
    }
    #endif

    return Validity; 
}

bool Fast_Bullet_Verify(Bullet_PP pp, Bullet_Instance instance, Bullet_Proof proof)
{
    bool V1, V2, Validity; // variables for checking results

    // first step: recover the challenge
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

    vector<ECn> vec_HASH_e = {proof.A, proof.S, proof.T1, proof.T2}; 
    Big e = Hash_GGn_ZZ(vec_HASH_e);  


    vector<Big> vec_1_power(pp.RANGE_LEN, 1); // vec_unary = 1^n
    vector<Big> vec_2_power = gen_vec_zz_power(2, pp.RANGE_LEN); 
    vector<Big> vec_y_power = gen_vec_zz_power(y, pp.RANGE_LEN); 

    Big delta_yz = (z-z_square)*inner_product(vec_1_power, vec_y_power) 
                   - z_cubic*inner_product(vec_1_power, vec_2_power); 
    delta_yz %= q; // Eq (39)

    vector<ECn> G1(5); 
    vector<Big> a1(5); // going to check Eq (97) using multi-exponentiation
    G1[0] = pp.g, G1[1] = pp.h, G1[2] = instance.C, G1[3] = proof.T1, G1[4] = proof.T2;  
    a1[0] = proof.taux, a1[1] = proof.tx - delta_yz, a1[2] = -z_square, a1[3] = -x, a1[4] = -x_square; 
    ECn result1 = vec_gg_mul(G1, a1);   
    V1 = result1.iszero(); 

    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Log Size BulletProof) = " << V1 << endl; 
    #endif

    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, pp.RANGE_LEN); // y^n

    // recover the challenge of innerproduct proof
    vector<Big> vec_x(pp.LOG_RANGE_LEN); // the vector of challenge 
    vector<Big> vec_x_inverse(pp.LOG_RANGE_LEN); // the vector of challenge inverse
    vector<Big> vec_x_square(pp.LOG_RANGE_LEN); // the vector of challenge 
    vector<Big> vec_x_inverse_square(pp.LOG_RANGE_LEN); // the vector of challenge inverse
    
    for (int j = 0; j < pp.LOG_RANGE_LEN; j++)
    {  
        vec_HASH_x[0] = proof.ip_proof.vec_L[j]; 
        vec_HASH_x[1] = proof.ip_proof.vec_R[j];  
        vec_x[j] = Hash_GGn_ZZ(vec_HASH_x); // reconstruct the challenge
        vec_x_square[j] = pow(vec_x[j], 2, q); 
        vec_x_inverse[j] = inverse(vec_x[j], q); 
        vec_x_inverse_square[j] = pow(vec_x_inverse[j], 2, q);
    }

    // compute vec_s and vec_s_inverse 
    vector<Big> vec_s = compute_vec_ss(vec_x, vec_x_inverse); // page 15: the s vector
    vector<Big> vec_s_inverse = vec_zz_invert(vec_s);  // the s^{-1} vector

    vector<Big> llx(pp.RANGE_LEN); 
    vector<Big> rrx(pp.RANGE_LEN); 
    for(int i = 0; i < pp.RANGE_LEN; i++)
    {
        llx[i] = vec_s[i] * proof.ip_proof.a + z; 
        rrx[i] = vec_y_inverse_power[i] * (vec_s_inverse[i] * proof.ip_proof.b - z_square*vec_2_power[i]) -z; 
    }

    int l = 2*pp.RANGE_LEN + 4 + 2*pp.LOG_RANGE_LEN; 
    vector<ECn> tempG(l); 
    vector<Big> tempa(l); // going to check Eq (104) using multi-exponentiation

    int index = 0; 
    // push back vec_g^vec_l
    for (int i = 0; i < pp.RANGE_LEN; i++)
    {
        tempG[index+i] = pp.vec_g[i]; 
        tempa[index+i] = llx[i]; 
    }
    index = pp.RANGE_LEN; 
    // push back vec_h^vec_r
    for (int i = 0; i < pp.RANGE_LEN; i++)
    {
        tempG[index+i] = pp.vec_h[i]; 
        tempa[index+i] = rrx[i]; 
    }
    index = 2*pp.RANGE_LEN; 
    
    // push back u^{ab-tx} 
    ECn u = pp.u; 
    u *= e; 
    tempG[index] = u; 
    tempa[index] = proof.ip_proof.a*proof.ip_proof.b - proof.tx; 
    index++; 

    // push back h^mu
    tempG[index] = pp.h; 
    tempa[index] = proof.mu; 
    index++; 

    // push back A^{-1}
    tempG[index] = proof.A; 
    tempa[index] = -1; 
    index++; 

    // push back S^{-x}
    tempG[index] = proof.S; 
    tempa[index] = -x; 
    index++; 

    // push back vec_h^vec_r
    for (int i = 0; i < pp.LOG_RANGE_LEN; i++)
    {
        tempG[index+i] = proof.ip_proof.vec_L[i]; 
        tempa[index+i] = -vec_x_square[i]; 
    }
    index += pp.LOG_RANGE_LEN; 

    // push back vec_h^vec_r
    for (int i = 0; i < pp.LOG_RANGE_LEN; i++)
    {
        tempG[index+i] = proof.ip_proof.vec_R[i]; 
        tempa[index+i] = -vec_x_inverse_square[i]; 
    }
    index += pp.LOG_RANGE_LEN;

    ECn result2 = vec_gg_mul(tempG, tempa); 
    V2 = result2.iszero(); 

    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (log size Bulletproof) = " << V2 << endl; 
    #endif


    Validity = V1 && V2;
     
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "log size Bulletproof accepts..." << endl; 
    }
    else 
    {
        cout<< "log size Bulletproof rejects..." << endl; 
    }
    #endif

    return Validity; 
}