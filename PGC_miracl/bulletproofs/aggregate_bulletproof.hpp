/***********************************************************************************
this hpp implements aggregated logarithmic size Bulletproofs  
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/

#include <iostream>
#include <algorithm>
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
    int RANGE_LEN; 
    int LOG_RANGE_LEN; 
    int m; // number of sub-argument (for now, we require m to be the power of 2)

    ECn g, h;
    ECn u; // used for inside innerproduct statement
    vector<ECn> vec_g; 
    vector<ECn> vec_h; // the pp of innerproduct part    
};

struct Bullet_Instance
{
    vector<ECn> C;  // Ci = g^ri h^vi
}; 

struct Bullet_Witness
{
    vector<Big> r; 
    vector<Big> v; 
}; 

struct Bullet_Proof
{
    ECn A, S, T1, T2;  
    Big taux, mu, tx; 
    InnerProduct_Proof ip_proof;    
};

Bullet_PP Bullet_Setup(int n, int m)
{
    Bullet_PP pp;
    pp.RANGE_LEN = n; 
    pp.LOG_RANGE_LEN = log2(n);
    pp.m = m;  
    pp.g = random_gg(); 
    pp.h = random_gg(); 
    pp.u = random_gg(); 
    pp.vec_g.resize(n*m);
    pp.vec_h.resize(n*m);  

    for (int i = 0; i < n*m; i++)
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
    Big temp_z; 
    int l = pp.RANGE_LEN * pp.m; // l = mn
 
    vector<Big> vec_zz_temp(l, 1); 

    vector<Big> vec_aL(l); 
    vector<Big> vec_aR(l);
    //vector<Big> vec_al(l); 

    for (int j = 0; j < pp.m; j++)
    {
        for(int i = 0; i < pp.RANGE_LEN; i++)
        {
            vec_aL[j*pp.RANGE_LEN + i] = big_parse_binary(witness.v[j], i); 
        }
    }
   
    vector<Big> vec_1_power(l, 1); // vec_unary = 1^nm
    vec_aR = vec_zz_sub(vec_aL, vec_1_power); // Eq (42) -- aR = aL - 1^n

    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    Big alpha = random_zz(); 
    proof.A = pp.h;
    proof.A *= alpha; // h^alpha
    proof.A += vec_gg_mul(pp.vec_g, vec_aL);  // G^aL
    proof.A += vec_gg_mul(pp.vec_h, vec_aR);  // H^aR

    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    vector<Big> vec_sL = gen_random_vec_zz(l);
    vector<Big> vec_sR = gen_random_vec_zz(l);

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

    vector<Big> vec_adjust_z_power(pp.m+1); // generate z^{j+1} j \in [n]
    for (int j = 1; j <= pp.m; j++)
    {
        vec_adjust_z_power[j] = pow(z, j+1, q); 
    }  

    // prepare the vector polynomials
    
    // compute l(X)
    vector<Big> vec_z_unary = vec_zz_scalar(vec_1_power, z); // z \cdot 1^nm
    vector<Big> poly_ll0 = vec_zz_sub(vec_aL, vec_z_unary);  
    vector<Big> poly_ll1 = vec_sL;

    // compute r(X) 
    vec_zz_temp = vec_zz_add(vec_z_unary, vec_aR); // vec_t = aR + z1^nm
    vector<Big> vec_y_power = gen_vec_zz_power(y, l); // y^nm
    vector<Big> poly_rr0 = vec_zz_product(vec_y_power, vec_zz_temp); // y^nm(aR + z1^nm)
    
    vector<Big> vec_short_2_power = gen_vec_zz_power(2, pp.RANGE_LEN); // 2^n
    for (int j = 1; j <= pp.m; j++)
    {
        for (int i = 0; i < (j-1)*pp.RANGE_LEN; i++) vec_zz_temp[i] = 0; 
        for (int i = 0; i < pp.RANGE_LEN; i++) vec_zz_temp[(j-1)*pp.RANGE_LEN+i] = vec_short_2_power[i]; 
        for (int i = 0; i < (pp.m-j)*pp.RANGE_LEN; i++) vec_zz_temp[j*pp.RANGE_LEN+i] = 0; 
        poly_rr0 = vec_zz_add(poly_rr0, vec_zz_scalar(vec_zz_temp, vec_adjust_z_power[j]));  
    }
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

    // compute taux
    proof.taux = tau2*x_square + tau1*x; 
    for (int j = 1; j <= pp.m; j++)
    {
        proof.taux += vec_adjust_z_power[j]*witness.r[j-1]; 
    }
    proof.taux %= q; 

    //cout << "proof taux = " << proof.taux << endl; 

    // compute mu
    proof.mu = (alpha + rho*x) %q; // Eq (62)

    // transmit llx and rrx via inner product proof
    Big y_inverse = inverse(y, q); 
    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, l); // y^{-i+1}
    vector<ECn> vec_h_new = vec_gg_product(pp.vec_h, vec_y_inverse_power); 

    InnerProduct_PP ip_pp; 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN * pp.m; 
    ip_pp.LOG_VECTOR_LEN = log2(ip_pp.VECTOR_LEN); 
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
    cout << "Bullet Proof Generation Succeeds..." << endl; 
    #endif

    return proof; 
}

bool Bullet_Verify(Bullet_PP pp, Bullet_Instance instance, Bullet_Proof proof)
{
    #ifdef DEBUG
    cout << "begin to check the proof" << endl; 
    #endif

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

    int l = pp.RANGE_LEN * pp.m; 

    vector<Big> vec_1_power(l, 1); // vec_unary = 1^nm
    vector<Big> vec_short_1_power(pp.RANGE_LEN, 1); 
    vector<Big> vec_2_power = gen_vec_zz_power(2, l);
    vector<Big> vec_short_2_power = gen_vec_zz_power(2, pp.RANGE_LEN);  

    vector<Big> vec_y_power = gen_vec_zz_power(y, l); 

    vector<Big> vec_adjust_z_power(pp.m+1); // generate z^{j+1} j \in [n]
    for (int j = 1; j <= pp.m; j++)
    {
        vec_adjust_z_power[j] = pow(z, j+1, q); 
    }     

    // compute sum_{j=1^m} z^{j+2}
    Big sum_z = 0; 
    for (int j = 1; j <= pp.m; j++)
    {
        sum_z += (z*vec_adjust_z_power[j])%q; 
    } 

    // compute delta_yz (pp. 21)
    Big delta_yz = (z-z_square)*inner_product(vec_1_power, vec_y_power) 
                   - sum_z*inner_product(vec_short_1_power,vec_short_2_power); //Eq (39)

    ECn LEFT, RIGHT, RIGHT_prime; 
    // check Eq (72)    
    LEFT = mul(proof.taux, pp.g, proof.tx, pp.h); // LEFT = g^{\taux} h^\hat{t}
    
    vector<ECn> tempG; 
    vector<Big> tempa; 
    tempG.resize(pp.m + 3); 
    tempa.resize(pp.m + 3); // the intermediate variables used to compute the right value
    copy(instance.C.begin(), instance.C.end(), tempG.begin()); 
    copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), tempa.begin()); 

    tempG[pp.m] = pp.h, tempG[pp.m+1] = proof.T1, tempG[pp.m+2] = proof.T2;
    tempa[pp.m] = delta_yz, tempa[pp.m+1] = x, tempa[pp.m+2] = x_square;   

    RIGHT = vec_gg_mul(tempG, tempa);  // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2} 

    V1 = (LEFT == RIGHT); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << endl; 
    #endif

    vector<Big> vec_y_inverse_power = gen_vec_zz_power(y_inverse, l); // y^nm
    vector<ECn> vec_h_new = vec_gg_product(pp.vec_h, vec_y_inverse_power); 

    // check Eq (66,67,68) using Inner Product Argument
    InnerProduct_PP ip_pp; 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN * pp.m; 
    ip_pp.LOG_VECTOR_LEN = log2(ip_pp.VECTOR_LEN); 
    ip_pp.vec_g = pp.vec_g;
    ip_pp.vec_h = vec_h_new;  

    InnerProduct_Proof ip_proof = proof.ip_proof;

    InnerProduct_Instance ip_instance;
    ip_instance.u = pp.u; 
    ip_instance.u *= e; // u = u^e   
    ip_instance.P = mul(1, proof.A, x, proof.S); // LEFT = A+S^x
    ip_instance.P += vec_gg_mul(ip_pp.vec_g, vec_zz_scalar(vec_1_power, -z)); // LEFT += g^{-1 z^n}  
      
    // compute rr = z^ \cdot y^nm+(XYZ)
    vector<Big> vec_rr(l); 
    vec_rr = vec_zz_scalar(vec_y_power, z); // z y^nm

    vector<Big> vec_zz_temp; 
    for(int j = 1; j <= pp.m; j++)
    {
        vec_zz_temp = vec_zz_scalar(vec_2_power, vec_adjust_z_power[j]); 
        for(int i = 0; i < pp.RANGE_LEN; i++)
        {
            vec_rr[(j-1)*pp.RANGE_LEN+i] += vec_zz_temp[i];             
        }

    }
    ip_instance.P += vec_gg_mul(ip_pp.vec_h, vec_rr); 
    ip_instance.P += mul(-proof.mu, pp.h, proof.tx, ip_instance.u); // set P_new = P h^{-u} U^<l, r>   

    V2 = InnerProduct_Verify(ip_pp, ip_instance, ip_proof); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 2 (Aggregating Log Size BulletProof) = " << V2 << endl; 
    #endif

    Validity = V1 && V2;     
    #ifdef DEBUG
    if (Validity) 
    { 
        cout<< "log size BulletProof accepts..." << endl; 
    }
    else 
    {
        cout<< "log size BulletProof rejects..." << endl; 
    }
    #endif

    return Validity; 
}


void Print_Bullet_Proof(Bullet_Proof proof)
{
    cout << "A = " << proof.A << endl;
    cout << "S = " << proof.S << endl;
    cout << "T1 = " << proof.T1 << endl;
    cout << "T2 = " << proof.T2 << endl;
    cout << "taux = " << proof.taux << endl;
    cout << "mu = " << proof.mu << endl;
    cout << "tx = " << proof.tx << endl;

    for (int i = 0; i < proof.ip_proof.vec_L.size(); i++){
        cout << "vec_L[" << i << "] = " << proof.ip_proof.vec_L[i] << endl;
        cout << "vec_R[" << i << "] = " << proof.ip_proof.vec_R[i] << endl;
    }  
    cout << "a = " << proof.ip_proof.a << endl;
    cout << "b = " << proof.ip_proof.b << endl;
}

void Serialize_Bullet_Proof(Bullet_Proof proof, ofstream& fout)
{
    Serialize_GG(proof.A, fout); 
    Serialize_GG(proof.S, fout);
    Serialize_GG(proof.T1, fout);
    Serialize_GG(proof.T2, fout);

    Serialize_ZZ(proof.taux, fout); 
    Serialize_ZZ(proof.mu, fout); 
    Serialize_ZZ(proof.tx, fout); 

    Serialize_vec_GG(proof.ip_proof.vec_L, fout);
    Serialize_vec_GG(proof.ip_proof.vec_R, fout);

    Serialize_ZZ(proof.ip_proof.a, fout); 
    Serialize_ZZ(proof.ip_proof.b, fout); 
}

void Deserialize_Bullet_Proof(Bullet_Proof& proof, ifstream& fin)
{
    Deserialize_GG(proof.A, fin); 
    Deserialize_GG(proof.S, fin);
    Deserialize_GG(proof.T1, fin);
    Deserialize_GG(proof.T2, fin);

    Deserialize_ZZ(proof.taux, fin); 
    Deserialize_ZZ(proof.mu, fin); 
    Deserialize_ZZ(proof.tx, fin); 

    Deserialize_vec_GG(proof.ip_proof.vec_L, fin);
    Deserialize_vec_GG(proof.ip_proof.vec_R, fin);

    Deserialize_ZZ(proof.ip_proof.a, fin); 
    Deserialize_ZZ(proof.ip_proof.b, fin); 
}
