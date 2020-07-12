/***********************************************************************************
this hpp implements aggregated logarithmic size Bulletproofs  
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef __BULLET__
#define __BULLET__
#include "innerproduct_proof.hpp" 

// define the structure of Bulletproofs
struct Bullet_PP
{
    size_t RANGE_LEN; 
    size_t LOG_RANGE_LEN; 
    size_t AGG_NUM; // number of sub-argument (for now, we require m to be the power of 2)

    EC_POINT *g, *h;
    EC_POINT *u; // used for inside innerproduct statement
    vector<EC_POINT *> vec_g; 
    vector<EC_POINT *> vec_h; // the pp of innerproduct part    
};

struct Bullet_Instance
{
    vector<EC_POINT *> C;  // Ci = g^ri h^vi
}; 

struct Bullet_Witness
{
    vector<BIGNUM *> r; 
    vector<BIGNUM *> v; 
}; 

struct Bullet_Proof
{
    EC_POINT *A, *S, *T1, *T2;  
    BIGNUM *taux, *mu, *tx; 
    InnerProduct_Proof ip_proof;    
};

void Bullet_Proof_print(Bullet_Proof &proof)
{
    ECP_print(proof.A, "proof.A"); 
    ECP_print(proof.S, "proof.S"); 
    ECP_print(proof.T1, "proof.T1");  
    ECP_print(proof.T2, "proof.T2");  

    BN_print(proof.taux, "proof.taux"); 
    BN_print(proof.mu, "proof.mu"); 
    BN_print(proof.tx, "proof.tx"); 

    InnerProduct_Proof_print(proof.ip_proof); 
}

void Bullet_Proof_serialize(Bullet_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.A, fout); 
    ECP_serialize(proof.S, fout);
    ECP_serialize(proof.T1, fout);
    ECP_serialize(proof.T2, fout);

    BN_serialize(proof.taux, fout); 
    BN_serialize(proof.mu, fout); 
    BN_serialize(proof.tx, fout); 

    InnerProduct_Proof_serialize(proof.ip_proof, fout); 
}

void Bullet_Proof_deserialize(Bullet_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.A, fin); 
    ECP_deserialize(proof.S, fin);
    ECP_deserialize(proof.T1, fin);
    ECP_deserialize(proof.T2, fin);

    BN_deserialize(proof.taux, fin); 
    BN_deserialize(proof.mu, fin); 
    BN_deserialize(proof.tx, fin); 

    InnerProduct_Proof_deserialize(proof.ip_proof, fin); 
}

void Bullet_PP_new(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM)
{
    pp.g = EC_POINT_new(group);  
    pp.h = EC_POINT_new(group);
    pp.u = EC_POINT_new(group);  

    pp.vec_g.resize(RANGE_LEN*AGG_NUM); ECP_vec_new(pp.vec_g); 
    pp.vec_h.resize(RANGE_LEN*AGG_NUM); ECP_vec_new(pp.vec_h);  
}

void Bullet_PP_free(Bullet_PP &pp)
{
    EC_POINT_free(pp.g);
    EC_POINT_free(pp.h);
    EC_POINT_free(pp.u); 
    ECP_vec_free(pp.vec_g); 
    ECP_vec_free(pp.vec_h); 
}

void Bullet_Witness_new(Bullet_PP &pp, Bullet_Witness &witness)
{
    witness.r.resize(pp.AGG_NUM); 
    BN_vec_new(witness.r); 
    witness.v.resize(pp.AGG_NUM); 
    BN_vec_new(witness.v); 
} 

void Bullet_Witness_free(Bullet_Witness &witness)
{
    BN_vec_free(witness.r);  
    BN_vec_free(witness.v); 
}

void Bullet_Instance_new(Bullet_PP &pp, Bullet_Instance &instance)
{
    instance.C.resize(pp.AGG_NUM); 
    ECP_vec_new(instance.C); 
}

void Bullet_Instance_free(Bullet_Instance &instance)
{
    ECP_vec_free(instance.C); 
}

void Bullet_Proof_new(Bullet_Proof &proof)
{
    proof.A = EC_POINT_new(group); 
    proof.S = EC_POINT_new(group); 
    proof.T1 = EC_POINT_new(group); 
    proof.T2 = EC_POINT_new(group); 
    proof.taux = BN_new();   
    proof.mu = BN_new(); 
    proof.tx = BN_new();
    InnerProduct_Proof_new(proof.ip_proof);
}

void Bullet_Proof_free(Bullet_Proof &proof)
{
    EC_POINT_free(proof.A); 
    EC_POINT_free(proof.S); 
    EC_POINT_free(proof.T1); 
    EC_POINT_free(proof.T2); 
    BN_free(proof.taux);   
    BN_free(proof.mu); 
    BN_free(proof.tx);
    InnerProduct_Proof_free(proof.ip_proof);
}

void Bullet_Setup(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN); 
    pp.AGG_NUM = AGG_NUM; 
 
    EC_POINT_copy(pp.g, generator); 
    Hash_ECP_to_ECP(pp.g, pp.h); 
    ECP_random(pp.u);
    //cout << "Bulletproof setup finished" << endl; 
}


// statement C = g^r h^v and v \in [0, 2^n-1]
void Bullet_Prove(Bullet_PP &pp, Bullet_Instance &instance, Bullet_Witness &witness, 
                  string &transcript_str, Bullet_Proof &proof)
{ 
    auto start_time = chrono::steady_clock::now(); 
    for (auto i = 0; i < instance.C.size(); i++){
        transcript_str += ECP_ep2string(instance.C[i]); 
    }

    BIGNUM *temp_bn; 
    size_t l = pp.RANGE_LEN * pp.AGG_NUM; // l = mn

    vector<BIGNUM *> vec_aL(l); 
    BN_vec_new(vec_aL); 
    vector<BIGNUM *> vec_aR(l);
    BN_vec_new(vec_aR); 
    vector<BIGNUM *> vec_1_power(l); // vec_unary = 1^nm
    BN_vec_new(vec_1_power);
    for(auto i = 0; i < l; i++) BN_one(vec_1_power[i]); 
   
    for (auto i = 0; i < pp.AGG_NUM; i++)
    {
        for(auto j = 0; j < pp.RANGE_LEN; j++)
        {
            if(BN_parse_binary(witness.v[i], j) == 1){
                BN_one(vec_aL[i*pp.RANGE_LEN + j]);  
            }
            else{
                BN_zero(vec_aL[i*pp.RANGE_LEN + j]); 
            } 
        }
    }

    BN_vec_sub(vec_aR, vec_aL, vec_1_power); // Eq (42) -- aR = aL - 1^n

    // prepare vec_A and vec_a for multi-exponention (used hereafter)
    vector<EC_POINT *> vec_A; 
    vector<BIGNUM *> vec_a; 

    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    BIGNUM *alpha = BN_new(); 
    BN_random(alpha); 

    vec_A.emplace_back(pp.h); 
    vec_A.insert(vec_A.end(), pp.vec_g.begin(), pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end()); 

    vec_a.emplace_back(alpha); 
    vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
    vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 

    ECP_vec_mul(proof.A, vec_A, vec_a); // Eq (44) 


    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    vector<BIGNUM *> vec_sL(l);
    BN_vec_new(vec_sL); 
    BN_vec_random(vec_sL); 

    vector<BIGNUM *> vec_sR(l);
    BN_vec_new(vec_sR); 
    BN_vec_random(vec_sR); 
    
    // Eq (47) compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    BIGNUM *rho = BN_new(); 
    BN_random(rho); 

    vec_a.clear(); 
    vec_a.emplace_back(rho); 
    vec_a.insert(vec_a.end(), vec_sL.begin(), vec_sL.end()); 
    vec_a.insert(vec_a.end(), vec_sR.begin(), vec_sR.end()); 

    ECP_vec_mul(proof.S, vec_A, vec_a); // Eq (47) 

    // Eq (49, 50) compute y and z
    transcript_str += ECP_ep2string(proof.A); 
    BIGNUM *y = BN_new(); 
    Hash_String_to_BN(transcript_str, y);

    BIGNUM* y_inverse = BN_new();
    BN_mod_inverse(y_inverse, y, order, bn_ctx); 

    vector<BIGNUM *> vec_y_inverse_power(l); 
    BN_vec_new(vec_y_inverse_power); 
    BN_vec_gen_power(vec_y_inverse_power, y_inverse); // y^{-i+1}

    transcript_str += ECP_ep2string(proof.S); 
    BIGNUM *z = BN_new(); 
    Hash_String_to_BN(transcript_str, z);

    BIGNUM *z_square = BN_new(); 
    BN_mod_sqr(z_square, z, order, bn_ctx);
    BIGNUM *z_cubic = BN_new(); 
    BN_mod_mul(z_cubic, z, z_square, order, bn_ctx);
    
    vector<BIGNUM *> vec_adjust_z_power(pp.AGG_NUM+1); // generate z^{j+1} j \in [n]
    BN_vec_new(vec_adjust_z_power); 
    BN_copy(vec_adjust_z_power[0], z); 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BN_mod_mul(vec_adjust_z_power[j], z, vec_adjust_z_power[j-1], order, bn_ctx); 
        //vec_adjust_z_power[j] = pow(z, j+1, q); description below Eq (71)
    }  

    // prepare the vector polynomials
    
    // compute l(X) Eq (70)
    vector<BIGNUM *> vec_z_unary(l); 
    BN_vec_new(vec_z_unary); 
    BN_vec_scalar(vec_z_unary, vec_1_power, z); // z \cdot 1^nm

    vector<BIGNUM *> poly_ll0(l);
    BN_vec_new(poly_ll0); 
    vector<BIGNUM *> poly_ll1(l);
    BN_vec_new(poly_ll1); 
    BN_vec_sub(poly_ll0, vec_aL, vec_z_unary);  
    BN_vec_copy(poly_ll1, vec_sL); 

    // compute r(X)     
    vector<BIGNUM *> poly_rr0(l); 
    BN_vec_new(poly_rr0); 

    vector<BIGNUM *> vec_y_power(l); 
    BN_vec_new(vec_y_power); 
    BN_vec_gen_power(vec_y_power, y); // y^nm

    vector<BIGNUM *> vec_zz_temp(l); 
    BN_vec_new(vec_zz_temp); 
    BN_vec_add(vec_zz_temp, vec_z_unary, vec_aR); // vec_t = aR + z1^nm
    BN_vec_product(poly_rr0, vec_y_power, vec_zz_temp); // y^nm(aR + z1^nm)
    
    vector<BIGNUM *> vec_short_2_power(pp.RANGE_LEN); 
    BN_vec_new(vec_short_2_power); 
    BN_vec_gen_power(vec_short_2_power, BN_2); // 2^n

    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        for (auto i = 0; i < (j-1)*pp.RANGE_LEN; i++) 
            BN_zero(vec_zz_temp[i]); 
        for (auto i = 0; i < pp.RANGE_LEN; i++) 
            BN_copy(vec_zz_temp[(j-1)*pp.RANGE_LEN+i], vec_short_2_power[i]); 
        for (auto i = 0; i < (pp.AGG_NUM-j)*pp.RANGE_LEN; i++) 
            BN_zero(vec_zz_temp[j*pp.RANGE_LEN+i]);

        BN_vec_scalar(vec_zz_temp, vec_zz_temp, vec_adjust_z_power[j]); 
        //BN_print(vec_adjust_z_power[j], "adjust_vec_z"); 
        BN_vec_add(poly_rr0, poly_rr0, vec_zz_temp);  
    }
    vector<BIGNUM *> poly_rr1(l); 
    BN_vec_new(poly_rr1); 
    BN_vec_product(poly_rr1, vec_y_power, vec_sR); //y^nsR X

    // compute t(X) 
    BIGNUM* bn_temp  = BN_new(); 
    BIGNUM* bn_temp1 = BN_new(); 
    BIGNUM* bn_temp2 = BN_new(); 
    
    BIGNUM* t0 = BN_new(); 
    BIGNUM* t1 = BN_new(); 
    BIGNUM* t2 = BN_new(); 
    
    BN_vec_inner_product(t0, poly_ll0, poly_rr0); 
    BN_vec_inner_product(bn_temp1, poly_ll1, poly_rr0); 
    BN_vec_inner_product(bn_temp2, poly_ll0, poly_rr1);
    BN_mod_add(t1, bn_temp1, bn_temp2, order, bn_ctx);  
  
    BN_vec_inner_product(t2, poly_ll1, poly_rr1); 

    // Eq (53) -- commit to t1, t2
    // P picks tau1 and tau2
    BIGNUM* tau1 = BN_new(); 
    BN_random(tau1); 
    BIGNUM* tau2 = BN_new(); 
    BN_random(tau2);

    EC_POINT_mul(group, proof.T1, tau1, pp.h, t1, bn_ctx); // mul(tau1, pp.g, t1, pp.h);
    EC_POINT_mul(group, proof.T2, tau2, pp.h, t2, bn_ctx); // mul(tau2, pp.g, t2, pp.h);    

    // Eq (56) -- compute the challenge x
    transcript_str += ECP_ep2string(proof.T1) + ECP_ep2string(proof.T2); 
    BIGNUM* x = BN_new(); 
    Hash_String_to_BN(transcript_str, x); 

    BIGNUM* x_square = BN_new(); 
    BN_mod_sqr(x_square, x, order, bn_ctx);  

    // compute the value of l(x) and r(x) at point x
    vector<BIGNUM *> llx(l); 
    BN_vec_new(llx);
    BN_vec_scalar(vec_zz_temp, poly_ll1, x);
    BN_vec_add(llx, poly_ll0, vec_zz_temp);

    vector<BIGNUM *> rrx(l); 
    BN_vec_new(rrx);
    BN_vec_scalar(vec_zz_temp, poly_rr1, x); 
    BN_vec_add(rrx, poly_rr0, vec_zz_temp); 

    BN_vec_inner_product(proof.tx, llx, rrx);  // Eq (60)  
 
    // compute taux
    BN_mul(bn_temp1, tau1, x, bn_ctx);
    BN_mul(bn_temp2, tau2, x_square, bn_ctx);
    BN_mod_add(proof.taux, bn_temp1, bn_temp2, order, bn_ctx); //proof.taux = tau2*x_square + tau1*x; 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BN_mul(bn_temp, vec_adjust_z_power[j], witness.r[j-1], bn_ctx); 
        BN_mod_add(proof.taux, proof.taux, bn_temp, order, bn_ctx); 
    }

    // compute proof.mu = (alpha + rho*x) %q;  Eq (62)
    BN_mul(proof.mu, rho, x, bn_ctx); 
    BN_mod_add(proof.mu, proof.mu, alpha, order, bn_ctx); 
    
    // transmit llx and rrx via inner product proof
    vector<EC_POINT *> vec_h_new(l); 
    ECP_vec_new(vec_h_new); 
    ECP_vec_product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    InnerProduct_PP ip_pp; 
    InnerProduct_PP_new(ip_pp, pp.RANGE_LEN*pp.AGG_NUM); 
    InnerProduct_Setup(ip_pp, pp.RANGE_LEN*pp.AGG_NUM, false); 
    ECP_vec_copy(ip_pp.vec_g, pp.vec_g); // ip_pp.vec_g = pp.vec_g
    ECP_vec_copy(ip_pp.vec_h, vec_h_new);  // ip_pp.vec_h = vec_h_new  

    transcript_str += BN_bn2string(x); 
    BIGNUM* e = BN_new(); 
    Hash_String_to_BN(transcript_str, e);   

    InnerProduct_Witness ip_witness;
    InnerProduct_Witness_new(ip_witness, l); 
    BN_vec_copy(ip_witness.vec_a, llx); // ip_witness.vec_a = llx
    BN_vec_copy(ip_witness.vec_b, rrx); // ip_witness.vec_b = rrx

    InnerProduct_Instance ip_instance;
    InnerProduct_Instance_new(ip_instance);
    EC_POINT_copy(ip_instance.u, pp.u); // ip_instance.u = pp.u
    EC_POINT_mul(group, ip_instance.u, NULL, ip_instance.u, e, bn_ctx); //ip_instance.u = u^e 

    vec_A.clear(); vec_a.clear();

    vec_A.emplace_back(ip_instance.u); 
    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 

    vec_a.emplace_back(proof.tx); 
    vec_a.insert(vec_a.end(), ip_witness.vec_a.begin(), ip_witness.vec_a.end()); 
    vec_a.insert(vec_a.end(), ip_witness.vec_b.begin(), ip_witness.vec_b.end()); 

    ECP_vec_mul(ip_instance.P, vec_A, vec_a);  

    transcript_str += ECP_ep2string(ip_instance.P) + ECP_ep2string(ip_instance.u);  
 
    InnerProduct_Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        cout << "Bullet Proof Generation Succeeds >>>" << endl; 
    #endif

    BN_vec_free(vec_aL), BN_vec_free(vec_aR); 
    BN_vec_free(vec_1_power);
    BN_free(alpha), BN_free(rho);
    BN_vec_free(vec_sL), BN_vec_free(vec_sR);
    BN_free(x); 
    BN_free(y), BN_free(y_inverse);  
    BN_vec_free(vec_y_power), BN_vec_free(vec_y_inverse_power); 
    BN_free(z), BN_free(z_square), BN_free(z_cubic); 
    BN_vec_free(vec_adjust_z_power); 
    BN_vec_free(vec_z_unary); 
    BN_free(e); 

    BN_vec_free(poly_ll0), BN_vec_free(poly_ll1);  
    BN_vec_free(poly_rr0), BN_vec_free(poly_rr1);  

    BN_free(tau1), BN_free(tau2); 
    BN_vec_free(llx), BN_vec_free(rrx);  

    ECP_vec_free(vec_h_new); 

    BN_free(bn_temp), BN_free(bn_temp1), BN_free(bn_temp2); 
    BN_free(t0), BN_free(t1), BN_free(t2);  

    InnerProduct_PP_free(ip_pp); 
    InnerProduct_Witness_free(ip_witness); 
    InnerProduct_Instance_free(ip_instance); 
}

bool Bullet_Verify(Bullet_PP &pp, Bullet_Instance &instance, string &transcript_str, Bullet_Proof &proof)
{
    #ifdef DEBUG
        cout << "begin to check the proof" << endl; 
    #endif

    for (auto i = 0; i < instance.C.size(); i++){
        transcript_str += ECP_ep2string(instance.C[i]); 
    }

    bool V1, V2, Validity; // variables for checking results

    transcript_str += ECP_ep2string(proof.A); 
    BIGNUM* y = BN_new(); 
    Hash_String_to_BN(transcript_str, y);   
    BIGNUM* y_inverse = BN_new(); 
    BN_mod_inverse(y_inverse, y, order, bn_ctx); //recover the challenge y
    
    transcript_str += ECP_ep2string(proof.S); 
    BIGNUM* z = BN_new(); 
    BIGNUM* z_minus = BN_new(); 
    BIGNUM* z_square = BN_new(); 
    BIGNUM* z_cubic = BN_new(); 

    Hash_String_to_BN(transcript_str, z); 
    BN_mod_sub(z_minus, BN_0, z, order, bn_ctx); 
    BN_mod_sqr(z_square, z, order, bn_ctx); // (z*z)%q; 
    BN_mod_mul(z_cubic, z, z_square, order, bn_ctx); //recover the challenge z from PI

    transcript_str += ECP_ep2string(proof.T1) + ECP_ep2string(proof.T2); 
    BIGNUM *x = BN_new(); 
    Hash_String_to_BN(transcript_str, x); 
    BIGNUM *x_square = BN_new(); 
    BN_mod_sqr(x_square, x, order, bn_ctx); // (x*x)%q;  //recover the challenge x from PI

    transcript_str += BN_bn2string(x); 
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e);  

    size_t l = pp.RANGE_LEN * pp.AGG_NUM; 

    vector<BIGNUM *> vec_1_power(l); // vec_unary = 1^nm
    BN_vec_new(vec_1_power); 
    BN_vec_one(vec_1_power); 
    
    vector<BIGNUM *> vec_short_1_power(pp.RANGE_LEN);
    BN_vec_new(vec_short_1_power); 
    BN_vec_gen_power(vec_short_1_power, BN_1); 

    vector<BIGNUM *> vec_2_power(l); 
    BN_vec_new(vec_2_power); 
    BN_vec_gen_power(vec_2_power, BN_2);

    vector<BIGNUM *> vec_short_2_power(pp.RANGE_LEN);
    BN_vec_new(vec_short_2_power); 
    BN_vec_gen_power(vec_short_2_power, BN_2);  

    vector<BIGNUM *> vec_y_power(l); 
    BN_vec_new(vec_y_power); 
    BN_vec_gen_power(vec_y_power, y); 

    vector<BIGNUM *> vec_adjust_z_power(pp.AGG_NUM+1); // generate z^{j+2} j \in [n]
    BN_vec_new(vec_adjust_z_power); 
    BN_copy(vec_adjust_z_power[0], z); 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BN_mod_mul(vec_adjust_z_power[j], z, vec_adjust_z_power[j-1], order, bn_ctx); 
    }  

    // compute sum_{j=1^m} z^{j+2}
    BIGNUM* sum_z = BN_new(); 
    BN_zero(sum_z); 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BN_add(sum_z, sum_z, vec_adjust_z_power[j]); 
    }
    BN_mul(sum_z, sum_z, z, bn_ctx); 
    BN_mod(sum_z, sum_z, order, bn_ctx); 

    // compute delta_yz (pp. 21)
    BIGNUM* delta_yz = BN_new(); 

    BIGNUM* bn_temp0 = BN_new(); 
    BIGNUM* bn_temp1 = BN_new(); 
    BIGNUM* bn_temp2 = BN_new(); 
    BN_vec_inner_product(bn_temp1, vec_1_power, vec_y_power); 
    BN_vec_inner_product(bn_temp2, vec_short_1_power, vec_short_2_power); 

    BIGNUM* bn_c0 = BN_new(); 
    BN_mod_sub(bn_c0, z, z_square, order, bn_ctx);
    BN_mul(bn_temp1, bn_c0, bn_temp1, bn_ctx); 
    BN_mul(bn_temp2, sum_z, bn_temp2, bn_ctx); 
  
    BN_mod_sub(delta_yz, bn_temp1, bn_temp2, order, bn_ctx);  //Eq (39)

    EC_POINT* LEFT = EC_POINT_new(group); 
    EC_POINT* RIGHT = EC_POINT_new(group); 
    // check Eq (72)  
    EC_POINT_mul(group, LEFT, proof.taux, pp.h, proof.tx, bn_ctx);  // LEFT = g^{\taux} h^\hat{t}

    // the intermediate variables used to compute the right value
    vector<EC_POINT*> vec_A; 
    vector<BIGNUM*> vec_a;
    vec_A.resize(pp.AGG_NUM + 3); 
    vec_a.resize(pp.AGG_NUM + 3);

    copy(instance.C.begin(), instance.C.end(), vec_A.begin()); 
    copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), vec_a.begin()); 

    vec_A[pp.AGG_NUM] = pp.h, vec_A[pp.AGG_NUM+1] = proof.T1, vec_A[pp.AGG_NUM+2] = proof.T2;
    vec_a[pp.AGG_NUM] = delta_yz, vec_a[pp.AGG_NUM+1] = x, vec_a[pp.AGG_NUM+2] = x_square;  

    ECP_vec_mul(RIGHT, vec_A, vec_a);  // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2} 

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << endl; 
    #endif

    vector<BIGNUM *> vec_y_inverse_power(l); 
    BN_vec_new(vec_y_inverse_power); 
    BN_vec_gen_power(vec_y_inverse_power, y_inverse); // y^nm
    vector<EC_POINT *> vec_h_new(l); 
    ECP_vec_new(vec_h_new); 
    ECP_vec_product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    //check Eq (66,67,68) using Inner Product Argument
    InnerProduct_PP ip_pp; 
    InnerProduct_PP_new(ip_pp, l); 
    InnerProduct_Setup(ip_pp, l, false); 
    ECP_vec_copy(ip_pp.vec_g, pp.vec_g);
    ECP_vec_copy(ip_pp.vec_h, vec_h_new);  

    //InnerProduct_Proof ip_proof = proof.ip_proof;
    InnerProduct_Instance ip_instance;
    InnerProduct_Instance_new(ip_instance); 
    EC_POINT_copy(ip_instance.u, pp.u); 
    EC_POINT_mul(group, ip_instance.u, NULL, ip_instance.u, e, bn_ctx); // u = u^e 
    
    vec_A.clear(); vec_a.clear(); 
    vec_A.emplace_back(proof.A); vec_A.emplace_back(proof.S); 
    vec_a.emplace_back(BN_1); vec_a.emplace_back(x); // LEFT = A+S^x

    vector<BIGNUM *> vec_z_minus_unary(l); 
    BN_vec_new(vec_z_minus_unary); 
    BN_vec_scalar(vec_z_minus_unary, vec_1_power, z_minus); 

    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_a.insert(vec_a.end(), vec_z_minus_unary.begin(), vec_z_minus_unary.end()); // LEFT += g^{-1 z^n} 
      
    vector<BIGNUM *> vec_rr(l); 
    BN_vec_new(vec_rr); 
    BN_vec_scalar(vec_rr, vec_y_power, z); // z y^nm

    vector<BIGNUM*> temp_vec_zz(l);
    BN_vec_new(temp_vec_zz); 
    for(auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BN_vec_scalar(temp_vec_zz, vec_2_power, vec_adjust_z_power[j]); 
        for(auto i = 0; i < pp.RANGE_LEN; i++)
        {
            BN_mod_add(vec_rr[(j-1)*pp.RANGE_LEN+i], vec_rr[(j-1)*pp.RANGE_LEN+i], temp_vec_zz[i], order, bn_ctx);            
        }
    }

    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 
    vec_a.insert(vec_a.end(), vec_rr.begin(), vec_rr.end()); 

    BN_mod_negative(proof.mu); 
    vec_A.emplace_back(pp.h); vec_A.emplace_back(ip_instance.u); 
    vec_a.emplace_back(proof.mu); vec_a.emplace_back(proof.tx); 
    ECP_vec_mul(ip_instance.P, vec_A, vec_a);  // set P_new = P h^{-u} U^<l, r>   

    transcript_str += ECP_ep2string(ip_instance.P) + ECP_ep2string(ip_instance.u); 
    V2 = InnerProduct_Verify(ip_pp, ip_instance, transcript_str, proof.ip_proof); 
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

    // free temporary variables
    BN_vec_free(vec_1_power), BN_vec_free(vec_short_1_power);
    BN_vec_free(vec_2_power), BN_vec_free(vec_short_2_power); 

    BN_free(x), BN_free(x_square); 
    BN_free(y), BN_free(y_inverse);  
    BN_vec_free(vec_y_power), BN_vec_free(vec_y_inverse_power); 
    BN_free(z), BN_free(z_minus), BN_free(z_square), BN_free(z_cubic); 
    BN_vec_free(vec_adjust_z_power), BN_vec_free(vec_z_minus_unary); 
    BN_free(e); 
    BN_free(sum_z); 
    BN_free(delta_yz); 

    ECP_vec_free(vec_h_new); 

    BN_free(bn_c0), BN_free(bn_temp0), BN_free(bn_temp1), BN_free(bn_temp2); 

    BN_vec_free(vec_rr); 
    BN_vec_free(temp_vec_zz); 

    InnerProduct_PP_free(ip_pp); 
    InnerProduct_Instance_free(ip_instance); 

    return Validity; 
}

#endif
