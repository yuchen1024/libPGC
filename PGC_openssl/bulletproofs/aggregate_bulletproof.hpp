/***********************************************************************************
this hpp implements aggregated logarithmic size Bulletproofs  
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#include "innerproduct_proof.hpp" 

// define the structure of Bulletproofs
struct Bullet_PP
{
    uint64_t RANGE_LEN; 
    uint64_t LOG_RANGE_LEN; 
    uint64_t m; // number of sub-argument (for now, we require m to be the power of 2)

    EC_POINT *g, *h;
    EC_POINT *u; // used for inside innerproduct statement
    vector<EC_POINT *> vec_g; 
    vector<EC_POINT *> vec_h; // the pp of innerproduct part    
};

struct Bullet_Instance
{
    vector<EC_POINT*> C;  // Ci = g^ri h^vi
}; 

struct Bullet_Witness
{
    vector<BIGNUM*> r; 
    vector<BIGNUM*> v; 
}; 

struct Bullet_Proof
{
    EC_POINT *A, *S, *T1, *T2;  
    BIGNUM *taux, *mu, *tx; 
    InnerProduct_Proof ip_proof;    
};

void Print_Bullet_Proof(Bullet_Proof proof)
{
    print_gg(proof.A, "proof.A"); 
    print_gg(proof.S, "proof.S"); 
    print_gg(proof.T1, "proof.T1");  
    print_gg(proof.T2, "proof.T2");  

    print_zz(proof.taux, "proof.taux"); 
    print_zz(proof.mu, "proof.mu"); 
    print_zz(proof.tx, "proof.tx"); 

    Print_InnerProduct_Proof(proof.ip_proof); 
}

void Serialize_Bullet_Proof(Bullet_Proof &proof, ofstream &fout)
{
    Serialize_GG(proof.A, fout); 
    Serialize_GG(proof.S, fout);
    Serialize_GG(proof.T1, fout);
    Serialize_GG(proof.T2, fout);

    Serialize_ZZ(proof.taux, fout); 
    Serialize_ZZ(proof.mu, fout); 
    Serialize_ZZ(proof.tx, fout); 

    Serialize_InnerProduct_Proof(proof.ip_proof, fout); 
}

void Deserialize_Bullet_Proof(Bullet_Proof &proof, ifstream &fin)
{
    Deserialize_GG(proof.A, fin); 
    Deserialize_GG(proof.S, fin);
    Deserialize_GG(proof.T1, fin);
    Deserialize_GG(proof.T2, fin);

    Deserialize_ZZ(proof.taux, fin); 
    Deserialize_ZZ(proof.mu, fin); 
    Deserialize_ZZ(proof.tx, fin); 

    Deserialize_InnerProduct_Proof(proof.ip_proof, fin); 
}

void Bullet_PP_Init(Bullet_PP &pp, uint64_t n, uint64_t m)
{
    uint64_t l = n*m;
    pp.h = EC_POINT_new(group);
    pp.u = EC_POINT_new(group); 
    pp.vec_g.resize(l); 
    pp.vec_h.resize(l); 
    vec_gg_init(pp.vec_g); 
    vec_gg_init(pp.vec_h); 
}

void Bullet_Proof_Init(Bullet_Proof &proof)
{
    proof.A = EC_POINT_new(group); 
    proof.S = EC_POINT_new(group); 
    proof.T1 = EC_POINT_new(group); 
    proof.T2 = EC_POINT_new(group); 
    proof.taux = BN_new();   
    proof.mu = BN_new(); 
    proof.tx = BN_new();
    InnerProduct_Proof_Init(proof.ip_proof);
}

void Bullet_Witness_Init(Bullet_Witness &witness, uint64_t m)
{
    witness.r.resize(m); 
    vec_zz_init(witness.r); 
    witness.v.resize(m); 
    vec_zz_init(witness.v); 
}; 

void Bullet_Instance_Init(Bullet_Instance &instance, uint64_t m)
{
    instance.C.resize(m); 
    vec_gg_init(instance.C); 
}

void Bullet_PP_Free(Bullet_PP &pp)
{
    EC_POINT_free(pp.h);
    EC_POINT_free(pp.u); 
    vec_gg_free(pp.vec_g); 
    vec_gg_free(pp.vec_h); 
}

void Bullet_Proof_Free(Bullet_Proof &proof)
{
    EC_POINT_free(proof.A); 
    EC_POINT_free(proof.S); 
    EC_POINT_free(proof.T1); 
    EC_POINT_free(proof.T2); 
    BN_free(proof.taux);   
    BN_free(proof.mu); 
    BN_free(proof.tx);
    InnerProduct_Proof_Free(proof.ip_proof);
}

void Bullet_Witness_Free(Bullet_Witness &witness)
{
    vec_zz_free(witness.r);  
    vec_zz_free(witness.v); 
}; 

void Bullet_Instance_Free(Bullet_Instance &instance)
{
    vec_gg_free(instance.C); 
}

void Bullet_Setup(Bullet_PP &pp, uint64_t n, uint64_t m)
{
    pp.RANGE_LEN = n; 
    pp.m = m;  
    Bullet_PP_Init(pp, n, m); 
    pp.g = (EC_POINT*)EC_GROUP_get0_generator(group); 
    random_gg(pp.h); 
    random_gg(pp.u); 
    random_vec_gg(pp.vec_g); 
    random_vec_gg(pp.vec_h);  
}

// statement C = g^r h^v and v \in [0, 2^n-1]
void Bullet_Prove(Bullet_PP &pp, Bullet_Instance &instance, Bullet_Witness &witness, Bullet_Proof &proof)
{
    string transcript_str = ""; 
    for (size_t i = 0; i < instance.C.size(); i++){
        transcript_str += EC_POINT_ep2string(instance.C[i]); 
    }

    BIGNUM *temp_bn; 
    uint64_t l = pp.RANGE_LEN * pp.m; // l = mn

    vector<BIGNUM *> vec_aL(l); 
    vec_zz_init(vec_aL); 
    vector<BIGNUM *> vec_aR(l);
    vec_zz_init(vec_aR); 
    vector<BIGNUM *> vec_1_power(l); // vec_unary = 1^nm
    vec_zz_init(vec_1_power);
    for(size_t i = 0; i < l; i++) BN_one(vec_1_power[i]); 
   
    for (size_t i = 0; i < pp.m; i++)
    {
        for(size_t j = 0; j < pp.RANGE_LEN; j++)
        {
            if(big_parse_binary(witness.v[i], j) == 1){
                BN_one(vec_aL[i*pp.RANGE_LEN + j]);  
            }
            else{
                BN_zero(vec_aL[i*pp.RANGE_LEN + j]); 
            } 
        }
    }
    vec_zz_sub(vec_aR, vec_aL, vec_1_power); // Eq (42) -- aR = aL - 1^n

    // prepare vec_A and vec_a for multi-exponention (used hereafter)
    vector<EC_POINT*> vec_A; 
    vector<BIGNUM*> vec_a; 

    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    BIGNUM *alpha = BN_new(); 
    random_zz(alpha); 

    vec_A.emplace_back(pp.h); 
    vec_A.insert(vec_A.end(), pp.vec_g.begin(), pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end()); 
    
    vec_a.emplace_back(alpha); 
    vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
    vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 

    vec_gg_mul(proof.A, vec_A, vec_a); // Eq (44) 

    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    vector<BIGNUM *> vec_sL(l);
    vec_zz_init(vec_sL); 
    random_vec_zz(vec_sL); 

    vector<BIGNUM *> vec_sR(l);
    vec_zz_init(vec_sR); 
    random_vec_zz(vec_sR); 
    
    // Eq (47) compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    BIGNUM *rho = BN_new(); 
    random_zz(rho); 

    vec_a.clear(); 
    vec_a.emplace_back(rho); 
    vec_a.insert(vec_a.end(), vec_sL.begin(), vec_sL.end()); 
    vec_a.insert(vec_a.end(), vec_sR.begin(), vec_sR.end()); 

    vec_gg_mul(proof.S, vec_A, vec_a); // Eq (47) 

    // Eq (49, 50) compute y and z
    transcript_str += EC_POINT_ep2string(proof.A); 
    BIGNUM *y = BN_new(); 
    Hash_String_ZZ(y, transcript_str);

    BIGNUM* y_inverse = BN_new();
    BN_mod_inverse(y_inverse, y, order, bn_ctx); 

    vector<BIGNUM *> vec_y_inverse_power(l); 
    vec_zz_init(vec_y_inverse_power); 
    gen_vec_zz_power(vec_y_inverse_power, y_inverse); // y^{-i+1}

    transcript_str += EC_POINT_ep2string(proof.S); 
    BIGNUM *z = BN_new(); 
    Hash_String_ZZ(z, transcript_str);

    BIGNUM *z_square = BN_new(); 
    BN_mod_sqr(z_square, z, order, bn_ctx);
    BIGNUM *z_cubic = BN_new(); 
    BN_mod_mul(z_cubic, z, z_square, order, bn_ctx);
    
    vector<BIGNUM *> vec_adjust_z_power(pp.m+1); // generate z^{j+1} j \in [n]
    vec_zz_init(vec_adjust_z_power); 
    BN_copy(vec_adjust_z_power[0], z); 
    for (size_t j = 1; j <= pp.m; j++)
    {
        BN_mod_mul(vec_adjust_z_power[j], z, vec_adjust_z_power[j-1], order, bn_ctx); 
        //vec_adjust_z_power[j] = pow(z, j+1, q); description below Eq (71)
    }  

    // prepare the vector polynomials
    
    // compute l(X) Eq (70)
    vector<BIGNUM *> vec_z_unary(l); 
    vec_zz_init(vec_z_unary); 
    vec_zz_scalar(vec_z_unary, vec_1_power, z); // z \cdot 1^nm

    vector<BIGNUM *> poly_ll0(l);
    vec_zz_init(poly_ll0); 
    vector<BIGNUM *> poly_ll1(l);
    vec_zz_init(poly_ll1); 
    vec_zz_sub(poly_ll0, vec_aL, vec_z_unary);  
    vec_zz_copy(poly_ll1, vec_sL); 

 
    // compute r(X)     
    vector<BIGNUM *> poly_rr0(l); 
    vec_zz_init(poly_rr0); 

    vector<BIGNUM *> vec_y_power(l); 
    vec_zz_init(vec_y_power); 
    gen_vec_zz_power(vec_y_power, y); // y^nm

    vector<BIGNUM *> vec_zz_temp(l); 
    vec_zz_init(vec_zz_temp); 
    vec_zz_add(vec_zz_temp, vec_z_unary, vec_aR); // vec_t = aR + z1^nm
    vec_zz_product(poly_rr0, vec_y_power, vec_zz_temp); // y^nm(aR + z1^nm)
    
    vector<BIGNUM *> vec_short_2_power(pp.RANGE_LEN); 
    vec_zz_init(vec_short_2_power); 
    gen_vec_zz_power(vec_short_2_power, bn_2); // 2^n

    for (int j = 1; j <= pp.m; j++)
    {
        for (int i = 0; i < (j-1)*pp.RANGE_LEN; i++) 
            BN_zero(vec_zz_temp[i]); 
        for (int i = 0; i < pp.RANGE_LEN; i++) 
            BN_copy(vec_zz_temp[(j-1)*pp.RANGE_LEN+i], vec_short_2_power[i]); 
        for (int i = 0; i < (pp.m-j)*pp.RANGE_LEN; i++) 
            BN_zero(vec_zz_temp[j*pp.RANGE_LEN+i]);

        vec_zz_scalar(vec_zz_temp, vec_zz_temp, vec_adjust_z_power[j]); 
        //print_zz(vec_adjust_z_power[j], "adjust_vec_z"); 
        vec_zz_add(poly_rr0, poly_rr0, vec_zz_temp);  
    }
    vector<BIGNUM *> poly_rr1(l); 
    vec_zz_init(poly_rr1); 
    vec_zz_product(poly_rr1, vec_y_power, vec_sR); //y^nsR X

    // compute t(X) 
    BIGNUM* bn_temp  = BN_new(); 
    BIGNUM* bn_temp1 = BN_new(); 
    BIGNUM* bn_temp2 = BN_new(); 
    
    BIGNUM* t0 = BN_new(); 
    BIGNUM* t1 = BN_new(); 
    BIGNUM* t2 = BN_new(); 
    
    inner_product(t0, poly_ll0, poly_rr0); 
    inner_product(bn_temp1, poly_ll1, poly_rr0); 
    inner_product(bn_temp2, poly_ll0, poly_rr1);
    BN_mod_add(t1, bn_temp1, bn_temp2, order, bn_ctx);  
  
    inner_product(t2, poly_ll1, poly_rr1); 

    // Eq (53) -- commit to t1, t2
    // P picks tau1 and tau2
    BIGNUM* tau1 = BN_new(); 
    random_zz(tau1); 
    BIGNUM* tau2 = BN_new(); 
    random_zz(tau2);

    EC_POINT_mul(group, proof.T1, tau1, pp.h, t1, bn_ctx); // mul(tau1, pp.g, t1, pp.h);
    EC_POINT_mul(group, proof.T2, tau2, pp.h, t2, bn_ctx); // mul(tau2, pp.g, t2, pp.h);    

    // Eq (56) -- compute the challenge x
    transcript_str += EC_POINT_ep2string(proof.T1) + EC_POINT_ep2string(proof.T2); 
    BIGNUM* x = BN_new(); 
    Hash_String_ZZ(x, transcript_str); 

    BIGNUM* x_square = BN_new(); 
    BN_mod_sqr(x_square, x, order, bn_ctx);  

    // compute the value of l(x) and r(x) at point x
    vector<BIGNUM *> llx(l); 
    vec_zz_init(llx);
    vec_zz_scalar(vec_zz_temp, poly_ll1, x);
    vec_zz_add(llx, poly_ll0, vec_zz_temp);

    vector<BIGNUM *> rrx(l); 
    vec_zz_init(rrx);
    vec_zz_scalar(vec_zz_temp, poly_rr1, x); 
    vec_zz_add(rrx, poly_rr0, vec_zz_temp); 

    inner_product(proof.tx, llx, rrx);  // Eq (60)  
 
    // compute taux
    BN_mul(bn_temp1, tau1, x, bn_ctx);
    BN_mul(bn_temp2, tau2, x_square, bn_ctx);
    BN_mod_add(proof.taux, bn_temp1, bn_temp2, order, bn_ctx); //proof.taux = tau2*x_square + tau1*x; 
    for (size_t j = 1; j <= pp.m; j++)
    {
        BN_mul(bn_temp, vec_adjust_z_power[j], witness.r[j-1], bn_ctx); 
        BN_mod_add(proof.taux, proof.taux, bn_temp, order, bn_ctx); 
    }

    // compute proof.mu = (alpha + rho*x) %q;  Eq (62)
    BN_mul(proof.mu, rho, x, bn_ctx); 
    BN_mod_add(proof.mu, proof.mu, alpha, order, bn_ctx); 
    
    // transmit llx and rrx via inner product proof
    vector<EC_POINT *> vec_h_new(l); 
    vec_gg_init(vec_h_new); 
    vec_gg_product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    InnerProduct_PP ip_pp; 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN * pp.m; 
    ip_pp.LOG_VECTOR_LEN = log2(ip_pp.VECTOR_LEN);
    InnerProduct_PP_Init(ip_pp, ip_pp.VECTOR_LEN); 
    vec_gg_copy(ip_pp.vec_g, pp.vec_g); // ip_pp.vec_g = pp.vec_g
    vec_gg_copy(ip_pp.vec_h, vec_h_new);  // ip_pp.vec_h = vec_h_new 
 
    transcript_str += BN_bn2string(x); 
    BIGNUM* e = BN_new(); 
    Hash_String_ZZ(e, transcript_str);   

    InnerProduct_Witness ip_witness;
    InnerProduct_Witness_Init(ip_witness, l); 
    vec_zz_copy(ip_witness.vec_a, llx); // ip_witness.vec_a = llx
    vec_zz_copy(ip_witness.vec_b, rrx); // ip_witness.vec_b = rrx

    InnerProduct_Instance ip_instance;
    InnerProduct_Instance_Init(ip_instance);
    EC_POINT_copy(ip_instance.u, pp.u); // ip_instance.u = pp.u
    EC_POINT_mul(group, ip_instance.u, NULL, ip_instance.u, e, bn_ctx); //ip_instance.u = u^e 

    vec_A.clear(); vec_a.clear();

    vec_A.emplace_back(ip_instance.u); 
    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 

    vec_a.emplace_back(proof.tx); 
    vec_a.insert(vec_a.end(), ip_witness.vec_a.begin(), ip_witness.vec_a.end()); 
    vec_a.insert(vec_a.end(), ip_witness.vec_b.begin(), ip_witness.vec_b.end()); 

    vec_gg_mul(ip_instance.P, vec_A, vec_a);  

    transcript_str += EC_POINT_ep2string(ip_instance.P) + EC_POINT_ep2string(ip_instance.u);  
 
    InnerProduct_Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        cout << "Bullet Proof Generation Succeeds >>>" << endl; 
    #endif

    vec_zz_free(vec_aL), vec_zz_free(vec_aR); 
    vec_zz_free(vec_1_power);
    BN_free(alpha), BN_free(rho);
    vec_zz_free(vec_sL), vec_zz_free(vec_sR);
    BN_free(x); 
    BN_free(y), BN_free(y_inverse);  
    vec_zz_free(vec_y_power), vec_zz_free(vec_y_inverse_power); 
    BN_free(z), BN_free(z_square), BN_free(z_cubic); 
    vec_zz_free(vec_adjust_z_power); 
    vec_zz_free(vec_z_unary); 
    BN_free(e); 

    vec_zz_free(poly_ll0), vec_zz_free(poly_ll1);  
    vec_zz_free(poly_rr0), vec_zz_free(poly_rr1);  

    BN_free(tau1), BN_free(tau2); 
    vec_zz_free(llx), vec_zz_free(rrx);  

    vec_gg_free(vec_h_new); 

    BN_free(bn_temp), BN_free(bn_temp1), BN_free(bn_temp2); 
    BN_free(t0), BN_free(t1), BN_free(t2);  

    InnerProduct_PP_Free(ip_pp); 
    InnerProduct_Witness_Free(ip_witness); 
    InnerProduct_Instance_Free(ip_instance); 
}

bool Bullet_Verify(Bullet_PP &pp, Bullet_Instance &instance, Bullet_Proof &proof)
{
    #ifdef DEBUG
        cout << "begin to check the proof" << endl; 
    #endif

    string transcript_str = ""; 
    for (size_t i = 0; i < instance.C.size(); i++){
        transcript_str += EC_POINT_ep2string(instance.C[i]); 
    }

    bool V1, V2, Validity; // variables for checking results

    transcript_str += EC_POINT_ep2string(proof.A); 
    BIGNUM* y = BN_new(); 
    Hash_String_ZZ(y, transcript_str);   
    BIGNUM* y_inverse = BN_new(); 
    BN_mod_inverse(y_inverse, y, order, bn_ctx); //recover the challenge y
    
    transcript_str += EC_POINT_ep2string(proof.S); 
    BIGNUM* z = BN_new(); 
    BIGNUM* z_minus = BN_new(); 
    BIGNUM* z_square = BN_new(); 
    BIGNUM* z_cubic = BN_new(); 

    Hash_String_ZZ(z, transcript_str); 
    BN_mod_sub(z_minus, bn_0, z, order, bn_ctx); 
    BN_mod_sqr(z_square, z, order, bn_ctx); // (z*z)%q; 
    BN_mod_mul(z_cubic, z, z_square, order, bn_ctx); //recover the challenge z from PI

    transcript_str += EC_POINT_ep2string(proof.T1) + EC_POINT_ep2string(proof.T2); 
    BIGNUM* x = BN_new(); 
    Hash_String_ZZ(x, transcript_str); 
    BIGNUM* x_square = BN_new(); 
    BN_mod_sqr(x_square, x, order, bn_ctx); // (x*x)%q;  //recover the challenge x from PI

    transcript_str += BN_bn2string(x); 
    BIGNUM* e = BN_new(); 
    Hash_String_ZZ(e, transcript_str);  

    uint64_t l = pp.RANGE_LEN * pp.m; 

    vector<BIGNUM*> vec_1_power(l); // vec_unary = 1^nm
    vec_zz_init(vec_1_power); 
    vec_zz_one(vec_1_power); 
    
    vector<BIGNUM*> vec_short_1_power(pp.RANGE_LEN);
    vec_zz_init(vec_short_1_power); 
    vec_zz_one(vec_short_1_power); 

    vector<BIGNUM*> vec_2_power(l); 
    vec_zz_init(vec_2_power); 
    gen_vec_zz_power(vec_2_power, bn_2);

    vector<BIGNUM*> vec_short_2_power(pp.RANGE_LEN);
    vec_zz_init(vec_short_2_power); 
    gen_vec_zz_power(vec_short_2_power, bn_2);  

    vector<BIGNUM*> vec_y_power(l); 
    vec_zz_init(vec_y_power); 
    gen_vec_zz_power(vec_y_power, y); 

    vector<BIGNUM*> vec_adjust_z_power(pp.m+1); // generate z^{j+2} j \in [n]
    vec_zz_init(vec_adjust_z_power); 
    BN_copy(vec_adjust_z_power[0], z); 
    for (size_t j = 1; j <= pp.m; j++)
    {
        BN_mod_mul(vec_adjust_z_power[j], z, vec_adjust_z_power[j-1], order, bn_ctx); 
    }  

    // compute sum_{j=1^m} z^{j+2}
    BIGNUM* sum_z = BN_new(); 
    BN_zero(sum_z); 
    for (size_t j = 1; j <= pp.m; j++)
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
    inner_product(bn_temp1, vec_1_power, vec_y_power); 
    inner_product(bn_temp2, vec_short_1_power, vec_short_2_power); 

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
    vec_A.resize(pp.m + 3); 
    vec_a.resize(pp.m + 3);

    copy(instance.C.begin(), instance.C.end(), vec_A.begin()); 
    copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), vec_a.begin()); 

    vec_A[pp.m] = pp.h, vec_A[pp.m+1] = proof.T1, vec_A[pp.m+2] = proof.T2;
    vec_a[pp.m] = delta_yz, vec_a[pp.m+1] = x, vec_a[pp.m+2] = x_square;  

    vec_gg_mul(RIGHT, vec_A, vec_a);  // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2} 

    V1 = (EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0); 
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << endl; 
    #endif

    vector<BIGNUM*> vec_y_inverse_power(l); 
    vec_zz_init(vec_y_inverse_power); 
    gen_vec_zz_power(vec_y_inverse_power, y_inverse); // y^nm
    vector<EC_POINT*> vec_h_new(l); 
    vec_gg_init(vec_h_new); 
    vec_gg_product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    //check Eq (66,67,68) using Inner Product Argument
    InnerProduct_PP ip_pp; 
    InnerProduct_PP_Init(ip_pp, l); 
    ip_pp.VECTOR_LEN = pp.RANGE_LEN * pp.m; 
    ip_pp.LOG_VECTOR_LEN = log2(ip_pp.VECTOR_LEN);
    vec_gg_copy(ip_pp.vec_g, pp.vec_g);
    vec_gg_copy(ip_pp.vec_h, vec_h_new);  

    //InnerProduct_Proof ip_proof = proof.ip_proof;
    InnerProduct_Instance ip_instance;
    InnerProduct_Instance_Init(ip_instance); 
    EC_POINT_copy(ip_instance.u, pp.u); 
    EC_POINT_mul(group, ip_instance.u, NULL, ip_instance.u, e, bn_ctx); // u = u^e 
    
    vec_A.clear(); vec_a.clear(); 
    vec_A.emplace_back(proof.A); vec_A.emplace_back(proof.S); 
    vec_a.emplace_back(bn_1); vec_a.emplace_back(x); // LEFT = A+S^x

    vector<BIGNUM*> vec_z_minus_unary(l); 
    vec_zz_init(vec_z_minus_unary); 
    vec_zz_scalar(vec_z_minus_unary, vec_1_power, z_minus); 


    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_a.insert(vec_a.end(), vec_z_minus_unary.begin(), vec_z_minus_unary.end()); // LEFT += g^{-1 z^n} 
      
    vector<BIGNUM*> vec_rr(l); 
    vec_zz_init(vec_rr); 
    vec_zz_scalar(vec_rr, vec_y_power, z); // z y^nm

    vector<BIGNUM*> temp_vec_zz(l);
    vec_zz_init(temp_vec_zz); 
    for(int j = 1; j <= pp.m; j++)
    {
        vec_zz_scalar(temp_vec_zz, vec_2_power, vec_adjust_z_power[j]); 
        for(int i = 0; i < pp.RANGE_LEN; i++)
        {
            BN_mod_add(vec_rr[(j-1)*pp.RANGE_LEN+i], vec_rr[(j-1)*pp.RANGE_LEN+i], temp_vec_zz[i], order, bn_ctx);            
        }
    }

    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 
    vec_a.insert(vec_a.end(), vec_rr.begin(), vec_rr.end()); 

    BN_mod_negative(proof.mu); 
    vec_A.emplace_back(pp.h); vec_A.emplace_back(ip_instance.u); 
    vec_a.emplace_back(proof.mu); vec_a.emplace_back(proof.tx); 
    vec_gg_mul(ip_instance.P, vec_A, vec_a);  // set P_new = P h^{-u} U^<l, r>   

    transcript_str += EC_POINT_ep2string(ip_instance.P) + EC_POINT_ep2string(ip_instance.u); 
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
    vec_zz_free(vec_1_power), vec_zz_free(vec_short_1_power);
    vec_zz_free(vec_2_power), vec_zz_free(vec_short_2_power); 

    BN_free(x), BN_free(x_square); 
    BN_free(y), BN_free(y_inverse);  
    vec_zz_free(vec_y_power), vec_zz_free(vec_y_inverse_power); 
    BN_free(z), BN_free(z_minus), BN_free(z_square), BN_free(z_cubic); 
    vec_zz_free(vec_adjust_z_power), vec_zz_free(vec_z_minus_unary); 
    BN_free(e); 
    BN_free(sum_z); 
    BN_free(delta_yz); 

    vec_gg_free(vec_h_new); 

    BN_free(bn_c0), BN_free(bn_temp0), BN_free(bn_temp1), BN_free(bn_temp2); 

    vec_zz_free(vec_rr); 
    vec_zz_free(temp_vec_zz); 

    InnerProduct_PP_Free(ip_pp); 
    InnerProduct_Instance_Free(ip_instance); 

    return Validity; 
}
