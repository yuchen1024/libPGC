#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "aggregate_bulletproof.hpp"


void generate_random_instance_witness(Bullet_PP& pp, 
                                      Bullet_Instance& instance, 
                                      Bullet_Witness& witness, 
                                      bool flag)
{
    if(flag == true) cout << "generate a true statement pair" << endl; 
    else cout << "generate a random statement (false with overwhelming probability)" << endl; 
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    BIGNUM *range_size = BN_new(); 
    BN_mod_exp(range_size, bn_2, exp, order, bn_ctx); 
    cout << "range = [" << 0 << "," << BN_bn2hex(range_size) <<")"<<endl; 
    for(int i = 0; i < pp.m; i++)
    {
        random_zz(witness.r[i]);
        random_zz(witness.v[i]); 
        if (flag == true){
            BN_mod(witness.v[i], witness.v[i], range_size, bn_ctx);  
        }
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
        //cout << "v["<<i<<"]= " << BN_bn2hex(witness.v[i]) << endl; 
    }
}


void test_bulletproof(int n, int m, bool flag)
{
    Bullet_PP pp;  
    Bullet_Setup(pp, n, m);

    Bullet_Instance instance; 
    Bullet_Witness witness; 
    Bullet_Proof proof; 

    Bullet_Instance_Init(instance, m); 
    Bullet_Witness_Init(witness, m); 
    Bullet_Proof_Init(proof); 

    generate_random_instance_witness(pp, instance, witness, flag); 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    Bullet_Prove(pp, instance, witness, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    Bullet_Verify(pp, instance, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    Bullet_PP_Free(pp); 
    Bullet_Instance_Free(instance); 
    Bullet_Witness_Free(witness); 
    Bullet_Proof_Free(proof); 
}


int main()
{ 
    global_initialize(NID_X9_62_prime256v1);   
    int n = 32; // range size
    int m = 2;  // number of sub-argument
    test_bulletproof(n, m, true);
    Print_Splitline('*'); 
    test_bulletproof(n, m, false);  
    global_finalize();
    
    return 0;
}