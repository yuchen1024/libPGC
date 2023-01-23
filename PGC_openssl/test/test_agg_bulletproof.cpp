#define DEBUG

#include "../depends/bulletproofs/aggregate_bulletproof.hpp"


void generate_random_instance_witness(Bullet_PP &pp, 
                                      Bullet_Instance &instance, 
                                      Bullet_Witness &witness, 
                                      bool STATEMENT_FLAG)
{
    if(STATEMENT_FLAG == true) cout << "generate a true statement pair" << endl; 
    else cout << "generate a random statement (false with overwhelming probability)" << endl; 
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    BIGNUM *BN_range_size = BN_new(); 
    BN_mod_exp(BN_range_size, BN_2, exp, order, bn_ctx); 
    cout << "range = [" << 0 << "," << BN_bn2hex(BN_range_size) <<")"<<endl; 
    for(auto i = 0; i < pp.AGG_NUM; i++)
    {
        BN_random(witness.r[i]);
        BN_random(witness.v[i]); 
        if (STATEMENT_FLAG == true){
            BN_mod(witness.v[i], witness.v[i], BN_range_size, bn_ctx);  
        }
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
    }
    cout << "random instance generation finished" << endl; 
}

void generate_boundary_instance_witness(Bullet_PP &pp, 
                                        Bullet_Instance &instance, 
                                        Bullet_Witness &witness, 
                                        string BOUNDARY_FLAG)
{  
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    for(auto i = 0; i < pp.AGG_NUM; i++)
    {
        BN_random(witness.r[i]);
        if (BOUNDARY_FLAG == "LEFT")
        {
            cout << "generate left boundary" << endl;
            BN_zero(witness.v[i]);
        }
        else{
            cout << "generate right boundary" << endl;
            BN_mod_exp(witness.v[i], BN_2, exp, order, bn_ctx);
        } 
        BN_print_dec(witness.v[i], "witness.v"); 
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
    }
}

void test_bulletproof_boundary(size_t RANGE_LEN, size_t AGG_NUM, string BOUNDARY_FLAG)
{
    Bullet_PP pp; 
    Bullet_PP_new(pp, RANGE_LEN, AGG_NUM);  
    Bullet_Setup(pp, RANGE_LEN, AGG_NUM);

    Bullet_Instance instance; 
    Bullet_Witness witness; 
    Bullet_Proof proof; 

    Bullet_Instance_new(pp, instance); 
    Bullet_Witness_new(pp, witness); 
    Bullet_Proof_new(proof); 
    
    generate_boundary_instance_witness(pp, instance, witness, BOUNDARY_FLAG); 

    string transcript_str; 
    
    auto start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Verify(pp, instance, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    Bullet_PP_free(pp); 
    Bullet_Instance_free(instance); 
    Bullet_Witness_free(witness); 
    Bullet_Proof_free(proof); 
}


void test_bulletproof(size_t RANGE_LEN, size_t AGG_NUM, bool STATEMENT_FLAG)
{
    Bullet_PP pp; 
    Bullet_PP_new(pp, RANGE_LEN, AGG_NUM);  
    Bullet_Setup(pp, RANGE_LEN, AGG_NUM);

    Bullet_Instance instance; 
    Bullet_Witness witness; 
    Bullet_Proof proof; 

    Bullet_Instance_new(pp, instance); 
    Bullet_Witness_new(pp, witness); 
    Bullet_Proof_new(proof); 
    
    generate_random_instance_witness(pp, instance, witness, STATEMENT_FLAG); 

    string transcript_str; 
    
    auto start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Verify(pp, instance, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    Bullet_PP_free(pp); 
    Bullet_Instance_free(instance); 
    Bullet_Witness_free(witness); 
    Bullet_Proof_free(proof); 
}


int main()
{ 
    global_initialize(NID_X9_62_prime256v1);   
    
    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = 2;  // number of sub-argument
    test_bulletproof(RANGE_LEN, AGG_NUM, true);
    SplitLine_print('-'); 
    // test_bulletproof(RANGE_LEN, AGG_NUM, false); 
    // SplitLine_print('-'); 
    // AGG_NUM = 1; 
    // test_bulletproof_boundary(RANGE_LEN, AGG_NUM, "LEFT");  
    // test_bulletproof_boundary(RANGE_LEN, AGG_NUM, "RIGHT");  
    global_finalize();
    
    return 0;
}