#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "nizk_dlog_equality.hpp"

void generate_random_instance_witness(DLOG_Equality_PP &pp, 
                                      DLOG_Equality_Instance &instance, 
                                      DLOG_Equality_Witness &witness, 
                                      bool flag)
{
    // generate a true statement (false with overwhelming probability)
    Print_Splitline('-'); 
    if (flag == true){
        cout << ">>> generate a DDH tuple" << endl;
    }
    else{
        cout << ">>> generate a random tuple" << endl; 
    } 
    witness.w = BN_new(); 
    random_zz(witness.w);  

    instance.g1 = EC_POINT_new(group); 
    random_gg(instance.g1); 
    instance.g2 = EC_POINT_new(group); 
    random_gg(instance.g2);

    instance.h1 = EC_POINT_new(group); 
    EC_POINT_mul(group, instance.h1, NULL, instance.g1, witness.w, bn_ctx); 
    instance.h2 = EC_POINT_new(group); 
    EC_POINT_mul(group, instance.h2, NULL, instance.g2, witness.w, bn_ctx); 

    if(flag == false){
        EC_POINT *noisy = EC_POINT_new(group); 
        random_gg(noisy);
        EC_POINT_add(group, instance.h2, instance.h2, noisy, bn_ctx);
        EC_POINT_free(noisy);
    } 
}

void test_nizk_dlog_equality(bool flag)
{
    cout << "begin the test of dlog equality proof (standard version) >>>" << endl; 
    
    DLOG_Equality_PP pp; 
    NIZK_DLOG_Equality_Setup(pp);
    DLOG_Equality_Instance instance; 
    NIZK_DLOG_Equality_Instance_Init(instance); 
    DLOG_Equality_Witness witness; 
    NIZK_DLOG_Equality_Witness_Init(witness); 
    DLOG_Equality_Proof proof; 
    NIZK_DLOG_Equality_Proof_Init(proof); 

    string aux_str; 

    // test the standard version
    aux_str = "";

    generate_random_instance_witness(pp, instance, witness, flag); 
    NIZK_DLOG_Equality_Prove(pp, instance, aux_str, witness, proof); 
    NIZK_DLOG_Equality_Verify(pp, instance, aux_str, proof);

    cout << endl; 
    cout << "begin the test of dlog equality proof (auxiliary version) >>>" << endl; 

    // test the auxiliary version
    aux_str = "now we test the auxiliary version";
    generate_random_instance_witness(pp, instance, witness, flag); 
    NIZK_DLOG_Equality_Prove(pp, instance, aux_str, witness, proof); 
    NIZK_DLOG_Equality_Verify(pp, instance, aux_str, proof);

    NIZK_DLOG_Equality_Instance_Free(instance);
    NIZK_DLOG_Equality_Witness_Free(witness);
    NIZK_DLOG_Equality_Proof_Free(proof);
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    test_nizk_dlog_equality(true);
    test_nizk_dlog_equality(false);   
    global_finalize();  

    return 0; 
}



