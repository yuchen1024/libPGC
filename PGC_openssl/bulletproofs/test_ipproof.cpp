#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "innerproduct_proof.hpp"

// generate a random instance-witness pair
void generate_random_instance_witness(InnerProduct_PP &pp, 
                                 InnerProduct_Instance &instance, 
                                 InnerProduct_Witness &witness)
{ 

    InnerProduct_Instance_Init(instance); 

    InnerProduct_Witness_Init(witness, pp.VECTOR_LEN); 
    random_vec_zz(witness.vec_a); 
    random_vec_zz(witness.vec_b); 

    random_gg(instance.u);
    BIGNUM *c = BN_new(); 
    inner_product(c, witness.vec_a, witness.vec_b); 

    EC_POINT_mul(group, instance.P, NULL, instance.u, c, bn_ctx);  // P = u^c

    EC_POINT *temp_epsum = EC_POINT_new(group); 
    EC_POINT *temp_ep1 = EC_POINT_new(group); 
    EC_POINT *temp_ep2 = EC_POINT_new(group);
    vec_gg_mul(temp_ep1, pp.vec_g, witness.vec_a); 
    vec_gg_mul(temp_ep2, pp.vec_h, witness.vec_b); 
    EC_POINT_add(group, temp_epsum, temp_ep1, temp_ep2, bn_ctx);  
    EC_POINT_add(group, instance.P, instance.P, temp_epsum, bn_ctx);

    BN_free(c); 
    EC_POINT_free(temp_epsum); 
    EC_POINT_free(temp_ep1); 
    EC_POINT_free(temp_ep2); 

    cout << "generate random (instance, witness) pair >>>" << endl;  
}

void test_innerproduct_proof()
{
    int dimention = 32; 
    InnerProduct_PP pp; 
    InnerProduct_Setup(dimention, pp);
    // Print_InnerProduct_PP(pp);
    
    InnerProduct_Instance instance; 
    InnerProduct_Witness witness; 

    InnerProduct_Proof proof; 
    InnerProduct_Proof_Init(proof); 

    generate_random_instance_witness(pp, instance, witness); 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    string transcript_str = ""; 
    transcript_str += EC_POINT_ep2string(instance.P) + EC_POINT_ep2string(instance.u); 
    InnerProduct_Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    //Print_InnerProduct_Proof(proof); 
    
    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    transcript_str += EC_POINT_ep2string(instance.P) + EC_POINT_ep2string(instance.u); 
    InnerProduct_Verify(pp, instance, transcript_str, proof); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "fast proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    InnerProduct_PP_Free(pp); 
    InnerProduct_Instance_Free(instance);
    InnerProduct_Witness_Free(witness); 
    InnerProduct_Proof_Free(proof); 
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    test_innerproduct_proof();  
    global_finalize();  

    return 0; 
}