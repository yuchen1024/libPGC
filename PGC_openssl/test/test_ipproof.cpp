#define DEBUG

#include "../depends/bulletproofs/innerproduct_proof.hpp"

// generate a random instance-witness pair
void generate_random_instance_witness(InnerProduct_PP &pp, 
                                 InnerProduct_Instance &instance, 
                                 InnerProduct_Witness &witness)
{ 

    InnerProduct_Instance_new(instance); 

    InnerProduct_Witness_new(witness, pp.VECTOR_LEN); 
    BN_vec_random(witness.vec_a); 
    BN_vec_random(witness.vec_b); 

    ECP_random(instance.u);
    BIGNUM *c = BN_new(); 
    BN_vec_inner_product(c, witness.vec_a, witness.vec_b); 

    EC_POINT_mul(group, instance.P, NULL, instance.u, c, bn_ctx);  // P = u^c

    EC_POINT *temp_ecpsum = EC_POINT_new(group); 
    EC_POINT *temp_ecp1 = EC_POINT_new(group); 
    EC_POINT *temp_ecp2 = EC_POINT_new(group);
    ECP_vec_mul(temp_ecp1, pp.vec_g, witness.vec_a); 
    ECP_vec_mul(temp_ecp2, pp.vec_h, witness.vec_b); 
    EC_POINT_add(group, temp_ecpsum, temp_ecp1, temp_ecp2, bn_ctx);  
    EC_POINT_add(group, instance.P, instance.P, temp_ecpsum, bn_ctx);

    BN_free(c); 
    EC_POINT_free(temp_ecpsum); 
    EC_POINT_free(temp_ecp1); 
    EC_POINT_free(temp_ecp2); 

    cout << "generate random (instance, witness) pair >>>" << endl;  
}

void test_innerproduct_proof()
{
    InnerProduct_PP pp; 
    size_t VECTOR_LEN = 32; 
    InnerProduct_PP_new(pp, VECTOR_LEN);
    InnerProduct_Setup(pp, VECTOR_LEN, true);
    
    InnerProduct_Instance instance; 
    InnerProduct_Witness witness; 
    generate_random_instance_witness(pp, instance, witness); 

    InnerProduct_Proof proof; 
    InnerProduct_Proof_new(proof); 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    string transcript_str = ""; 
    transcript_str += ECP_ep2string(instance.P) + ECP_ep2string(instance.u); 
    InnerProduct_Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    //Print_InnerProduct_Proof(proof); 
    
    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    transcript_str += ECP_ep2string(instance.P) + ECP_ep2string(instance.u); 
    InnerProduct_Verify(pp, instance, transcript_str, proof); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "fast proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    InnerProduct_PP_free(pp); 
    InnerProduct_Instance_free(instance);
    InnerProduct_Witness_free(witness); 
    InnerProduct_Proof_free(proof); 
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    test_innerproduct_proof();  
    global_finalize();  

    return 0; 
}