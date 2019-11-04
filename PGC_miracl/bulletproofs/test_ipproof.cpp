#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "innerproduct_proof.hpp"

void run_innerproduct_proof(InnerProduct_PP pp, InnerProduct_Instance instance, InnerProduct_Witness witness)
{
    InnerProduct_Proof proof; 
    auto start_time = chrono::steady_clock::now(); // start to count the time
    InnerProduct_Prove(pp, instance, witness, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    start_time = chrono::steady_clock::now(); // start to count the time
    InnerProduct_Verify(pp, instance, proof); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "fast proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    Naive_InnerProduct_Verify(pp, instance, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "naive proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
}

int main()
{
    global_setting("../common/secp256k1.ecs"); 

    int dimention = 32; 
    InnerProduct_PP pp = InnerProduct_Setup(dimention);
    InnerProduct_Instance instance; 
    InnerProduct_Witness witness; 

    gen_random_instance_witness(pp, instance, witness);  
    run_innerproduct_proof(pp, instance, witness); 

    return 0; 
}

// 64
// proof generation takes time = 2201.18 ms
// proof verification takes time = 2207.96 ms

// 32
// proof generation takes time = 1115.98 ms
// proof verification takes time = 1110.65 ms