//#define DEBUG

#include "../depends/nizk/nizk_plaintext_knowledge.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"


void generate_random_instance_witness(Plaintext_Knowledge_PP &pp, 
                               Plaintext_Knowledge_Instance &instance, 
                               Plaintext_Knowledge_Witness &witness)
{
    SplitLine_print('-');  
    cout << ">>> generate a valid twisted elgamal ciphertext" << endl; 

    BN_random(witness.r); 
    BN_random(witness.v);

    instance.pk = EC_POINT_new(group); 
    ECP_random(instance.pk); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 
    Twisted_ElGamal_Enc(enc_pp, instance.pk, witness.v, witness.r, CT); 
    EC_POINT_copy(instance.X, CT.X); 
    EC_POINT_copy(instance.Y, CT.Y);
    Twisted_ElGamal_CT_free(CT);  
}

void test_nizk_plaintext_knowledge()
{
    cout << "begin the test of NIZKPoK for plaintext knowledge >>>" << endl; 
    
    Plaintext_Knowledge_PP pp; 
    NIZK_Plaintext_Knowledge_PP_new(pp); 
    NIZK_Plaintext_Knowledge_Setup(pp);
    Plaintext_Knowledge_Instance instance;
    NIZK_Plaintext_Knowledge_Instance_new(instance);  
    Plaintext_Knowledge_Witness witness; 
    NIZK_Plaintext_Knowledge_Witness_new(witness); 
    Plaintext_Knowledge_Proof proof; 
    NIZK_Plaintext_Knowledge_Proof_new(proof); 

    generate_random_instance_witness(pp, instance, witness); 

    string transcript_str; 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Knowledge_Prove(pp, instance, witness, transcript_str, proof); 
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Knowledge_Verify(pp, instance, transcript_str, proof); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    NIZK_Plaintext_Knowledge_PP_free(pp);
    NIZK_Plaintext_Knowledge_Instance_free(instance);
    NIZK_Plaintext_Knowledge_Witness_free(witness);
    NIZK_Plaintext_Knowledge_Proof_free(proof);
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    test_nizk_plaintext_knowledge();  
    global_finalize();  

    return 0; 
}



