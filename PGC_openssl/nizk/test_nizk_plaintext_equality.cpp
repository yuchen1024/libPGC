#define DEBUG

#include "nizk_plaintext_equality.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"

void generate_random_instance_witness(Plaintext_Equality_PP &pp, 
                                Plaintext_Equality_Instance &instance, 
                                Plaintext_Equality_Witness &witness, 
                                bool flag)
{
    SplitLine_print('-');  
    if (flag == true){
        cout << ">>> generate a well-formed 1-message 2-reciepient twisted elgamal ciphertext" << endl; 
    }
    else{
         cout << ">>> generate an ill-formed 1-message 2-reciepient twisted elgamal ciphertext" << endl; 
    }

    BN_random(witness.r);
    BN_random(witness.v); 

    ECP_random(instance.pk1);
    ECP_random(instance.pk2);

    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h; 
    MR_Twisted_ElGamal_CT CT; 
    MR_Twisted_ElGamal_CT_new(CT); 
    MR_Twisted_ElGamal_Enc(enc_pp, instance.pk1, instance.pk2, witness.v, witness.r, CT); 
    
    EC_POINT_copy(instance.X1, CT.X1); 
    EC_POINT_copy(instance.X2, CT.X2); 
    EC_POINT_copy(instance.Y, CT.Y); 

    if(flag == false){
        EC_POINT *noisy = EC_POINT_new(group); 
        ECP_random(noisy);
        EC_POINT_add(group, instance.Y, instance.Y, noisy, bn_ctx);
        EC_POINT_free(noisy);
    } 
    //Twisted_ElGamal_PP_Free(enc_pp); 
    MR_Twisted_ElGamal_CT_free(CT); 
}

void test_nizk_plaintext_equality(bool flag)
{
    cout << "begin the test of NIZKPoK for plaintext equality >>>" << endl; 

    Plaintext_Equality_PP pp;
    NIZK_Plaintext_Equality_PP_new(pp);    
    NIZK_Plaintext_Equality_Setup(pp);
    Plaintext_Equality_Instance instance; 
    NIZK_Plaintext_Equality_Instance_new(instance); 
    Plaintext_Equality_Witness witness; 
    NIZK_Plaintext_Equality_Witness_new(witness); 
    Plaintext_Equality_Proof proof; 
    NIZK_Plaintext_Equality_Proof_new(proof); 

    string transcript_str; 

    generate_random_instance_witness(pp, instance, witness, flag); 
    auto start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Equality_Prove(pp, instance, witness, transcript_str, proof); 
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Equality_Verify(pp, instance, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    NIZK_Plaintext_Equality_PP_free(pp); 
    NIZK_Plaintext_Equality_Instance_free(instance);
    NIZK_Plaintext_Equality_Witness_free(witness);
    NIZK_Plaintext_Equality_Proof_free(proof); 
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    
    test_nizk_plaintext_equality(true);
    test_nizk_plaintext_equality(false);  

    global_finalize();  

    return 0; 
}



