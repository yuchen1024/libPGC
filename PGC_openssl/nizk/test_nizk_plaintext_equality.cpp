#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "nizk_plaintext_equality.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"


void generate_random_instance_witness(Plaintext_Equality_PP &pp, 
                                Plaintext_Equality_Instance &instance, 
                                Plaintext_Equality_Witness &witness, 
                                bool flag)
{
    Print_Splitline('-');  
    if (flag == true){
        cout << ">>> generate a well-formed 1-message 2-reciepient twisted elgamal ciphertext" << endl; 
    }
    else{
         cout << ">>> generate an ill-formed 1-message 2-reciepient twisted elgamal ciphertext" << endl; 
    }

    random_zz(witness.r);
    random_zz(witness.v); 

    random_gg(instance.pk1);
    random_gg(instance.pk2);

    Twisted_ElGamal_PP enc_pp; 
    //Twisted_ElGamal_PP_Init(enc_pp); 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h; 
    MR_Twisted_ElGamal_CT CT; 
    MR_Twisted_ElGamal_CT_Init(CT); 
    MR_Twisted_ElGamal_Enc(enc_pp, instance.pk1, instance.pk2, witness.v, witness.r, CT); 
    
    EC_POINT_copy(instance.X1, CT.X1); 
    EC_POINT_copy(instance.X2, CT.X2); 
    EC_POINT_copy(instance.Y, CT.Y); 

    if(flag == false){
        EC_POINT *noisy = EC_POINT_new(group); 
        random_gg(noisy);
        EC_POINT_add(group, instance.Y, instance.Y, noisy, bn_ctx);
        EC_POINT_free(noisy);
    } 
    //Twisted_ElGamal_PP_Free(enc_pp); 
    MR_Twisted_ElGamal_CT_Free(CT); 
}

void test_nizk_plaintext_equality(bool flag)
{
    cout << "begin the test of NIZKPoK for plaintext equality >>>" << endl; 

    Plaintext_Equality_PP pp;
    NIZK_Plaintext_Equality_Setup(pp);
    Plaintext_Equality_Instance instance; 
    NIZK_Plaintext_Equality_Instance_Init(instance); 
    Plaintext_Equality_Witness witness; 
    NIZK_Plaintext_Equality_Witness_Init(witness); 
    Plaintext_Equality_Proof proof; 
    NIZK_Plaintext_Equality_Proof_Init(proof); 

    generate_random_instance_witness(pp, instance, witness, flag); 
    NIZK_Plaintext_Equality_Prove(pp, instance, witness, proof); 
    NIZK_Plaintext_Equality_Verify(pp, instance, proof);

    NIZK_Plaintext_Equality_Instance_Free(instance);
    NIZK_Plaintext_Equality_Witness_Free(witness);
    NIZK_Plaintext_Equality_Proof_Free(proof); 

    NIZK_Plaintext_Equality_PP_Free(pp); 
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 
    
    test_nizk_plaintext_equality(true);
    test_nizk_plaintext_equality(false);  

    global_finalize();  

    return 0; 
}



