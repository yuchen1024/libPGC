#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"


#include "nizk_plaintext_knowledge.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"


void generate_random_instance_witness(Plaintext_Knowledge_PP &pp, 
                               Plaintext_Knowledge_Instance &instance, 
                               Plaintext_Knowledge_Witness &witness)
{
    Print_Splitline('-');  
    cout << ">>> generate a valid twisted elgamal ciphertext" << endl; 

    random_zz(witness.r); 
    random_zz(witness.v);

    instance.pk = EC_POINT_new(group); 
    random_gg(instance.pk); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_Init(CT); 
    Twisted_ElGamal_Enc(enc_pp, instance.pk, witness.v, witness.r, CT); 
    EC_POINT_copy(instance.X, CT.X); 
    EC_POINT_copy(instance.Y, CT.Y);
    Twisted_ElGamal_CT_Free(CT);  
}

void test_nizk_plaintext_knowledge()
{
    cout << "begin the test of NIZKPoK for plaintext knowledge >>>" << endl; 
    
    Plaintext_Knowledge_PP pp; 
    NIZK_Plaintext_Knowledge_Setup(pp);
    Plaintext_Knowledge_Instance instance;
    NIZK_Plaintext_Knowledge_Instance_Init(instance);  
    Plaintext_Knowledge_Witness witness; 
    NIZK_Plaintext_Knowledge_Witness_Init(witness); 
    Plaintext_Knowledge_Proof proof; 
    NIZK_Plaintext_Knowledge_Proof_Init(proof); 

    generate_random_instance_witness(pp, instance, witness); 

    NIZK_Plaintext_Knowledge_Prove(pp, instance, witness, proof); 
    NIZK_Plaintext_Knowledge_Verify(pp, instance, proof); 

    NIZK_Plaintext_Knowledge_PP_Free(pp);
    NIZK_Plaintext_Knowledge_Instance_Free(instance);
    NIZK_Plaintext_Knowledge_Witness_Free(witness);
    NIZK_Plaintext_Knowledge_Proof_Free(proof);
}

int main()
{
    global_initialize(NID_X9_62_prime256v1); 

    test_nizk_plaintext_knowledge();  
    global_finalize();  

    return 0; 
}



