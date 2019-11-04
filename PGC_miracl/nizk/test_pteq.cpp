#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "../twisted_elgamal/twisted_elgamal.hpp"
#include "nizk_plaintext_equality.hpp"


void generate_true_statement(PT_EQ_PP pp, PT_EQ_Instance& instance, PT_EQ_Witness& witness)
{
    // generate a true statement (false with overwhelming probability)
    cout << "generate a real 2-recipient twisted elgamal ciphertext" << endl; 
    witness.r = random_zz(); 
    witness.v = random_zz(); 
    instance.pk1 = random_gg(); 
    instance.pk2 = random_gg(); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    MR_Twisted_ElGamal_CT CT = MR_Twisted_ElGamal_Enc(enc_pp, instance.pk1, instance.pk2, witness.v, witness.r); 
    instance.X1 = CT.X1; 
    instance.X2 = CT.X2;
    instance.Y = CT.Y;  
}

void generate_false_statement(PT_EQ_PP pp, PT_EQ_Instance& instance, PT_EQ_Witness& witness)
{
    // generate a random statement (false with overwhelming probability)
    cout << "generate a fake twisted elgamal ciphertext" << endl; 
    witness.r = random_zz(); 
    witness.v = random_zz(); 
    instance.pk1 = random_gg(); 
    instance.pk2 = random_gg(); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    MR_Twisted_ElGamal_CT CT = MR_Twisted_ElGamal_Enc(enc_pp, instance.pk1, instance.pk2, witness.v, witness.r); 
    instance.X1 = CT.X1; 
    instance.X2 = CT.X2;
    instance.Y = CT.Y;  
    instance.X2 += random_gg();  

}

void run_plaintext_eq_proof(PT_EQ_PP pp, PT_EQ_Instance instance, PT_EQ_Witness witness)
{
    cout << "begin the test of PT equality proof >>>" << endl; 
    PT_EQ_Proof proof = PT_Equality_Prove(pp, instance, witness); 
    PT_Equality_Verify(pp, instance, proof); 
}

int main()
{
    global_setting("../common/secp256k1.ecs"); 
    PT_EQ_PP pp = PT_Equality_Setup();
    PT_EQ_Instance instance; 
    PT_EQ_Witness witness; 

    generate_true_statement(pp, instance, witness); 
    run_plaintext_eq_proof(pp, instance, witness);
    cout << endl; 

    generate_false_statement(pp, instance, witness); 
    run_plaintext_eq_proof(pp, instance, witness);     

    return 0; 
}



