#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "../twisted_elgamal/twisted_elgamal.hpp"
#include "nizk_ct_validity.hpp"


void generate_true_statement(CT_Valid_PP pp, CT_Valid_Instance& instance, CT_Valid_Witness& witness)
{
    // generate a true statement (false with overwhelming probability)
    cout << "generate a valid twisted elgamal ciphertext" << endl; 
    witness.r = random_zz(); 
    witness.v = random_zz(); 
    instance.pk = random_gg(); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    Twisted_ElGamal_CT CT = Twisted_ElGamal_Enc(enc_pp, instance.pk, witness.v, witness.r); 
    instance.X = CT.X; 
    instance.Y = CT.Y;  
}

void run_ct_validity_proof(CT_Valid_PP pp, CT_Valid_Instance instance, CT_Valid_Witness witness)
{
    cout << "begin the test of CT validity proof >>>" << endl; 
    CT_Valid_Proof proof = CT_Validity_Prove(pp, instance, witness); 
    CT_Validity_Verify(pp, instance, proof); 
}



int main()
{
    global_setting("../common/secp256k1.ecs"); 
    CT_Valid_PP pp = CT_Validity_Setup();
    CT_Valid_Instance instance; 
    CT_Valid_Witness witness; 

    generate_true_statement(pp, instance, witness); 
    run_ct_validity_proof(pp, instance, witness);    

    return 0; 
}



