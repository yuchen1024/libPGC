#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "nizk_dlog_equality.hpp"


void generate_true_statement(DLOG_EQ_PP pp, DLOG_EQ_Instance& instance, DLOG_EQ_Witness& witness)
{
    // generate a true statement (false with overwhelming probability)
    cout << "generate a DDH tuple" << endl; 
    witness.w = random_zz(); 
    instance.g1 = random_gg(); 
    instance.g2 = random_gg(); 
    instance.h1 = instance.g1, instance.h1 *= witness.w;
    instance.h2 = instance.g2, instance.h2 *= witness.w;
}

void generate_false_statement(DLOG_EQ_PP pp, DLOG_EQ_Instance& instance, DLOG_EQ_Witness& witness)
{
    // generate a random statement (false with overwhelming probability)
    cout << "generate a random tuple" << endl; 
    witness.w = random_zz(); 
    instance.g1 = random_gg(); 
    instance.g2 = random_gg(); 
    instance.h1 = random_gg();
    instance.h2 = random_gg();
}

void run_dlog_eq_proof(DLOG_EQ_PP pp, DLOG_EQ_Instance instance, DLOG_EQ_Witness witness)
{
    cout << "begin the test of DLOG equality proof >>>" << endl; 
    DLOG_EQ_Proof proof = DLOG_Equality_Prove(pp, instance, witness); 
    DLOG_Equality_Verify(pp, instance, proof); 
}

void run_dlog_eq_auxiliary_proof(DLOG_EQ_PP pp, DLOG_EQ_Instance instance, DLOG_EQ_Witness witness, string msg_file)
{
    cout << "begin the test of DLOG equality proof with auxiliary message >>>" << endl; 
    DLOG_EQ_Proof proof = DLOG_Equality_Auxiliary_Prove(pp, instance, msg_file, witness); 
    DLOG_Equality_Auxiliary_Verify(pp, instance, msg_file, proof); 
}

int main()
{
    global_setting("../common/secp256k1.ecs"); 
    DLOG_EQ_PP pp = DLOG_Equality_Setup();
    DLOG_EQ_Instance instance; 
    DLOG_EQ_Witness witness; 

    generate_true_statement(pp, instance, witness); 
    run_dlog_eq_proof(pp, instance, witness);
    cout << endl; 

    generate_true_statement(pp, instance, witness); 
    run_dlog_eq_auxiliary_proof(pp, instance, witness, "nizk_dlog_equality.hpp");
    cout << endl; 

    generate_false_statement(pp, instance, witness); 
    run_dlog_eq_proof(pp, instance, witness);     

    return 0; 
}



