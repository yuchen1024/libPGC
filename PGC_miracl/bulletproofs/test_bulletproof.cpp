#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#define BASIC

#ifdef BASIC
#include "basic_bulletproof.hpp"
#endif

#ifdef LOGSIZE
#include "log_bulletproof.hpp"
#endif



void generate_true_statement(Bullet_PP pp, Bullet_Instance& instance, Bullet_Witness& witness)
{
    Print_Splitline('*'); 
    cout << "generate a true statement" << endl; 
    witness.r = random_zz(); 
    Big base = 2;
    //witness.v = -1; 
    //witness.v = pow(base, RANGE_LEN, q)-1;  
    witness.v = random_zz()% (pow(base, pp.RANGE_LEN, q));
    cout << "range = [" << 0 << ", " << pow(base, pp.RANGE_LEN, q)-1 <<"]"<<"   "; 
    cout << "v = " << witness.v << endl; 
    instance.C = mul(witness.r, pp.g, witness.v, pp.h);  
}

void generate_false_statement(Bullet_PP pp, Bullet_Instance& instance, Bullet_Witness& witness)
{
    Print_Splitline('*'); 
    cout << "generate a false statement" << endl; 
    witness.r = random_zz();
    Big base = 2; 
    resample: witness.v = random_zz();
    if (witness.v < pow(base, pp.RANGE_LEN, q)) goto resample; 
    cout << "range = [" << 0 << ", " << pow(base, pp.RANGE_LEN, q)-1 <<"]"<<"   "; 
    cout << "v = " << witness.v << endl; 
    instance.C = mul(witness.r, pp.g, witness.v, pp.h);  
}

void run_bulletproofs(const Bullet_PP pp, const Bullet_Instance& instance, const Bullet_Witness& witness)
{
    Print_Splitline('*'); 
    auto start_time = chrono::steady_clock::now(); // start to count the time
    Bullet_Proof proof = Bullet_Prove(pp, instance, witness);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    start_time = chrono::steady_clock::now(); // start to count the time
    Bullet_Verify(pp, instance, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    #ifdef LOGSIZE 
    Print_Splitline('*'); 
    start_time = chrono::steady_clock::now(); // start to count the time
    Fast_Bullet_Verify(pp, instance, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "fast proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    #endif

    Print_Splitline('*');  
}


int main()
{
    global_setting("../common/secp256k1.ecs"); 

    int size = 32; // range size
    Bullet_PP pp = Bullet_Setup(size);
    Bullet_Instance instance; 
    Bullet_Witness witness; 

    #ifdef BASIC
    cout << "Test the basic Bulletproofs" << ">>>" << endl;
    #endif

    #ifdef LOGSIZE
    cout << "Test the log size Bulletproofs" << ">>>" << endl;
    #endif

    generate_true_statement(pp, instance, witness); 
    run_bulletproofs(pp, instance, witness); 
    
    generate_false_statement(pp, instance, witness);
    run_bulletproofs(pp, instance, witness); 

    return 0; 
}