#define DEBUG

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "aggregate_bulletproof.hpp"


void generate_true_statement(Bullet_PP pp, Bullet_Instance& instance, Bullet_Witness& witness)
{
    Print_Splitline('*'); 
    cout << "generate a true statement" << endl; 
    Big base = 2;
    //witness.v = -1; 
    //witness.v = pow(base, RANGE_LEN, q)-1;  

    Big range_size = pow(base, pp.RANGE_LEN, q);
    cout << "range = [" << 0 << ", " << (range_size-1) <<"]"<<endl; 
    int i; 
    for(i = 0; i < pp.m; i++)
    {
        witness.r.push_back(random_zz()); 
        witness.v.push_back(random_zz()%range_size); 
        instance.C.push_back(mul(witness.r[i], pp.g, witness.v[i], pp.h)); 
        cout << "v["<<i<<"]= " << witness.v[i] << endl; 
    }
}

void generate_false_statement(Bullet_PP pp, Bullet_Instance& instance, Bullet_Witness& witness)
{
    Print_Splitline('*'); 
    cout << "generate a random statement (false with overwhelming probability)" << endl; 
    Big base = 2; 
    Big range_size = pow(base, pp.RANGE_LEN, q);
    cout << "range = [" << 0 << ", " << (range_size-1) <<"]"<<endl; 
    int i; 

    for(i = 0; i < pp.m-1; i++)
    {
        witness.r.push_back(random_zz()); 
        witness.v.push_back(random_zz()%range_size); 
        instance.C.push_back(mul(witness.r[i], pp.g, witness.v[i], pp.h)); 
        cout << "v["<<i<<"]= " << witness.v[i] << endl; 
    }
    witness.r.push_back(random_zz()); 
    witness.v.push_back(random_zz());
    instance.C.push_back(mul(witness.r[pp.m-1], pp.g, witness.v[pp.m-1], pp.h)); 
    cout << "v["<<7<<"]= " << witness.v[pp.m-1] << endl;  
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

    Print_Splitline('*');  
}


int main()
{
    global_setting("../common/secp256k1.ecs"); 

    int n = 64; // range size
    int m = 8;  // number of sub-argument
    Bullet_PP pp = Bullet_Setup(n, m);
    Bullet_Instance instance1, instance2; 
    Bullet_Witness witness1, witness2; 

    cout << "Test the aggregated log size Bulletproofs" << ">>>" << endl;

    generate_true_statement(pp, instance1, witness1); 
    run_bulletproofs(pp, instance1, witness1); 
    cout << endl; 
    
    generate_false_statement(pp, instance2, witness2);
    run_bulletproofs(pp, instance2, witness2); 

    return 0; 
}