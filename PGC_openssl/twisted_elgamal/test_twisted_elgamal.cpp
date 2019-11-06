//#define DEBUG
#define PREPROCESSING

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "twisted_elgamal.hpp"

void test_twisted_elgamal()
{
    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_Setup(pp);

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_Init(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    BIGNUM *m = BN_new(); 
    // random test
    random_zz(m); 
    BN_mod(m, m, bn_M, bn_ctx);

    // boundary test
    //BN_zero(m);
    //BN_sub(m, bn_M, bn_1);  
    print_zz(m, "m");

    auto start_time = chrono::steady_clock::now(); // start to count the time
    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_Init(CT); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    BIGNUM *r_prime = BN_new(); 
    random_zz(r_prime); 
    Twisted_ElGamal_CT CT_new; 
    Twisted_ElGamal_CT_Init(CT_new); 
    Twisted_ElGamal_Refresh(pp, keypair.pk, keypair.sk, CT, CT_new, r_prime); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "refresh takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    BIGNUM *m_prime = BN_new(); 
    Twisted_ElGamal_Dec(pp, keypair.sk, CT_new, m_prime); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    print_zz(m_prime, "m'");
    
    BN_free(m);
    BN_free(m_prime); 
    BN_free(r_prime);  

    Twisted_ElGamal_PP_Free(pp); 
    Twisted_ElGamal_KP_Free(keypair); 
    Twisted_ElGamal_CT_Free(CT); 
    Twisted_ElGamal_CT_Free(CT_new); 
}

void benchmark_twisted_elgamal()
{
    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_Setup(pp);

    size_t test_num = 100000;

    cout << "begin the benchmark test, test_num = " << test_num << endl; 
    Twisted_ElGamal_KP keypair[test_num];
    BIGNUM *m[test_num]; 
    BIGNUM *m_prime[test_num]; 
    Twisted_ElGamal_CT CT[test_num]; 
    Twisted_ElGamal_CT CT_new[test_num]; 

    BIGNUM *r_prime[test_num]; 

    for(size_t i = 0; i < test_num; i++){
        Twisted_ElGamal_KP_Init(keypair[i]); 
        Twisted_ElGamal_KeyGen(pp, keypair[i]); 
        m[i] = BN_new(); 
        m_prime[i] = BN_new(); 

        random_zz(m[i]); 
        BN_mod(m[i], m[i], bn_M, bn_ctx);

        Twisted_ElGamal_CT_Init(CT[i]); 

        r_prime[i] = BN_new(); 
        random_zz(r_prime[i]); 

        Twisted_ElGamal_CT_Init(CT_new[i]); 
    }

    auto start_time = chrono::steady_clock::now(); // start to count the time
    for(size_t i = 0; i < test_num; i++)
        Twisted_ElGamal_Enc(pp, keypair[i].pk, m[i], CT[i]);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "average encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/test_num << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    for(size_t i = 0; i < test_num; i++)
        Twisted_ElGamal_Refresh(pp, keypair[i].pk, keypair[i].sk, CT[i], CT_new[i], r_prime[i]); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "average refresh takes time = " 
    << chrono::duration <double, milli> (running_time).count()/test_num << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    for(size_t i = 0; i < test_num; i++)
        Twisted_ElGamal_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "average decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/test_num << " ms" << endl;

    
    for(size_t i = 0; i < test_num; i++)
    {
        if(BN_cmp(m[i], m_prime[i]) != 0) 
            cout << "decryption fails in the specified range" << endl; 
    }
 
    for(size_t i = 0; i < test_num; i++)
    {  
        BN_free(m[i]);
        BN_free(m_prime[i]); 
        BN_free(r_prime[i]);  
        Twisted_ElGamal_KP_Free(keypair[i]); 
        Twisted_ElGamal_CT_Free(CT[i]); 
        Twisted_ElGamal_CT_Free(CT_new[i]); 
    }
    Twisted_ElGamal_PP_Free(pp); 
}

int main()
{
    //global_initialize(NID_secp256k1);   
    global_initialize(NID_X9_62_prime256v1);    
    //test_twisted_elgamal();
    benchmark_twisted_elgamal(); 

    global_finalize();
    
    return 0; 
}



