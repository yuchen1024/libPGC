#define DEBUG
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
    bool success; 
    success = Twisted_ElGamal_Dec(pp, keypair.sk, CT_new, m_prime); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    if(success) print_zz(m_prime, "m'");
    else cout << "decryption fails in the specified range" << endl; 
    
    BN_free(m);
    BN_free(m_prime); 
    BN_free(r_prime);  

    Twisted_ElGamal_PP_Free(pp); 
    Twisted_ElGamal_KP_Free(keypair); 
    Twisted_ElGamal_CT_Free(CT); 
    Twisted_ElGamal_CT_Free(CT_new); 
}

int main()
{
    //global_initialize(NID_secp256k1);   
    global_initialize(NID_X9_62_prime256v1);    
    test_twisted_elgamal();

    // Twisted_ElGamal_PP pp; 
    // Twisted_ElGamal_Setup(pp);
    global_finalize();
    
    return 0; 
}



