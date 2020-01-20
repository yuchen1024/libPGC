#define DEBUG

#include "twisted_elgamal.hpp"

void test_twisted_elgamal()
{
    SplitLine_print('-'); 
    cout << "begin the basic correctness test >>>" << endl; 
    
    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t THREAD_NUM = 4;     
    Twisted_ElGamal_Setup(pp, MSG_LEN, TUNNING, THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    BN_random(m); 
    BN_mod(m, m, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(m, "m"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Parallel_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    // boundary test
    SplitLine_print('-'); 
    cout << "begin the left boundary test >>>" << endl; 
    BN_zero(m);
    BN_print(m, "m"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Parallel_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    SplitLine_print('-'); 
    cout << "begin the right boundary test >>>" << endl; 
    BN_sub(m, pp.BN_MSG_SIZE, BN_1);  
    BN_print(m, "m");
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Parallel_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 
 
    Twisted_ElGamal_PP_free(pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime); 
}

int main()
{  
    global_initialize(NID_X9_62_prime256v1);    
    test_twisted_elgamal();
    global_finalize();
    
    return 0; 
}



