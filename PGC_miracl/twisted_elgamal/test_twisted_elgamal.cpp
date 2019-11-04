#define DEBUG
#define PREPROCESSING

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "twisted_elgamal.hpp"

const int MSG_LEN = 32; 

void test_twisted_elgamal()
{
    Twisted_ElGamal_PP pp = Twisted_ElGamal_Setup();
    Twisted_ElGamal_KP keypair = Twisted_ElGamal_KeyGen(pp); 

    Big base = 2;
    Big message_size = pow(base, MSG_LEN, q); 
    Big m = random_zz()%message_size;
    cout << "m = " << m << endl;

    auto start_time = chrono::steady_clock::now(); // start to count the time
    Twisted_ElGamal_CT CT = Twisted_ElGamal_Enc(pp, keypair.pk, m);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    Big r_prime = random_zz(); 
    CT = Twisted_ElGamal_Refresh(pp, keypair.pk, keypair.sk, CT, r_prime); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "refresh takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    Big m_prime = Twisted_ElGamal_Dec(pp, keypair.sk, CT); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    cout << "m' = " << m_prime << endl; 
}

int main()
{
    global_setting("../common/secp256.ecs"); 
    test_twisted_elgamal(); 
    return 0; 
}



