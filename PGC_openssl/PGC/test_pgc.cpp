//#define DEBUG
//#define PRINT
#define SERIALIZE // indicate serialize CTx or not

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "PGC.hpp"

void test_pgc(BIGNUM* &balance1, BIGNUM* &balance2, bool ENC_CORRECT, 
              BIGNUM* &v, BIGNUM* &v1_claim, BIGNUM* &v2_claim)
{
    int n = 32; // set the range to be [0, 2^32-1]
    int m = 2; 
    PGC_PP pp; 
    PGC_Setup(n, m, pp);
    //Print_PGC_PP(pp); 
    
    // create accounts for Alice and Bob
    Print_Splitline('-'); 
    cout << "generate two accounts" << endl; 
    Print_Splitline('-'); 

    BIGNUM* sn1 = BN_new(); 
    BN_one(sn1); 

    BIGNUM* sn2 = BN_new(); 
    BN_one(sn2); 

    PGC_Account Acct_Alice; 
    PGC_Account_Init(Acct_Alice); 

    Create_Account(pp, "Alice", balance1, sn1, Acct_Alice); 

    PGC_Account Acct_Bob; 
    PGC_Account_Init(Acct_Bob); 
    Create_Account(pp, "Bob", balance2, sn2, Acct_Bob); 

    Print_Splitline('-'); 

    auto start_time = chrono::steady_clock::now(); // start to count the time
 

    // create a confidential transaction: Alice transfers v coins to Bob  
    PGC_CTx newCTx; 
    PGC_CTx_Init(newCTx); 

    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " to Bob" << endl; 
    Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, newCTx);

    string str_sn = sn_to_string(Acct_Alice.sn); 
    string memo_file = str_sn + ".memo"; 
    string ctx_file  = str_sn + ".ctx"; 
    
    if(!ENC_CORRECT){
        EC_POINT* noisy = EC_POINT_new(group); 
        random_gg(noisy); 
        EC_POINT_add(group, newCTx.transfer.X1, newCTx.transfer.X1, noisy, bn_ctx);
        EC_POINT_free(noisy); 
    } 
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "ctx generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    // print the details
    #ifdef PRINT
    Print_CTx(newCTx); 
    #endif

    // check its validity
    start_time = chrono::steady_clock::now(); // start to count the time
    bool Validity = Verify_CTx(pp, newCTx); 
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "ctx verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    if (Validity)
    {
        Update_Account(pp, newCTx, Acct_Alice, Acct_Bob); // update Alice and Bob's account

        BIGNUM* m = BN_new();
        Reveal_Balance(pp, Acct_Alice, m);
        print_dec_zz(m, "Alice's updated balance"); 

        Reveal_Balance(pp, Acct_Bob, m);
        print_dec_zz(m, "Bob's updated balance"); 

        cout << str_sn << ".ctx --- on-chain" <<endl;
    } 
    else cout << str_sn << ".ctx --- discarded" <<endl;
    
    Print_Splitline('-'); 

    print_dec_zz(v1_claim, "Alice claims the transfer amount"); 
    print_dec_zz(v2_claim, "Bob claims the transfer amount"); 

    cout << "Resolving Dispute >>>>>>" << endl;

    Print_Splitline('-'); 

    print_dec_zz(v1_claim, "Alice generates a proof for CTx transfer amount"); 

    DLOG_Equality_Proof Alice_proof; 
    NIZK_DLOG_Equality_Proof_Init(Alice_proof); 
    Justify_CTx(pp, newCTx, "sender", v1_claim, Acct_Alice.sk, Alice_proof);

    if (Check_CTx(pp, newCTx, "sender", v1_claim, Alice_proof))
    {
        cout << "Alice succeeds to justify " << ctx_file << endl;
    }
    else
    { 
        cout << "Alice fails to justify " << ctx_file << endl;  
    }
    cout << endl;

    print_dec_zz(v2_claim, "Bob generates a proof for CTx transfer amount"); 
    DLOG_Equality_Proof Bob_proof; 
    NIZK_DLOG_Equality_Proof_Init(Bob_proof); 
    Justify_CTx(pp, newCTx, "receiver", v2_claim, Acct_Bob.sk, Bob_proof);

    if (Check_CTx(pp, newCTx, "receiver", v2_claim, Bob_proof))
    { 
        cout << "Bob succeeds to justify " << ctx_file << endl;
    }
    else 
    {
        cout << "Bob fails to justify " << ctx_file << endl;    
    }
    Print_Splitline('-'); 

    // PGC_PP_Free(pp); 
    // PGC_Account_Free(Acct_Alice); 
    // PGC_Account_Free(Acct_Bob); 
    PGC_CTx_Free(newCTx); 
}

int main()
{
    // generate the system-wide public parameters   
    global_initialize(NID_X9_62_prime256v1); 

    // define test cases
    BIGNUM* balance1 = BN_new(); 
    BIGNUM* balance2 = BN_new(); 
    BIGNUM* v = BN_new(); 
    BIGNUM* v1_claim = BN_new(); 
    BIGNUM* v2_claim = BN_new();

    bool ENC_CORRECT;  

    cout << "Valid CTx and correct justification" << endl; 
    BN_set_word(balance1, 512);
    BN_set_word(balance2, 256);
    ENC_CORRECT = true;  
    BN_set_word(v, 128); 
    BN_set_word(v1_claim, 128);
    BN_set_word(v2_claim, 128);
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    cout << endl;
    cout << "Invalid CTx: wrong encryption => equality proof will reject" << endl; 
    BN_set_word(balance1, 512);
    BN_set_word(balance2, 256);
    ENC_CORRECT = false;  
    BN_set_word(v, 128); 
    BN_set_word(v1_claim, 128);
    BN_set_word(v2_claim, 128);
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    cout << endl;
    cout << "Invalid CTx: wrong interval of transfer amount => range proof will reject" << endl; 
    BN_set_word(balance1, 4294967297);
    BN_set_word(balance2, 12345);
    ENC_CORRECT = true;  
    BN_set_word(v, 4294967296); 
    BN_set_word(v1_claim, 4294967296);
    BN_set_word(v2_claim, 4294967296);
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    cout << endl; 
    cout << "Invalid CTx: balance is not enough => range proof will reject" << endl; 
    BN_set_word(balance1, 512);
    BN_set_word(balance2, 256);
    ENC_CORRECT = true;  
    BN_set_word(v, 513); 
    BN_set_word(v1_claim, 513);
    BN_set_word(v2_claim, 513);
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    cout << endl;
    cout << "Wrong justification: Bob's justifying proof will reject" << endl; 
    BN_set_word(balance1, 512);
    BN_set_word(balance2, 256);
    ENC_CORRECT = true;  
    BN_set_word(v, 512); 
    BN_set_word(v1_claim, 512);
    BN_set_word(v2_claim, 511);
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    BN_free(balance1);
    BN_free(balance2); 
    BN_free(v); 
    BN_free(v1_claim); 
    BN_free(v2_claim); 

    return 0; 
}



