//#define DEBUG
//#define PRINT
//#define SERIALIZE
//#define INVALID // generete an invalid transfer

#include "../common/global.hpp"
#include "../depends/routines.hpp"
#include "../depends/hash.hpp"

#include "PGC.hpp"

void test_pgc(Big balance1, Big balance2, bool ENC_CORRECT, Big v, Big v1_claim, Big v2_claim)
{
    int n = 32; // set the range to be [0, 2^32-1]
    int m = 2; 
    PGC_PP pp = PGC_Setup(n, m);
    
    // create accounts for Alice and Bob
    Print_Splitline('-'); 
    cout << "generate two accounts" << endl; 
    Print_Splitline('-'); 

    PGC_Account Acct_Alice = Create_Account(pp, "Alice", balance1); 
    PGC_Account Acct_Bob   = Create_Account(pp, "Bob", balance2); 

    Print_Splitline('-'); 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    Big nonce = 0x01; 

    // create a confidential transaction: Alice transfers v coins to Bob  
    PGC_CTx newCTx = Create_CTx(pp, nonce, Acct_Alice, v, Acct_Bob.pk);
    
    if(!ENC_CORRECT) newCTx.transfer.X1 += pp.g;  

    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "ctx generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    string str_nonce = nonce_to_string(newCTx.nonce); // format string
    string ctx_file = str_nonce + ".ctx";

    #ifdef SERIALIZE
    Serialize_CTx(newCTx, ctx_file); 
    PGC_CTx CTx; 
    Deserialize_CTx(CTx, ctx_file); 
    Print_CTx(CTx); 
    #endif

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

        mip->IOBASE = 10;
        cout << "Alice's updated balance = " << Reveal_Balance(pp, Acct_Alice) << endl; 
        cout << "Bob's updated balance = " << Reveal_Balance(pp, Acct_Bob) << endl;
        cout << endl; 
        mip->IOBASE = 16; 

        cout << str_nonce << ".ctx --- on-chain" <<endl;
    } 
    else cout << str_nonce << ".ctx --- discarded" <<endl;
    
    Print_Splitline('-'); 

    mip->IOBASE = 10; 
    cout << "Alice claims the transfer amount = " << v1_claim << endl;
    cout << "Bob claims the transfer amount = " << v2_claim << endl; 
    cout << "Resolving Dispute >>>>>>" << endl;
    mip->IOBASE = 16; 

    Print_Splitline('-'); 
    
    mip->IOBASE = 10; 
    cout << "Alice generates a proof for CTx transfer amount = " << v1_claim << endl;  
    mip->IOBASE = 16; 

    DLOG_EQ_Proof Alice_proof = Testify_CTx(pp, newCTx, "sender", v1_claim, Acct_Alice.sk);

    if (Check_CTx(pp, newCTx, "sender", v1_claim, Alice_proof))
    {
        cout << "Alice succeeds to justify " << ctx_file << endl;
    }
    else
    { 
        cout << "Alice fails to justify " << ctx_file << endl;  
    }
    cout << endl;
    
    mip->IOBASE = 10;  
    cout << "Bob generates a proof for CTx transfer amount =  " << v2_claim << endl;  
    mip->IOBASE = 16; 
    DLOG_EQ_Proof Bob_proof = Testify_CTx(pp, newCTx, "receiver", v2_claim, Acct_Bob.sk);

    if (Check_CTx(pp, newCTx, "receiver", v2_claim, Bob_proof))
    { 
        cout << "Bob succeeds to justify " << ctx_file << endl;
    }
    else 
    {
        cout << "Bob fails to justify " << ctx_file << endl;    
    }
    Print_Splitline('-'); 
}

int main()
{
    // generate the system-wide public parameters   
    global_setting("../common/secp256k1.ecs"); 

    // define test cases
    Big balance1, balance2, v, v1_claim, v2_claim; 
    bool ENC_CORRECT;  

    // Valid CTx and Correct Testfication
    balance1 = 512;  
    balance2 = 256;
    ENC_CORRECT = true;  
    v = 128; 
    v1_claim = 128; 
    v2_claim = 128; 
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    // Invalid CTx: wrong encryption
    balance1 = 512;  
    balance2 = 256;
    ENC_CORRECT = false;  
    v = 128; 
    v1_claim = 128; 
    v2_claim = 128; 
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    // Invalid CTx: wrong interval of transfer amount => range proof will reject
    balance1 = 4294967297; 
    balance2 = 12345; 
    ENC_CORRECT = true; 
    v = 4294967296; 
    v1_claim = 4294967296;  
    v2_claim = 4294967296;  
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    // Invalid CTx: balance is not enough => range proof will reject
    balance1 = 512;  
    balance2 = 256;
    ENC_CORRECT = true;  
    v = 513; 
    v1_claim = 513; 
    v2_claim = 513; 
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    // Wrong testification: Bob's testifying proof will reject
    balance1 = 512;  
    balance2 = 256;
    ENC_CORRECT = true;  
    v = 512; 
    v1_claim = 512; 
    v2_claim = 511; 
    test_pgc(balance1, balance2, ENC_CORRECT, v, v1_claim, v2_claim); 

    return 0; 
}



