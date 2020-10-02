#include "../PGC/PGC.hpp"

void build_test_enviroment()
{
    SplitLine_print('-'); 
    cout << "Build test enviroment for PGC >>>" << endl; 
    SplitLine_print('-'); 
    cout << "Setup PGC system" << endl; 
    // setup PGC system
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    size_t SN_LEN = 4; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4; 
    size_t TUNNING = 7; 
    PGC_PP pp; 
    PGC_PP_new(pp, RANGE_LEN, AGG_NUM); 
    PGC_Setup(pp, RANGE_LEN, AGG_NUM, SN_LEN, DEC_THREAD_NUM, IO_THREAD_NUM, TUNNING); 
    string PGC_PP_file = "pgc.pp"; 
    PGC_PP_serialize(pp, PGC_PP_file); 

    // create accounts for Alice and Bob
    SplitLine_print('-'); 
    cout << "generate three accounts" << endl; 
    SplitLine_print('-'); 

    BIGNUM *alice_balance = BN_new(); 
    BIGNUM *alice_sn = BN_new(); BN_one(alice_sn); 
    BN_set_word(alice_balance, 512);
    PGC_Account Acct_Alice; 
    PGC_Account_new(Acct_Alice); 
    PGC_Create_Account(pp, "Alice", alice_balance, alice_sn, Acct_Alice); 
    string Alice_ACCT_file = "Alice.account"; 
    PGC_Account_serialize(Acct_Alice, Alice_ACCT_file); 
    PGC_Account_free(Acct_Alice);

    BIGNUM *bob_balance = BN_new(); 
    BIGNUM *bob_sn = BN_new(); BN_one(bob_sn); 
    BN_set_word(bob_balance, 256); 
    PGC_Account Acct_Bob; 
    PGC_Account_new(Acct_Bob); 
    PGC_Create_Account(pp, "Bob", bob_balance, bob_sn, Acct_Bob); 
    string Bob_ACCT_file = "Bob.account"; 
    PGC_Account_serialize(Acct_Bob, Bob_ACCT_file); 
    PGC_Account_free(Acct_Bob);

    BIGNUM *tax_balance = BN_new(); 
    BIGNUM *tax_sn = BN_new(); BN_one(tax_sn); 
    BN_set_word(tax_balance, 0); 
    PGC_Account Acct_Tax; 
    PGC_Account_new(Acct_Tax); 
    PGC_Create_Account(pp, "Tax", tax_balance, tax_sn, Acct_Tax);  
    string Tax_ACCT_file = "Tax.account"; 
    PGC_Account_serialize(Acct_Tax, Tax_ACCT_file); 
    PGC_Account_free(Acct_Tax);

    PGC_PP_free(pp); 
} 

void emulate_ctx()
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    PGC_PP pp; 
    PGC_PP_new(pp, RANGE_LEN, AGG_NUM); 
    PGC_PP_deserialize(pp, "pgc.pp"); 
    PGC_Initialize(pp); 

    PGC_Account Acct_Alice; 
    PGC_Account_new(Acct_Alice); 
    PGC_Account_deserialize(Acct_Alice, "Alice.account"); 
    PGC_Account_print(Acct_Alice); 

    PGC_Account Acct_Bob; 
    PGC_Account_new(Acct_Bob); 
    PGC_Account_deserialize(Acct_Bob, "Bob.account"); 
    PGC_Account_print(Acct_Bob); 

    PGC_Account Acct_Tax; 
    PGC_Account_new(Acct_Tax); 
    PGC_Account_deserialize(Acct_Tax, "Tax.account"); 
    PGC_Account_print(Acct_Tax);

    cout << "begin to emulate transactions among Alice, Bob and Tax" << endl; 
    SplitLine_print('-'); 
    cout << "before transactions ......" << endl; 
    SplitLine_print('-');
     
    BIGNUM *v = BN_new(); 

    cout << "1st Valid CTx" << endl;
    PGC_CTx ctx1; PGC_CTx_new(ctx1);  
    BN_set_word(v, 128); 
    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " coins to Bob" << endl; 
    PGC_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, ctx1);
    PGC_Miner(pp, ctx1, Acct_Alice, Acct_Bob); 
    SplitLine_print('-'); 

    cout << "Wrong Case 1: Invalid CTx --- wrong encryption => equality proof will reject" << endl; 
    PGC_CTx wrong_ctx1; PGC_CTx_new(wrong_ctx1);  
    BN_set_word(v, 128); 
    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " to Bob" << endl; 
    PGC_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx1);

    EC_POINT* noisy = EC_POINT_new(group); 
    ECP_random(noisy); 
    EC_POINT_add(group, wrong_ctx1.transfer.X1, wrong_ctx1.transfer.X1, noisy, bn_ctx);
    EC_POINT_free(noisy); 
    PGC_Miner(pp, wrong_ctx1, Acct_Alice, Acct_Bob); 
    PGC_CTx_free(wrong_ctx1); 
    SplitLine_print('-'); 

    cout << "Wrong Case 2: Invalid CTx --- wrong interval of transfer amount => range proof will reject" << endl; 
    PGC_CTx wrong_ctx2; PGC_CTx_new(wrong_ctx2);  
    BN_set_word(v, 4294967296); 
    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " to Bob" << endl; 
    PGC_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx2);
    PGC_Miner(pp, ctx1, Acct_Alice, Acct_Bob); 
    PGC_CTx_free(wrong_ctx2); 
    SplitLine_print('-'); 

    cout << "Wrong Case 3: Invalid CTx --- balance is not enough => range proof will reject" << endl; 
    PGC_CTx wrong_ctx3; PGC_CTx_new(wrong_ctx3);
    BN_set_word(v, 385);  
    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " coins to Bob" << endl; 
    PGC_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx3);
    PGC_Miner(pp, wrong_ctx3, Acct_Alice, Acct_Bob); 
    PGC_CTx_free(wrong_ctx3); 
    SplitLine_print('-'); 

    cout << "2nd Valid CTx" << endl; 
    PGC_CTx ctx2; PGC_CTx_new(ctx2);
    BN_set_word(v, 384);  
    cout << "Alice is going to transfer "<< BN_bn2dec(v) << " coins to Bob" << endl; 
    PGC_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, ctx2);
    PGC_Miner(pp, ctx2, Acct_Alice, Acct_Bob); 
    SplitLine_print('-'); 

    cout << "3rd Valid CTx" << endl; 
    PGC_CTx ctx3; PGC_CTx_new(ctx3);
    BN_set_word(v, 32);  
    cout << "Bob is going to transfer "<< BN_bn2dec(v) << " coins to Tax" << endl; 
    PGC_Create_CTx(pp, Acct_Bob, v, Acct_Tax.pk, ctx3);
    PGC_Miner(pp, ctx3, Acct_Bob, Acct_Tax); 
    SplitLine_print('-'); 

    cout << "after transactions ......" << endl; 
    SplitLine_print('-'); 
    PGC_Account_print(Acct_Alice); 
    PGC_Account_print(Acct_Bob); 
    PGC_Account_print(Acct_Tax); 


    cout << "begin to test extended auditing policies" << endl; 
    SplitLine_print('-'); 
    cout << "test open policy over " << Get_ctxfilename(ctx1) << endl; 
    SplitLine_print('-'); 
    OPEN_POLICY predicate_open; 
    OPEN_POLICY_new(predicate_open); 

    BN_set_word(predicate_open.v, 128);  
    BN_print_dec(predicate_open.v, "Alice claims the transfer amount"); 
    BN_print_dec(predicate_open.v, "Alice generates a proof for CTx transfer amount"); 
    DLOG_Equality_Proof Alice_open_proof; 
    NIZK_DLOG_Equality_Proof_new(Alice_open_proof); 

    PGC_Justify_open_policy(pp, Acct_Alice, ctx1, predicate_open, Alice_open_proof);
    if (PGC_Audit_open_policy(pp, Acct_Alice.pk, ctx1, predicate_open, Alice_open_proof))
        cout << "Alice succeeds to justify " << Get_ctxfilename(ctx1) << endl;
    else cout << "Alice fails to justify " << Get_ctxfilename(ctx1) << endl;  
    NIZK_DLOG_Equality_Proof_free(Alice_open_proof); 
    SplitLine_print('-'); 

    BN_set_word(predicate_open.v, 127);  
    BN_print_dec(predicate_open.v, "Bob claims the transfer amount"); 
    BN_print_dec(predicate_open.v, "Bob generates a proof for CTx transfer amount"); 
    DLOG_Equality_Proof Bob_open_proof; 
    NIZK_DLOG_Equality_Proof_new(Bob_open_proof); 

    PGC_Justify_open_policy(pp, Acct_Bob, ctx1, predicate_open, Bob_open_proof);
    if (PGC_Audit_open_policy(pp, Acct_Bob.pk, ctx1, predicate_open, Bob_open_proof))
        cout << "Bob succeeds to justify " << Get_ctxfilename(ctx1) << endl;
    else cout << "Bob fails to justify " << Get_ctxfilename(ctx1) << endl;    
    NIZK_DLOG_Equality_Proof_free(Bob_open_proof); 
    OPEN_POLICY_free(predicate_open);  
    SplitLine_print('-'); 

    cout << "test rate policy over " << Get_ctxfilename(ctx1) << " and " << Get_ctxfilename(ctx3) << endl; 
    SplitLine_print('-'); 
    RATE_POLICY predicate_rate; 
    RATE_POLICY_new(predicate_rate); 
    BN_set_word(predicate_rate.t1, 1);
    BN_set_word(predicate_rate.t2, 4);

    DLOG_Equality_Proof rate_proof; 
    NIZK_DLOG_Equality_Proof_new(rate_proof); 
    PGC_Justify_rate_policy(pp, Acct_Bob, ctx1, ctx3, predicate_rate, rate_proof);
    if(PGC_Audit_rate_policy(pp, Acct_Bob.pk, ctx1, ctx3, predicate_rate, rate_proof))
        cout << "Bob paid the tax according to the rule" << endl; 
    else cout << "Bob did not pay the tax according to the rule" << endl;
    NIZK_DLOG_Equality_Proof_free(rate_proof);  
    RATE_POLICY_free(predicate_rate); 
    SplitLine_print('-'); 

    cout << "test limit policy over " << Get_ctxfilename(ctx1) << " and " << Get_ctxfilename(ctx2) << endl; 
    SplitLine_print('-'); 
    LIMIT_POLICY predicate_limit; 
    predicate_limit.RANGE_LEN = 10;
    cout << "limit = " << pow(2, predicate_limit.RANGE_LEN) -1 << endl;  
    
    Gadget2_Proof limit_proof; 
    Gadget2_Proof_new(limit_proof); 
    vector<PGC_CTx> ctx_set; 
    ctx_set.push_back(ctx1); ctx_set.push_back(ctx2); 
    PGC_Justify_limit_policy(pp, Acct_Alice, ctx_set, predicate_limit, limit_proof);
    if(PGC_Audit_limit_policy(pp, Acct_Alice.pk, ctx_set, predicate_limit, limit_proof))
        cout << "the sum of Alice's transfer amounts does not exceed limit" << endl; 
    else cout << "the sum of Alice's transfer amounts exceeds limit" << endl;
    Gadget2_Proof_free(limit_proof);  
    SplitLine_print('-');  

    predicate_limit.RANGE_LEN = 9;
    cout << "limit = " << pow(2, predicate_limit.RANGE_LEN) -1 << endl;  
    
    Gadget2_Proof_new(limit_proof);  
    PGC_Justify_limit_policy(pp, Acct_Alice, ctx_set, predicate_limit, limit_proof);
    if(PGC_Audit_limit_policy(pp, Acct_Alice.pk, ctx_set, predicate_limit, limit_proof))
        cout << "the sum of Alice's transfer amounts does not exceed limit" << endl; 
    else cout << "the sum of Alice's transfer amounts exceeds limit" << endl;
    Gadget2_Proof_free(limit_proof);  
    SplitLine_print('-');  

    BN_free(v); 
    PGC_PP_free(pp);
    PGC_Account_new(Acct_Alice);  
    PGC_Account_new(Acct_Bob); 
    PGC_Account_new(Acct_Tax); 

    PGC_CTx_free(ctx1); 
    PGC_CTx_free(ctx2); 
    PGC_CTx_free(ctx3); 
}



int main()
{
    // generate the system-wide public parameters   
    global_initialize(NID_X9_62_prime256v1); 
    // setup the system and generate three accounts
    build_test_enviroment(); 
    
    // emulate transactions among Alice, Bob, and Tax office 
    emulate_ctx(); 
    global_finalize(); 

    return 0; 
}



