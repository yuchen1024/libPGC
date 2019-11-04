/****************************************************************************
this hpp implements DLOG algorithm 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <thread>

using namespace std; 

uint64_t RANGE_LEN = 32; 
uint64_t tunning = 7; // one can increase this parameter: larger table size and less running time
unordered_map<string, unsigned long> point_to_index_map; // the maximum size of the table is 2^32

/* 
    This program implements the Shanks algorithm for DLOG problem

    give (g, h) find x \in [n] s.t. g^x = h 
    g^{j*step_size + i}
    loop_num = n/step_size
*/
void Serialize_Map(EC_POINT* &g, string map_file)
{
    // build the hash map 
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + tunning); 

    EC_POINT* babystep = EC_POINT_new(group); 
    EC_POINT_set_to_infinity(group, babystep); // set babystep = 0
    if(!file_exist(map_file))
    {
        #ifdef DEBUG
        cout << "search table does not exist, begin to generate it now >>>" << endl;
        #endif 
        
        auto start_time = chrono::steady_clock::now(); // start to count the time

        unsigned char *buffer = new unsigned char[giantstep_size*POINT_LEN](); 

        for(uint64_t i = 0; i < giantstep_size; i++)
        {
            EC_POINT_point2oct(group, babystep, POINT_CONVERSION_COMPRESSED, 
            buffer+(i*POINT_LEN), POINT_LEN, bn_ctx); 
            EC_POINT_add(group, babystep, babystep, g, bn_ctx); 
        } 
        ofstream fout; 
        fout.open(map_file, ios::binary); 
        fout.write(reinterpret_cast<char*>(buffer), giantstep_size*POINT_LEN); 
        fout.close(); 
        delete[] buffer; 
        
        auto end_time = chrono::steady_clock::now(); // end to count the time
        auto running_time = end_time - start_time;
        cout << "search table generation takes time = " 
        << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    }
    else{
        cout << "search table already exists, begin to load >>>" << endl; 
    }

    EC_POINT_free(babystep); 
}

void Load_Map(string map_file)
{   
    auto start_time = chrono::steady_clock::now(); // start to count the time
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + tunning); 
    unsigned char* buffer = new unsigned char[giantstep_size*POINT_LEN];     
    ifstream fin; 
    fin.open(map_file, ios::binary); 
    if(!fin){
        throw "cannot open the map file"; 
    }
    fin.seekg(0, fin.end);
    size_t FILE_LEN = fin.tellg();
    fin.seekg(0); 
    fin.read(reinterpret_cast<char*>(buffer), giantstep_size*POINT_LEN); 
    fin.close(); 

    unsigned char A[POINT_LEN]; 
    string ep_str; 

    for(uint64_t i = 1; i < giantstep_size; i++)
    {
        //point_to_index_map[ECn_to_String(babystep)] = i;
        memcpy(A, buffer+(i*POINT_LEN), POINT_LEN); 
        ep_str.assign(reinterpret_cast<char*>(A), POINT_LEN);  
        point_to_index_map[ep_str] = i;
    }
    delete[] buffer; 
    
    #ifdef DEBUG
    cout << "search table load finishes >>>" << endl; 
    #endif 

    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "search table loading takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
} 

bool Preprocessing_Shanks(BIGNUM* &x, EC_POINT* &g, EC_POINT* &h)
{
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + tunning); 
    uint64_t loop_num  = pow(2, RANGE_LEN/2 - tunning); 

    EC_POINT* giantstep = EC_POINT_new(group); 
    BIGNUM* bn_giantstep_size = BN_new(); 
    BN_set_word(bn_giantstep_size, giantstep_size);

    EC_POINT_mul(group, giantstep, NULL, g, bn_giantstep_size, bn_ctx); // set giantstep = g^giantstep_size

    // begin to search;
    uint64_t i, j; 
    EC_POINT* searchpoint = EC_POINT_new(group); 
    EC_POINT_copy(searchpoint, h);    

    string ep_str;
 
    unsigned char A[POINT_LEN]; 
    bool finding = false; 
    for(j = 0; j < loop_num; j++)
    {
        // If key not found in map iterator to end is returned
        if(EC_POINT_is_at_infinity(group, searchpoint) == 1) 
        {
            i = 0; 
            finding = true; 
            break; 
        } 

        EC_POINT_point2oct(group, searchpoint, POINT_CONVERSION_COMPRESSED, A, POINT_LEN, bn_ctx); 
        ep_str.assign(reinterpret_cast<char*>(A), POINT_LEN); 
        if (point_to_index_map.find(ep_str) == point_to_index_map.end())
        {
            EC_POINT_sub(searchpoint, searchpoint, giantstep);   
        }
        else{
            i = point_to_index_map[ep_str]; 
            finding = true; 
            break;
        }
    }
    if(finding == true){
        BIGNUM* bn_i = BN_new(); BN_set_word(bn_i, i); 
        BIGNUM* bn_j = BN_new(); BN_set_word(bn_j, j); 

        BN_mul(bn_j, bn_j, bn_giantstep_size, bn_ctx); 
        BN_add(x, bn_i, bn_j); // x = i + j*giantstep_size; 

        EC_POINT_free(giantstep); 
        EC_POINT_free(searchpoint); 
        BN_free(bn_giantstep_size); 
        BN_free(bn_i); 
        BN_free(bn_j);
    }
    else{
        cout << "the DLOG is not found in the specified range" << endl; 
    } 
    return finding; 
}

void search_hash_table(string& ep_str, int& finding) 
{ 
    if (point_to_index_map.find(ep_str) == point_to_index_map.end()) finding = 0; 
    else finding = 1; 
} 

bool Preprocessing_Parallel_Shanks(BIGNUM* &x, EC_POINT* &g, EC_POINT* &h)
{
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + tunning); 
    uint64_t loop_num  = pow(2, RANGE_LEN/2 - tunning); 

    EC_POINT* giantstep = EC_POINT_new(group); 
    BIGNUM* bn_giantstep_size = BN_new(); 
    BN_set_word(bn_giantstep_size, giantstep_size);

    EC_POINT_mul(group, giantstep, NULL, g, bn_giantstep_size, bn_ctx); // set giantstep = g^giantstep_size

    // begin to search;
    uint64_t i, j; 
    EC_POINT* searchpoint = EC_POINT_new(group); 
    EC_POINT_copy(searchpoint, h);    

    //uint64_t thread_num = std::thread::hardware_concurrency();
    uint64_t thread_num = 2; 
    vector<string> ep_str(thread_num); 
 
    unsigned char A[POINT_LEN]; 
    bool finding_one = false; 
    vector<int> finding(thread_num);
    //bool finding; 

    cout << "loop_num = " << loop_num << endl; 

    for(j = 0; j < loop_num; j += thread_num)
    {
        // If key not found in map iterator to end is returned
        if(EC_POINT_is_at_infinity(group, searchpoint) == 1) 
        {
            i = 0; 
            finding_one = true; 
            break; 
        } 
        vector<std::thread> search_index; 
        for(uint64_t k = 0; k < thread_num; k++){
            EC_POINT_point2oct(group, searchpoint, POINT_CONVERSION_COMPRESSED, A, POINT_LEN, bn_ctx); 
            ep_str[k].assign(reinterpret_cast<char*>(A), POINT_LEN); 
            finding[k] = 0; 
            thread thr_search(search_hash_table, std::ref(ep_str[k]), std::ref(finding[k]));
            search_index.emplace_back(std::move(thr_search));
            EC_POINT_sub(searchpoint, searchpoint, giantstep);   
        }
        for(uint64_t k = 0; k < thread_num; k++){
            search_index[k].join(); 
        }
 
        for(uint64_t k = 0; k < thread_num; k++){
            if(finding[k] == 1){
                i = point_to_index_map[ep_str[k]]; 
                finding_one = true; 
                j = j + k;
                goto search_finished; 
            }
        }        
    }
    search_finished:
    if(finding_one == true){
        BIGNUM* bn_i = BN_new(); BN_set_word(bn_i, i); 
        BIGNUM* bn_j = BN_new(); BN_set_word(bn_j, j); 

        cout << "i = " << i << endl; 
        cout << "j = " << j << endl; 

        BN_mul(bn_j, bn_j, bn_giantstep_size, bn_ctx); 
        BN_add(x, bn_i, bn_j); // x = i + j*giantstep_size; 
        //BN_set_word(x, i + j*giantstep_size); 
        BN_free(bn_i); 
        BN_free(bn_j);
    }
    else{
        cout << "the DLOG is not found in the specified range" << endl; 
    } 

    EC_POINT_free(giantstep); 
    EC_POINT_free(searchpoint); 
    BN_free(bn_giantstep_size); 
    
    return finding_one; 
}


/*
    Solve the Discrete Logarithm Problem by Brute Force: x = log_g h
*/
void Brute_Search(BIGNUM* &x, EC_POINT* &g, EC_POINT* &h)
{
    EC_POINT *searchpoint = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, searchpoint); 
    //EC_POINT_copy(searchpoint, g); // set searchpoint = g; 

    BN_zero(x); // set x = 0  

    while(true){
        if(EC_POINT_cmp(group, searchpoint, h, bn_ctx)==0) break; 
        else{
            EC_POINT_add(group, searchpoint, searchpoint, g, bn_ctx); // searchpoint += g; 
            BN_add(x, x, bn_1); // x += 1; 
        }
    }
    EC_POINT_free(searchpoint); 
}
