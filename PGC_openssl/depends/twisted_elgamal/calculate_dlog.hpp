/****************************************************************************
this hpp implements DLOG algorithm 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include "../common/global.hpp"

/* 
    Shanks algorithm for DLOG problem: given (g, h) find x \in [0, n = 2^RANGE_LEN) s.t. g^x = h 
    g^{j*giantstep_size + i} = g^x; giantstep_num = n/giantstep_size
*/

unordered_map<string, unsigned long> point2index_map; // key-value hash table: key is EC POINT, value is its DLOG w.r.t. g

/*
    Note that OpenSSL does not provide substract operation for EC points, 
    we have to implement substract operation by combining add operation and invert operation. 
    This means substract operation is more expensive than add operation. 
    When implementing Shanks algorithm, a repeated operation is "searchpoint = searchpoint - giantstep". 
    To be more efficient, we set giantstep = - giantstep, than do the above update as "searchpoint = searchpoint + giantstep"   
*/

/* build the hash map */
void HASHMAP_serialize(EC_POINT *&g, string hashmap_file, size_t RANGE_LEN, size_t TUNNING)
{
    cout << "hash map does not exist, begin to build and serialize >>>" << endl; 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + TUNNING); // giantstep size
    EC_POINT *ECP_babystep = EC_POINT_new(group); 
    EC_POINT_set_to_infinity(group, ECP_babystep); // set babystep = 0

    unsigned char *buffer = new unsigned char[giantstep_size*POINT_LEN]();
    if(buffer == NULL)
    {
        cout << "fail to create buffer" << endl; 
        exit(EXIT_FAILURE); 
    } 
    // compute and save g^i into buffer 
    for(auto i = 0; i < giantstep_size; i++)
    {
        EC_POINT_point2oct(group, ECP_babystep, POINT_CONVERSION_COMPRESSED, 
                           buffer+(i*POINT_LEN), POINT_LEN, bn_ctx); 
        EC_POINT_add(group, ECP_babystep, ECP_babystep, g, bn_ctx); // babystep += g
    } 
    // serialize buffer to hashmap_file
    ofstream fout; 
    fout.open(hashmap_file, ios::binary); 
    if(!fout)
    {
        cout << hashmap_file << " open error" << endl;
        exit(1); 
    }
    fout.write(reinterpret_cast<char *>(buffer), giantstep_size*POINT_LEN); 
    fout.close(); 
    delete[] buffer; 
        
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "hash map building and serializing takes time = " 
        << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    EC_POINT_free(ECP_babystep); 
}

/* rebuild hash map from hashmap file */
void HASHMAP_load(string hashmap_file, size_t RANGE_LEN, size_t TUNNING)
{   
    cout << "hash map already exists, begin to load and rebuild >>>" << endl; 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + TUNNING); 

    unsigned char* buffer = new unsigned char[giantstep_size*POINT_LEN]();  
    if(buffer == NULL)
    {
        cout << "fail to create buffer" << endl; 
        exit(EXIT_FAILURE); 
    }   
    // load hashmap_file to buffer
    ifstream fin; 
    fin.open(hashmap_file, ios::binary); 
    if(!fin)
    {
        cout << hashmap_file << " read error" << endl;
        exit(EXIT_FAILURE); 
    }
    fin.seekg(0, fin.end);
    size_t FILE_LEN = fin.tellg(); // get the size of hash table file
    if (FILE_LEN != giantstep_size*POINT_LEN)
    {
        cout << "buffer size does not match hashmap size" << endl; 
        exit(EXIT_FAILURE); 
    }
    fin.seekg(0);                  // reset the file pointer to the beginning of file
    fin.read(reinterpret_cast<char*>(buffer), FILE_LEN); // read file from disk to RAM
    fin.close(); 

    // reconstruct hashmap from buffer 
    string str; 

    /* point_to_index_map[ECn_to_String(babystep)] = i */
    for(auto i = 0; i < giantstep_size; i++)
    {
        str.assign(reinterpret_cast<char *>(buffer+(i*POINT_LEN)), POINT_LEN);  
        point2index_map[str] = i; 
    }

    delete[] buffer; 
    
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "hash map loading and rebuilding takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
} 

/* compute x s.t. y g^x = h: finding = false indicates there is no such x in specified range */
bool Shanks_DLOG(BIGNUM *&x, EC_POINT *&g, EC_POINT *&h, size_t RANGE_LEN, size_t TUNNING)
{
    /* giantstep_size * loop_num = 2^RANGE_LEN */
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + TUNNING); 
    uint64_t loop_num  = pow(2, RANGE_LEN/2 - TUNNING); 

    /* compute the giantstep */
    EC_POINT* ECP_giantstep = EC_POINT_new(group); 
    BIGNUM* BN_giantstep_size = BN_new(); 
    BN_set_word(BN_giantstep_size, giantstep_size);
    EC_POINT_mul(group, ECP_giantstep, NULL, g, BN_giantstep_size, bn_ctx); // set giantstep = g^giantstep_size
    EC_POINT_invert(group, ECP_giantstep, bn_ctx);

    /* begin to search */
    uint64_t i, j; // define two indices used to record babystep and giantstep
    EC_POINT* searchpoint = EC_POINT_new(group); 
    EC_POINT_copy(searchpoint, h);  // set the searchpoint to h
  
    string ecp_str; 
    bool finding = false; // set the initial finding flag to be false

    // check if the hash map is empty
    if(point2index_map.empty() == true)
    {
        cout << "the hashmap is empty" << endl; 
        exit (EXIT_FAILURE);
    }

    unsigned char *buffer = new unsigned char[loop_num*POINT_LEN](); 
    if (buffer == NULL)
    {
        cout << "fail to create buffer" << endl; 
        exit(EXIT_FAILURE); 
    } 
    // giant-step and baby-step search
    for(j = 0; j < loop_num; j++)
    {
        /* If key not found in map iterator to end is returned */ 

        // convert the search point to binary form
        EC_POINT_point2oct(group, searchpoint, POINT_CONVERSION_COMPRESSED, buffer+(j*POINT_LEN), POINT_LEN, bn_ctx);  
        // map the binary expression to string
        ecp_str.assign(reinterpret_cast<char*>(buffer+(j*POINT_LEN)), POINT_LEN); 
        
        // baby-step search in the hash map
        if (point2index_map.find(ecp_str) == point2index_map.end())
        {
            //EC_POINT_sub(searchpoint, searchpoint, giantstep); // not found, take a giant-step 
            EC_POINT_add(group, searchpoint, searchpoint, ECP_giantstep, bn_ctx); // not found, take a giant-step     
        }
        else{
            i = point2index_map[ecp_str]; 
            finding = true; 
            break;
        }
    }

    if(finding == true){
        BIGNUM* BN_i = BN_new(); BN_set_word(BN_i, i); 
        BIGNUM* BN_j = BN_new(); BN_set_word(BN_j, j); 

        BN_mul(BN_j, BN_j, BN_giantstep_size, bn_ctx); 
        BN_add(x, BN_i, BN_j); // x = i + j*giantstep_size; 

        BN_free(BN_i); 
        BN_free(BN_j);
    }
    else{
        cout << "the DLOG is not found in the specified range" << endl; 
    } 

    delete[] buffer; 
    EC_POINT_free(ECP_giantstep); 
    EC_POINT_free(searchpoint); 
    BN_free(BN_giantstep_size); 
    
    return finding; 
}


void search_index(EC_POINT *&ECP_searchpoint, EC_POINT *&ECP_giantstep, 
                  uint64_t &sliced_loop_num, uint64_t &i, uint64_t &j, int &finding, int &parallel_finding)
{    
    string ecp_str; 
    unsigned char *buffer = new unsigned char[sliced_loop_num*POINT_LEN](); 
    if (buffer == NULL)
    {
        cout << "fail to create buffer" << endl; 
        delete[] buffer; 
        exit(EXIT_FAILURE); 
    } 
    // giant-step and baby-step search
    for(j = 0; j < sliced_loop_num; j++)
    {
        /* If key not found in map iterator to end is returned */ 
        if (parallel_finding == 1) break; 
        // map the point to string
        EC_POINT_point2oct(group, ECP_searchpoint, POINT_CONVERSION_COMPRESSED, buffer+(j*POINT_LEN), POINT_LEN, NULL);  
        ecp_str.assign(reinterpret_cast<char*>(buffer+(j*POINT_LEN)), POINT_LEN); 
        
        // baby-step search in the hash map
        if (point2index_map.find(ecp_str) == point2index_map.end())
        {
            //EC_POINT_sub_without_bnctx(searchpoint, searchpoint, giantstep); // not found, take a giant-step forward   
            EC_POINT_add(group, ECP_searchpoint, ECP_searchpoint, ECP_giantstep, NULL); // not found, take a giant-step forward   
        }
        else{
            i = point2index_map[ecp_str]; 
            finding = 1; 
            parallel_finding = 1; 
            break;
        }
    }
    delete[] buffer; 
}

bool Parallel_Shanks_DLOG(BIGNUM *&x, EC_POINT *&g, EC_POINT *&h, 
                          size_t RANGE_LEN, size_t TUNNING, uint64_t thread_num)
{
    uint64_t giantstep_size = pow(2, RANGE_LEN/2 + TUNNING); 
    uint64_t loop_num  = pow(2, RANGE_LEN/2 - TUNNING); 

    /* compute the giantstep */
    EC_POINT* ECP_giantstep = EC_POINT_new(group); 
    BIGNUM* BN_giantstep_size = BN_new(); 
    BN_set_word(BN_giantstep_size, giantstep_size);
    EC_POINT_mul(group, ECP_giantstep, NULL, g, BN_giantstep_size, bn_ctx); // set giantstep = g^giantstep_size
    EC_POINT_invert(group, ECP_giantstep, bn_ctx);
 
    uint64_t sliced_loop_num = loop_num/thread_num; 
    if(loop_num%thread_num != 0)
    {
        cout << "thread assignment fails" << endl; 
        exit(EXIT_FAILURE); 
    }
    BIGNUM* BN_sliced_loop_num = BN_new();
    BN_set_word(BN_sliced_loop_num, sliced_loop_num);

    EC_POINT* ECP_smallscale = EC_POINT_new(group); 
    EC_POINT_mul(group, ECP_smallscale, NULL, ECP_giantstep, BN_sliced_loop_num, bn_ctx);

    /* begin to search */
    vector<uint64_t> i_index(thread_num); 
    vector<uint64_t> j_index(thread_num);

    // initialize searchpoint vector
    vector<EC_POINT*> ECP_searchpoint(thread_num);
    for (auto i = 0; i < thread_num; i++){
        ECP_searchpoint[i] = EC_POINT_new(group);         
    }   
     
    EC_POINT_copy(ECP_searchpoint[0], h);
    for (auto i = 1; i < thread_num; i++){
        EC_POINT_add(group, ECP_searchpoint[i], ECP_searchpoint[i-1], ECP_smallscale, bn_ctx);         
    }
    
    vector<int> finding(thread_num, 0); 
    int parallel_finding = 0; 

    // check if the hash map is empty
    if(point2index_map.empty() == true)
    {
        cout << "the hashmap is empty" << endl; 
        exit (EXIT_FAILURE);
    }

    vector<thread> searchtask;
    for(auto i = 0; i < thread_num; i++){ 
        searchtask.push_back(std::thread(search_index, std::ref(ECP_searchpoint[i]), 
                             std::ref(ECP_giantstep), std::ref(sliced_loop_num), 
                             std::ref(i_index[i]), std::ref(j_index[i]), 
                             std::ref(finding[i]), std::ref(parallel_finding)));
    }

    for(auto i = 0; i < thread_num; i++){ 
        searchtask[i].join(); 
    }    

    BIGNUM* BN_i = BN_new();
    BIGNUM* BN_j = BN_new();

    for(auto i = 0; i < thread_num; i++)
    { 
        if(finding[i] == 1)
        {
            BN_set_word(BN_i, i_index[i]); 
            BN_set_word(BN_j, j_index[i]+i*sliced_loop_num);             
        }
    }  

    BN_mul(BN_j, BN_j, BN_giantstep_size, bn_ctx); 
    BN_add(x, BN_i, BN_j); // x = i + j*giantstep_size; 

    BN_free(BN_i); 
    BN_free(BN_j);

    EC_POINT_free(ECP_giantstep); 
    BN_free(BN_giantstep_size); 
    BN_free(BN_sliced_loop_num); 

    EC_POINT_free(ECP_smallscale); 

    for (auto i = 0; i < thread_num; i++){
        EC_POINT_free(ECP_searchpoint[i]);         
    } 

    return true; 
}