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
#include "ecn.h"
#include "zzn.h"

const int RANGE_LEN = 32; 
const int tunning = 0; // one can increase this parameter: larger table size and less running time
unordered_map<string, Big> point_to_index_map; 

inline string ECn_to_String(const ECn g)
{
    stringstream ss; 
    Big x, y; 
    g.get(x, y); 
    ss << x << y;
    return ss.str();  
}

/* 
    This program implements the Shanks algorithm for DLOG problem

    give (g, h) find x \in [n] s.t. g^x = h 
    g^{j*step_size + i}
    loop_num = n/step_size
*/
void Serialize_Map(const ECn g)
{
    // build the hash map
    Big base = 2; 
    Big giantstep_size = pow(base, RANGE_LEN/2 + tunning, q); 

    #ifdef DEBUG
    cout << "begin to generate the serach table" << endl; 
    #endif 

    auto start_time = chrono::steady_clock::now(); // start to count the time
    ECn babystep = ZeroPoint; // set T = 0
    if(!file_exist("serach.table"))
    {
        ofstream fout; 
        fout.open("search.table", ios::binary); 
        for(Big i = 0; i < giantstep_size; i+=1)
        {
            //point_to_index_map[ECn_to_String(babystep)] = i;
            Serialize_GG(babystep, fout); 
            babystep += g; //i = i + 1; 
        } 
    fout.close(); 
    }
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "search table generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    start_time = chrono::steady_clock::now(); // start to count the time
    #ifdef DEBUG
    cout << "begin to load the search table >>>" << endl; 
    #endif 
    
    ifstream fin; 
    fin.open("search.table", ios::binary); 
    for(Big i = 0; i < giantstep_size; i+=1)
    {
        Deserialize_GG(babystep, fin); 
        //cout << "i = " << i << " " << babystep << endl;  
        point_to_index_map[ECn_to_String(babystep)] = i;
    }
    fin.close(); 

    #ifdef DEBUG
    cout << "search table load finishes >>>" << endl; 
    #endif 

    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "search table loading takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
} 

Big Preprocessing_Shanks(const ECn g, const ECn h)
{
    Big base = 2; 
    Big giantstep_size = pow(base, RANGE_LEN/2 + tunning, q); 
    Big loop_num  = pow(base, RANGE_LEN/2 - tunning, q); 
    // mip->IOBASE = 10; 
    // cout << "giantstep size = " << giantstep_size << endl; 
    // cout << "loop num = " << loop_num << endl;
    // mip->IOBASE = 16; 
    ECn giantstep = g;
    giantstep *= giantstep_size;

    // begin to search;
    Big i, j; 
    ECn searchpoint = h;    
    for(j = 0; j < loop_num; j+=1)
    {
        // If key not found in map iterator to end is returned 
        if (point_to_index_map.find(ECn_to_String(searchpoint)) == point_to_index_map.end())
        {
            searchpoint -= giantstep; //j = j + 1;  
        }
        else break;
    }
    i = point_to_index_map[ECn_to_String(searchpoint)]; 
    Big x = i + j*giantstep_size; 

    return x; 
}


Big Shanks(const ECn g, const ECn h)
{
    Big base = 2; 

    int tunning = 0; 
    Big giantstep_size = pow(base, RANGE_LEN/2 + tunning, q); 
    Big loop_num  = pow(base, RANGE_LEN/2 - tunning, q); 
        
    // build the hash map
    unordered_map<string, Big> point_to_index_map; 
    ECn babystep = ZeroPoint; // set T = 0
    
    Big i, j; 
    for(i = 0; i < giantstep_size; i+=1)
    {
        point_to_index_map[ECn_to_String(babystep)] = i;
        babystep += g; //i = i + 1; 
    } 
    
    ECn giantstep = g;
    giantstep *= giantstep_size;

    // begin to search;
    ECn searchpoint = h;    
    for(j = 0; j< loop_num;j+=1)
    {
        // If key not found in map iterator to end is returned 
        if (point_to_index_map.find(ECn_to_String(searchpoint)) == point_to_index_map.end())
        {
            //trypoint += giantstep; 
            searchpoint -= giantstep; //j = j + 1;  
        }
        else break;
    }
    i = point_to_index_map[ECn_to_String(searchpoint)]; 
    Big x = i + j*giantstep_size; 

    return x; 
}


/*
    Solve the Discrete Logarithm Problem by Brute Force
*/
Big Brute_Search(ECn g, ECn h)
{
    ECn searchpoint = ZeroPoint;
    Big x = 0;  
    while(searchpoint!=h)
    {
        searchpoint += g; 
        x += 1;  
    } 
    return x; 
}
