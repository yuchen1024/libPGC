/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace std;

const size_t POINT_LEN = 33;
const size_t BN_LEN = 32;  // assume the maximum size of base field and scalar field are less than 2^256

void bn_dec_print(BIGNUM* &a)
{
    char* bn_str = BN_bn2dec(a);
    cout << bn_str << endl;
}

void bn_print(BIGNUM* &a)
{
    char* bn_str = BN_bn2hex(a);
    cout << bn_str << endl;
}

void ep_print(EC_POINT* &A)
{
    char* ep_str = EC_POINT_point2hex(group, A, POINT_CONVERSION_UNCOMPRESSED, NULL);
    cout << ep_str << endl; 
}

// print an EC point
void print_gg(EC_POINT* &A, string name)
{ 
    cout << name << " = "; 
    ep_print(A); 
}

// print a BN number
void print_zz(BIGNUM* &a, string name)
{ 
    cout << name << " = "; 
    bn_print(a); 
}

// print a BN number
void print_dec_zz(BIGNUM* &a, string name)
{ 
    cout << name << " = "; 
    bn_dec_print(a); 
}

// print an ECn vector
void print_vec_gg(vector<EC_POINT*> &vec_g, string name)
{ 
    for (int i = 0; i < vec_g.size(); i++)
    {
        cout << name << "[" << i << "]="; 
        ep_print(vec_g[i]); 
    }
}

// print a ZZ vector
void print_vec_zz(vector<BIGNUM*> &vec_a, string name)
{
    for (int i = 0; i < vec_a.size(); i++)
    {
        cout << name <<"[" << i << "]="; 
        bn_dec_print(vec_a[i]); 
    }
}

void random_zz(BIGNUM* &result)
{
    BN_priv_rand_range(result, order);
} 

void random_gg(EC_POINT* &result)
{
    BIGNUM *r = BN_new(); 
    random_zz(r);  
    EC_POINT_mul(group, result, r, NULL, NULL, bn_ctx);
    BN_free(r);
} 

void random_vec_zz(vector<BIGNUM*> vec_a)
{
    for(int i = 0; i < vec_a.size(); i++) 
        random_zz(vec_a[i]); 
}

void random_vec_gg(vector<EC_POINT*> vec_A)
{
    for(int i = 0; i < vec_A.size(); i++) 
        random_gg(vec_A[i]); 
}

void vec_zz_init(vector<BIGNUM *> &vec_a)
{
    for(int i = 0; i < vec_a.size(); i++){
        vec_a[i] = BN_new(); 
    }
}

void vec_zz_free(vector<BIGNUM*> &vec_a)
{
    for(int i = 0; i < vec_a.size(); i++){
        BN_free(vec_a[i]); 
    }
}

void vec_zz_copy(vector<BIGNUM*> &vec_to, vector<BIGNUM *> &vec_from)
{
    if(vec_to.size() != vec_from.size()){
        throw "size does not match"; 
    }
    else{
    for(int i = 0; i < vec_to.size(); i++){
        BN_copy(vec_to[i], vec_from[i]); 
    }
    }
}

void vec_zz_one(vector<BIGNUM*> &vec_a)
{
    for(int i = 0; i < vec_a.size(); i++){
        BN_one(vec_a[i]); 
    }
}

void vec_gg_copy(vector<EC_POINT*> &vec_to, vector<EC_POINT*> &vec_from)
{
    if(vec_to.size() != vec_from.size()){
        throw "size does not match"; 
    }
    else{
    for(int i = 0; i < vec_to.size(); i++){
        EC_POINT_copy(vec_to[i], vec_from[i]); 
    }
    }
}

void vec_gg_init(vector<EC_POINT *> &vec_A)
{
    for(int i = 0; i < vec_A.size(); i++){
        vec_A[i] = EC_POINT_new(group); 
    }
}

void vec_gg_free(vector<EC_POINT *>& vec_A)
{
    for(int i = 0; i < vec_A.size(); i++){
        EC_POINT_free(vec_A[i]); 
    }
}

void BN_mod_negative(BIGNUM* &a)
{ 
    BN_mod_sub(a, bn_0, a, order, bn_ctx); // return a = -a mod order
} 


// EC_POINT* point_mul(BIGNUM* e)
// {
//     EC_POINT *A = EC_POINT_new(group); 
//     EC_POINT_mul(group, A, e, NULL, NULL, bn_ctx); // return A = g^e
//     return A; 
// } 

// EC_POINT* point_mul(EC_POINT *result, EC_POINT *A, BIGNUM* c)
// {
//     EC_POINT_mul(group, result, NULL, A, c, bn_ctx); // result = A^c
//     return A; 
// } 

// EC_POINT* points_mul(int num, const EC_POINT **h, const BIGNUM** e)
// {
//     EC_POINT *A = EC_POINT_new(group); 
//     EC_POINTs_mul(group, A, NULL, num, h, e, bn_ctx); // return A = h_i^e_i
//     return A; 
// } 

// EC_POINT* point_add(EC_POINT *r, const EC_POINT *a, const EC_POINT *b)
// {
//     EC_POINT_add(group, r, a, b, bn_ctx);
//     return r; 
// }

// BIGNUM* bn_inverse(BIGNUM *a, const BIGNUM *n)
// {
//     BIGNUM *a_inverse = BN_new();
//     BN_mod_inverse(a_inverse, a, n, bn_ctx);
//     return a_inverse;   
// }



// save a compressed ECn element in binary form 
void Serialize_GG(EC_POINT* &A, ofstream& fout)
{
    unsigned char buffer[POINT_LEN];
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char*>(buffer), POINT_LEN); 
}


// recover an ECn element from binary file
void Deserialize_GG(EC_POINT* &A, ifstream& fin)
{
    unsigned char buffer[POINT_LEN];
    fin.read(reinterpret_cast<char*>(buffer), POINT_LEN); 
    EC_POINT_oct2point(group, A, buffer, POINT_LEN, bn_ctx);
}

// save a 32-bytes big number (<2^256) in binary form 
void Serialize_ZZ(BIGNUM* &x, ofstream& fout)
{
    unsigned char buffer[BN_LEN];
    BN_bn2binpad(x, buffer, BN_LEN);
    // write to outfile
    fout.write(reinterpret_cast<char*>(buffer), BN_LEN);  
}


// recover a ZZn element from binary file
void Deserialize_ZZ(BIGNUM* &x, ifstream& fin)
{
    // unsigned char buffer[BN_LEN];
    // fin.read(reinterpret_cast<char*>(buffer), BN_LEN); 
    // BN_bin2bn(buffer, BN_LEN, x);
    char buffer[BN_LEN];
    fin.read(buffer, BN_LEN);
    BN_bin2bn(reinterpret_cast<unsigned char*>(buffer), BN_LEN, x);
}

// save a vector of 32-bytes big number (<2^256) in binary form 
void Serialize_vec_GG(vector<EC_POINT*> &vec_A, ofstream& fout)
{ 
    unsigned char buffer[POINT_LEN];
    for(int i = 0; i < vec_A.size(); i++)
    {
        EC_POINT_point2oct(group, vec_A[i], POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
        // write to outfile
        fout.write(reinterpret_cast<char*>(buffer), POINT_LEN); 
    } 
}

//recover vector<ECn> from binary file, n is the size of vec_A
void Deserialize_vec_GG(vector<EC_POINT*> &vec_A, ifstream &fin)
{   
    unsigned char buffer[POINT_LEN];
    
    for (int i = 0; i < vec_A.size(); i++)
    {  
        fin.read(reinterpret_cast<char*>(buffer), POINT_LEN); 
        EC_POINT_oct2point(group, vec_A[i], buffer, POINT_LEN, bn_ctx); 
    }
}


int EC_POINT_sub(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b)
{
    EC_POINT* temp_ep = EC_POINT_new(group);
    EC_POINT_copy(temp_ep, b);  
    EC_POINT_invert(group, temp_ep, bn_ctx);
    return EC_POINT_add(group, r, a, temp_ep, bn_ctx);
}

inline bool file_exist(const string& name)
{
    bool existing_flag; 
    ifstream fin; 
    fin.open(name);
    if(!fin)  existing_flag = false;    
    else existing_flag = true;
    return existing_flag; 
}

string EC_POINT_ep2string(EC_POINT* &A)
{
    unsigned char buffer[POINT_LEN] = "";
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    string str(reinterpret_cast<char*>(buffer), POINT_LEN); 
    return str; 
}

string BN_bn2string(BIGNUM* &a)
{
    unsigned char buffer[BN_LEN] = "";
    BN_bn2binpad(a, buffer, BN_LEN);
    string str(reinterpret_cast<char*>(buffer), BN_LEN); 
    return str; 
}
