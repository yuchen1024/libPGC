/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __PRINT__
#define __PRINT__

#include "global.hpp"

const size_t LINE_LEN = 120;     // the length of split line

/* print split line */
void SplitLine_print(char ch)
{
    for (auto i = 0; i < LINE_LEN; i++) cout << ch;  
    cout << endl;
}

void BN_print_dec(BIGNUM *&a)
{
    char *bn_str = BN_bn2dec(a);
    cout << bn_str << endl;
}

void BN_print_dec(BIGNUM *&a, string note)
{
    cout << note << " = "; 
    char *bn_str = BN_bn2dec(a);
    cout << bn_str << endl;
}

void BN_print(BIGNUM *&a)
{
    char *bn_str = BN_bn2hex(a);
    cout << bn_str << endl;
}

// print a BN number with note
void BN_print(BIGNUM *&a, string note)
{ 
    cout << note << " = "; 
    char *bn_str = BN_bn2hex(a);
    cout << bn_str << endl; 
}

void ECP_print(EC_POINT *&A)
{
    char *ecp_str = EC_POINT_point2hex(group, A, POINT_CONVERSION_UNCOMPRESSED, NULL);
    cout << ecp_str << endl; 
}

// print an EC point with note
void ECP_print(EC_POINT *&A, string note)
{ 
    cout << note << " = "; 
    char *ecp_str = EC_POINT_point2hex(group, A, POINT_CONVERSION_UNCOMPRESSED, NULL);
    cout << ecp_str << endl; 
}

// print an EC Point vector
void ECP_vec_print(vector<EC_POINT *> &vec_A, string name)
{ 
    for (auto i = 0; i < vec_A.size(); i++)
    {
        cout << name << "[" << i << "]="; 
        ECP_print(vec_A[i]); 
    }
}

// print a Big Number vector
void BN_vec_print(vector<BIGNUM *> &vec_a, string name)
{
    for (auto i = 0; i < vec_a.size(); i++)
    {
        cout << name <<"[" << i << "]="; 
        BN_print(vec_a[i]); 
    }
}

#endif