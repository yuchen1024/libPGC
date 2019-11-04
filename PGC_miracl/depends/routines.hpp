/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <vector>
#include "ecn.h"
#include "zzn.h"

const int LINE_LEN = 80; // the length of split line
const int NUM_LEN = 32;   // assume the maximum size of base field and scalar field are less than 2^256

Big random_zz()
{
    // long seed; 
    // seed = time(NULL); // initialize the seed with current system time
    // irand(seed); // set the seed for irand function
    Big r = rand(q);
    return r;  
}

ECn random_gg()
{
    Big r = random_zz();  
    ECn G = BasePoint;  
    G *= r; 
    return G; 
}

ECn random_generator()
{
    sampling: Big r = random_zz();
    if (r==0) goto sampling;   
    ECn G = BasePoint;  
    G *= r; 
    return G; 
}

/*
    print split line
*/
void Print_Splitline(char ch)
{
    int i; 
    for (i = 0; i < LINE_LEN; i++) cout << ch;  
    cout << endl;
}

// save a compressed ECn element in binary form 
void Serialize_GG(const ECn A, ofstream& fout)
{
    Big x, y_lsb;  
    char x_array[NUM_LEN];
    char lsb_array[1];   

    int lsb = A.get(x); 
    to_binary(x, NUM_LEN, x_array, TRUE);   
    fout.write(x_array, NUM_LEN); // store the x coordinate in binary form   

    if (lsb == 0) y_lsb = 0; 
    else y_lsb = 1; 
    to_binary(y_lsb, 1, lsb_array, TRUE);   
    fout.write(lsb_array, 1);     // store the lsb of y in binary form
}


// recover an ECn element from binary file
void Deserialize_GG(ECn& A, ifstream& fin)
{
    Big x, y_lsb;  
    int lsb; 
    char x_array[NUM_LEN];
    char lsb_array[1];  
    fin.read(x_array, NUM_LEN);  
    x = from_binary(NUM_LEN, x_array);
    
    fin.read(lsb_array, 1);
    y_lsb = from_binary(1, lsb_array);
    if (y_lsb == 1) lsb = 1; 
    else lsb = 0;  

    /*  
        possibly a bug
        if A is not a zero point already, then even x = 0 and lsb = 0
        A will not be set as infinity, but (0, 0)
    */
    if (x == 0 && lsb == 0) A = ZeroPoint;
    else A.set(x, lsb); 
    //A.set(x, lsb); 
}

// save a 32-bytes big number (<2^256) in binary form 
void Serialize_ZZ(Big x, ofstream& fout)
{
    //mip->IOBASE=16;
    x = (x+q)%q; 
    char x_array[NUM_LEN];
    to_binary(x, NUM_LEN, x_array, TRUE);
    fout.write(x_array, NUM_LEN);  
    //cout << "(serialize) x=" << x << endl;  
}


// recover a ZZn element from binary file
void Deserialize_ZZ(Big& x, ifstream& fin)
{
    //mip->IOBASE=16;
    char x_array[NUM_LEN]; 
    fin.read(x_array, NUM_LEN);  
    x = from_binary(NUM_LEN, x_array); 
    //cout << "(deserialize) x=" << x << endl;  
}

// save a vector of 32-bytes big number (<2^256) in binary form 
void Serialize_vec_GG(const vector<ECn> vec_A, ofstream& fout)
{ 
    Big x, y_lsb;
    int lsb;  
    char x_array[NUM_LEN];  
    char lsb_array[1]; 

    int n = vec_A.size(); 
    fout << n; 
    //cout << "(serialize) n = " << n << endl; 

    for(int i = 0; i < n; i++)
    {
        lsb = vec_A[i].get(x);
        
        to_binary(x, NUM_LEN, x_array, TRUE); 
        fout.write(x_array, NUM_LEN);  // store the x coordinate in binary form   
        
        if (lsb == 0) y_lsb = 0; 
        else y_lsb = 1; 
        to_binary(y_lsb, 1, lsb_array, TRUE);   
        fout.write(lsb_array, 1);  // store the lsb of y in binary form
    } 
}

//recover vector<ECn> from binary file, n is the size of vec_A
void Deserialize_vec_GG(vector<ECn>& vec_A, ifstream &fin)
{   
    Big x, y_lsb;
    int lsb;  
    char x_array[NUM_LEN];
    char lsb_array[1];    

    int n; 
    fin >> n; 
    vec_A.resize(n); 
    //cout << "(deserialize) n = " << n << endl; 
    for (int i = 0; i < n; i++)
    {  
        fin.read(x_array, NUM_LEN);
        x = from_binary(NUM_LEN, x_array); 

        fin.read(lsb_array, 1);  
        y_lsb = from_binary(1, lsb_array);
        
        if (y_lsb == 0) lsb = 0; 
        else lsb = 1;  
        
        //vec_A[i].set(x, lsb);  
        if (x == 0 && lsb == 0) vec_A[i] = ZeroPoint;
        else vec_A[i].set(x, lsb);   
    }
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
