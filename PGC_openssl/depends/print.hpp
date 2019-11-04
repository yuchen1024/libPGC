/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include <iostream>

using namespace std;

const size_t LINE_LEN = 120;     // the length of split line

/*
    print split line
*/
void Print_Splitline(char ch)
{
    for (size_t i = 0; i < LINE_LEN; i++) cout << ch;  
    cout << endl;
}