/**************************************************************************** 
this hpp sets the global parameters 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

//#pragma once

#include <iostream>
#include <fstream>
#include "ecn.h"
#include "zzn.h"

Miracl precision(50, MAXBASE);
miracl *mip;
Big p;                 // scalar field is p 
Big coeff_a; 
Big coeff_b;           // EC curve: y^2 = x^3 + coeff_a x + coeff_b over Fp with prime order q
Big q;                 // base field is q 
ECn BasePoint;         // random group elements (also generators)
ECn ZeroPoint; 

long seed;  // random seed

bool global_setting(string ecc_file)
{
    mip = &precision;
    mip->IOBASE=16;

/* load public parameters */
    ifstream fin; 
    fin.open(ecc_file);
    if(!fin){
        throw "cannot open the ecc file!"; 
    }  
    Big x, y; 
    fin >> p >> coeff_a >> coeff_b >> q >> x >> y; 
    fin.close();
    ecurve(coeff_a, coeff_b, p, MR_PROJECTIVE);
    BasePoint = ECn(x, y); 
    ZeroPoint = BasePoint; 
    ZeroPoint-= ZeroPoint; // set ZeroPoint as the infinity point

    seed = time(NULL); // initialize the seed with current system time
    irand(seed); // set the seed for irand function
    
    return true;
}




