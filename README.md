# libPGC: a C++ library for Pretty Good Confidential Transaction System

This library implements PGC, a **transparent** confidential transaction system with **accountability**, 
whose security relies only on *discrete logarithm problem* (https://eprint.iacr.org/2019/319).

<font color =red>**WARNING:**</font> 
This library provides two implementations in C++, one is based on MIRACL, the other one is based on OpenSSL.  
The one based on MIRACL is easy to follow but a bit slow. 
(A brand new version of MIRACL will come soon. Looking forward to it.)
The one based on OpenSSL is fast but hard to follow (due to the syntax and design of OpenSSL). 
Compared to the MIRACL-version, the OpenSSL version also incorporates many refinements,  
such as correct design of hash functions, faster implementation of DLP algorithm etc.
Note that both of them are only academic proof-of-concept prototype, 
and in particular have not received careful code review, thus they are NOT ready for production use.


## Code Structure

- common module (/common)
  * global.hpp: generate global parameters

- depends module (/depends)
  * print.hpp: print split line for demo use
  * hash.hpp: case-tailored hash functions based on SHA2
  * routines.hpp: related routine algorithms
  * MIRACL library or OpenSSL library

- PKE module (/twisted_elgamal)
  * twisted_elgamal.hpp: twisted ElGamal PKE  
  * calculate_dlog.hpp: discrete logarithm searching algorithm

- NIZK module (/nizk) 
  * nizk_pt_equality.hpp: NIZKPoK for twisted ElGamal plaintext equality
  * nizk_ct_validity.hpp: NIZKPoK for twisted ElGamal ciphertext validity
  * nizk_dlog_equality.hpp: NIZKPoK for discrete logarithm equality
  
  all the NIZKPoK protocols are obtained by applying Fiat-Shamir transform to Sigma-protocols 

- Bulletproofs module (/bulletproofs)
  * basic_bulletproof.hpp: the basic bulletproofs
  * log_bulletproof.hpp: the logarithmic size bulletproofs
  * aggregate_bulletproof.hpp: the aggregating logarithmic size bulletproofs
  * innerproduct_proof.hpp: the inner product argument (used by Bulletproof to shrink the proof size) 

- <font color=blue>**PGC module (/PGC)**</font> (relies on the above modules)
  * PGC.hpp: the PGC system


## Testing

In each module, there exists unit test. For example, in twisted_elgamal module, 
to run the test of twisted ElGamal PKE, do the following:

```
  $ ./make_twisted_elgamal.sh
  $ ./test_enc # tests the twisted ElGamal PKE
```

## Demo with Test Cases

set the range size = $[0, 2^\ell = 2^{32}-1 = 4294967295]$

### Flow of PGC_Demo

   1. run <font color=blue>Setup:</font> to build up the system, generating system-wide parameters and store them in "common.para"
   2. run <font color=blue>Create_Account</font> to create accounts for Alice ($m_1$) and Bob ($m_2$); 
      one can reveal the balance by running <font color=blue>Reveal_Balance:</font> 
   3. Alice runs <font color=blue>Create_CTx</font> to transfer $v_1$ coins to Bob ===> nonce.ctx; 
      <font color=blue>Print_CTx:</font> shows the details of CTx
   4. Miners runs <font color=blue>Verify_CTx:</font> check CTx validity
   5. If CTx is valid, run <font color=blue>Update_Account</font> to Update Alice and Bob's account balance
   6. Either Alice or Bob can reveal the transfer amount of related CTx in dispute by running <font color=blue>Testify_CTx</font>
   7. Anyone can check if the transfer amount is correct by running <font color=blue>Check_CTx</font>


### Test Cases

1. Valid CTx and Correct Justification: <font color=blue>$v_1 = v_2 \wedge v_1 \in [0, \ell] \wedge (m_1 - v_1) \in [0, \ell]$</font>
   - $m_1  = 512$ --- Alice's initial balance  
   - $m_2  = 256$ --- Bob's initial balance    
   - $v_1  = 128$ --- out transfer amount      
   - $v_2  = 128$ --- in transfer amount       
   - $v_1' = 128$ --- amount claimed by Alice  
   - $v_2' = 128$ --- amount claimed by Bob    



2. Invalid CTx: <font color=red>$v_1 \neq v_2$ $\Rightarrow$ plaintext equality proof will be rejected</font>
   - $m_1  = 512$ --- Alice's initial balance  
   - $m_2  = 256$ --- Bob's initial balance    
   - $v_1  = 128$ --- out transfer amount      
   - $v_2 \neq v_1$ --- in transfer amount       
   - $v_1' = 128$ --- amount claimed by Alice  
   - $v_2' = 128$ --- amount claimed by Bob 



3. Invalid CTx: <font color=red>$v_1 \notin [0, 2^\ell]$ $\Rightarrow$ range proof for right interval will be rejected</font>
   - $m_1  = 4294967297$ --- Alice's initial balance  
   - $m_2  = 12345$ --- Bob's initial balance    
   - $v_1  = 4294967296$ --- out transfer amount      
   - $v_2  = 4294967296$ --- in transfer amount       
   - $v_1' = 4294967296$ --- amount claimed by Alice  
   - $v_2' = 4294967296$ --- amount claimed by Bob 



4. Invalid CTx: <font color=red>$(m_1 - v_1) \notin [0, 2^\ell]$ $\Rightarrow$ range proof for enough balance 
   will be rejected</font>
   - $m_1  = 512$ --- Alice's initial balance  
   - $m_2  = 256$ --- Bob's initial balance    
   - $v_1  = 513$ --- out transfer amount      
   - $v_2  = 513$ --- in transfer amount       
   - $v_1' = 513$ --- amount claimed by Alice  
   - $v_2' = 513$ --- amount claimed by Bob 


5. Wrong Justification: <font color=red>$v_2 \neq v_2'$ $\Rightarrow$ Bob's account proof will be rejected</font>
   - $m_1  = 512$ --- Alice's initial balance  
   - $m_2  = 256$ --- Bob's initial balance    
   - $v_1  = 512$ --- out transfer amount      
   - $v_2  = 512$ --- in transfer amount       
   - $v_1' = 512$ --- amount claimed by Alice  
   - $v_2' = 511$ --- amount claimed by Bob 

## License

This library is licensed under the [MIT License](LICENSE).

