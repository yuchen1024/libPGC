# libPGC: a C++ library for Pretty Good Confidential Transaction System

This library implements PGC, a **transparent** confidential transaction system with **accountability**, whose security relies only on *discrete logarithm problem* (https://eprint.iacr.org/2019/319).

<font color =red>**WARNING:**</font> 
This library provides two implementations in C++, one is based on MIRACL, the other one is based on OpenSSL. The one based on MIRACL is easy to follow but a bit slow. (A brand new version of MIRACL will come soon. Looking forward to it.) The one based on OpenSSL is fast but hard to follow (due to the syntax and design of OpenSSL). Compared to the MIRACL-version, the OpenSSL version also incorporates many refinements, such as correct design of hash functions, faster implementation of DLP algorithm etc. Note that both of them are only academic proof-of-concept prototype, and in particular have not received careful code review or being fully optimized, thus they are NOT ready for production use.

---

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


- NIZK module (/nizk): obtained by applying Fiat-Shamir transform to Sigma-protocols  
  * nizk_plaintext_equality.hpp: NIZKPoK for twisted ElGamal plaintext equality
  * nizk_plaintext_knowledge.hpp: NIZKPoK for twisted ElGamal plaintext and randomness knowledge
  * nizk_dlog_equality.hpp: NIZKPoK for discrete logarithm equality


- Bulletproofs module (/bulletproofs)
  * basic_bulletproof.hpp: the basic bulletproofs
  * log_bulletproof.hpp: the logarithmic size bulletproofs
  * aggregate_bulletproof.hpp: the aggregating logarithmic size bulletproofs
  * innerproduct_proof.hpp: the inner product argument (used by Bulletproof to shrink the proof size) 


- Gadget module (/gadgets)
  * gadgets.hpp: two useful gadgets for proving encrypted values lie in the right range


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
   3. Alice runs <font color=blue>Create_CTx</font> to transfer $v_1$ coins to Bob ===> Alice_sn.ctx; 
      <font color=blue>Print_CTx:</font> shows the details of CTx
   4. Miners runs <font color=blue>Verify_CTx:</font> check CTx validity
   5. If CTx is valid, run <font color=blue>Update_Account</font> to Update Alice and Bob's account balance and serialize the changes.

### Support to Auditing Polices

   * Selective opne policy: either Alice or Bob can reveal the transfer amount of related CTx in dispute by running <font color=blue>Justify_open_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_open_policy</font>. 
   
   * Anti-money laundering policy: sender can prove the transfer amount sum of a collection of ctx sent from him does not exceed a give limit by running <font color=blue>Justify_limit_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_limit_policy</font>. 

   * Tax policy: user can prove he paid the incoming tax according to the rules by running <font color=blue>Justify_tax_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_tax_policy</font>. 



### Test Cases
---
Create PGC environment

1. setup the PGC system


2. generate three accounts: Alice, Bob and Tax
   * $512$ --- Alice's initial balance  
   * $256$ --- Bob's initial balance    
   * $0$   --- Tax's initial balance


3. serialize pp and three accounts

---
Test basic transactions among Alice, Bob and Tax

0. deserialize pp and three accounts


1. 1st Valid CTx: <font color=blue>$v_1 = v_2 \wedge v_1 \in [0, \ell] \wedge (m_1 - v_1) \in [0, \ell]$</font>
   - $v    = 128$ --- transfer amount from Alice to Bob
   - $384$ --- Alice's updated balance  
   - $384$ --- Bob's updated balance    
   - $0$   --- Tax's updated balance


2. Invalid CTx: <font color=red>$v_1 \neq v_2$ $\Rightarrow$ plaintext equality proof will be rejected</font>  
   - $v_1 \neq v_2$ --- in transfer amount


3. Invalid CTx: <font color=red>$v \notin [0, 2^\ell]$ $\Rightarrow$ range proof for right interval will be rejected</font>
   - $v  = 4294967296$ --- transfer amount      


4. Invalid CTx: <font color=red>$(m_1 - v) \notin [0, 2^\ell]$ $\Rightarrow$ range proof for solvent 
   will be rejected</font>
   - $m_1  = 384$ --- Alice's updated balance  
   - $v  = 385$ --- transfer amount 


5. 2nd Valid CTx: <font color=blue>$v_1 = v_2 \wedge v_1 \in [0, \ell] \wedge (m_1 - v_1) \in [0, \ell]$</font>
   - $v    = 32$ --- transfer amount from Bob to Alice
   - $384$ --- Alice's updated balance  
   - $352$ --- Bob's updated balance    
   - $32$   --- Tax's updated balance


6. 3st Valid CTx: <font color=blue>$v_1 = v_2 \wedge v_1 \in [0, \ell] \wedge (m_1 - v_1) \in [0, \ell]$</font>
   - $v    = 384$ --- transfer amount from Alice to Bob
   - $0$ --- Alice's updated balance  
   - $736$ --- Bob's updated balance    
   - $32$   --- Tax's updated balance

---
Test auditing policies

1. Open policy: for ctx1
   - $v_1  = 128$ --- Alice's claim (correct)  
   - $v_2  = 127$ --- Bob's claim (false)  


2. Tax policy: for ctx1 and ctx2
   - tax rate is 1/4 --- Bob's claim (correct)


3. Limit policy: for ctx1 and ctx3
   - limit is 511 --- Alice's claim (false) 
   - limit is 512 --- Alice's claim (correct)      

---

## License

This library is licensed under the [MIT License](LICENSE).

