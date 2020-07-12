# libPGC: a C++ library for Pretty Good Confidential Transaction System

This library implements PGC, a **transparent** confidential transaction system with **accountability**, whose security relies only on *discrete logarithm problem* (https://eprint.iacr.org/2019/319).

<font color =red>**WARNING:**</font> 
This library provides two implementations in C++, one is based on MIRACL, the other one is based on OpenSSL. The one based on MIRACL is easy to follow but a bit slow. (A brand new version of MIRACL will come soon. Looking forward to it.) The one based on OpenSSL is fast but hard to follow (due to the syntax and design of OpenSSL). Compared to the MIRACL-version, the OpenSSL version also incorporates many refinements, such as correct design of hash functions, faster implementation of DLP algorithm etc. Note that both of them are only academic proof-of-concept prototype, and in particular have not received careful code review or being fully optimized, thus they are NOT ready for production use.

---

## License

This library is licensed under the [MIT License](LICENSE).

