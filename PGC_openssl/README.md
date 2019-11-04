## Specifications

- OS: Linux x64, MAC OS x64

- Language: C++

- Requires: OpenSSL

- The default elliptic curve is "NID_X9_62_prime256v1"


## Installation

The current implementation is based on OpenSSL library. See the installment instructions of OpenSSL as below:  

1. Download [openssl-master.zip](https://github.com/openssl/openssl.git)

2. make a directory "openssl" to save the source codes of MIRACL

```
    mkdir openssl
    mv openssl-master.zip /openssl
```

3. unzip it

4. install openssl on your machine

```
    ./config --prefix=/usr/local/ssl shared
    make 
    sudo make install
```