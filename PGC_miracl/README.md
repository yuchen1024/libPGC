## Specifications

- OS: Linux x64, MAC OS x64

- Language: C++

- Requires: MIRACL

- The default elliptic curve is "secp256k1.esc"


## Installation

The current implementation is based on MIRACL library. See the installment instructions of MIRACL as below:  

1. Download [MIRACL-master.zip](https://github.com/miracl/MIRACL/archive/master.zip "With a Title")

2. make a directory MIRACL to save the source codes of MIRACL

```
    mkdir MIRACL
    mv MIRACL-master.zip /MIRACL
```

3. unzip in a flatten manner 

```
    unzip -j -aa -L MIRACL-master.zip`
```

4. install MIRACL on your machine

```
    bash linux64
```

5. run pk-demo to test if MIRACL installs successfully. (this is a simple Diffie–Hellman key exchange protocol) 

```
    ./pk-demo
```