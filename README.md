# safeheron-crypto-suites-cpp

![img](doc/logo.png)

# Prerequisites

- [GoogleTest](https://github.com/google/googletest). You need it to compile and run test cases. See the [GoogleTest Installation Instructions](./doc/GoogleTest-Installation.md)
- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)


# Introduction

SafeheronCryptoSuites is an assembly of all the basic libraries and cryptography protocols from Safeheron, which contains:

- [crypto-bn-cpp](https://github.com/Safeheron/crypto-bn-cpp): It provides an implementation of C++ big integer. Additionally, it provides operations for modular arithmetic, GCD calculation, primality testing, prime generation, bit manipulation, jacobi symbol calculation, and a few other miscellaneous operations.
- [crypto-curve-cpp](https://github.com/Safeheron/crypto-curve-cpp). It provides a uniform abstract for elliptic curves based cryptography (ECC).
  - It contains an extremely simple mathematical interface to onboard new elliptic curves. Use this library for general purpose elliptic curve cryptography.
  - It provides interfaces on ecdsa to Sepcp256k1 and P256.
  - It provides interfaces on eddsa to ed25519.

- [crypto-commitment-cpp](https://github.com/Safeheron/crypto-commitment-cpp). It provides several commitment schemes.
- [crypto-hash-cpp](https://github.com/Safeheron/crypto-hash-cpp). It provides several hash algorithms such as sha1, sha256, sha512, ripemd160, hash160, hash256, hmac_sha256, hmac_sha512 and chacha20.
- [crypto-encode-cpp](https://github.com/Safeheron/crypto-encode-cpp). It provides encoding interfaces for hex, base58 and base64.
- [crypto-paillier-cpp](https://github.com/Safeheron/crypto-paillier-cpp). It provides an implementation of  Paillier's crypto scheme.
- [crypto-sss-cpp](https://github.com/Safeheron/crypto-sss-cpp). It provides secret sharing schemes.

- [crypto-zkp-cpp](https://github.com/Safeheron/crypto-zkp-cpp). It provides several zero knowledge protocols.

- [crypto-bip32-cpp](https://github.com/Safeheron/crypto-bip32-cpp). It provides a BIP32 compatible library which supports bip32-secp256k1 and bip32-ed25519.
- [crypto-bip39-cpp](https://github.com/Safeheron/crypto-bip39-cpp). It provides an implementation of BIP39.
 
- [crypto-ecies-cpp](https://github.com/Safeheron/crypto-ecies-cpp). It provides an implementation of Elliptic Curve Integrated Encryption Scheme according to IEEE 1363 which is an Institute of Electrical and Electronics Engineers (IEEE) standardization project for public-key cryptography.


# Important Update in Module "crypto-bn-cpp"

The input of the random number generator changes from "bytes" to "bits".

- The new generators:
```c++
safeheron::bignum::BN RandomBN(size_t bits);
safeheron::bignum::BN RandomBNStrict(size_t bits);
safeheron::bignum::BN RandomPrime(size_t bits);
safeheron::bignum::BN RandomPrimeStrict(size_t bits);
safeheron::bignum::BN RandomSafePrime(size_t bits);
safeheron::bignum::BN RandomSafePrimeStrict(size_t bits);
```

- The old generators:
```c++
safeheron::bignum::BN RandomBN(size_t byteSize);
safeheron::bignum::BN RandomBNStrict(size_t byteSize);
safeheron::bignum::BN RandomPrime(size_t byteSize);
safeheron::bignum::BN RandomPrimeStrict(size_t byteSize);
safeheron::bignum::BN RandomSafePrime(size_t byteSize);
safeheron::bignum::BN RandomSafePrimeStrict(size_t byteSize);
```


**Along with the update, all the usage should update too, otherwise there is a risk.**.

For example, we used to get a 256-bits number like this before:
```c++
    BN r = safeheron::bignum::BN RandomBN(256 / 8);
```
Now we must invoke the generator like this:
```c++
    BN r = safeheron::bignum::BN RandomBN(256);
```
**If usage don't update then you will get a small number with 32-bits length, and then it could easily be guessed out by the adversary.**




# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
# Pass --recurse-submodules to the git clone command, and it will automatically initialize and update each submodule in the repository, including nested submodules if any of the submodules in the repository have submodules themselves.
git clone --recurse-submodules https://github.com/safeheron/safeheron-crypto-suites-cpp.git
cd safeheron-crypto-suites-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL  -DENABLE_TESTS=ON" instead of the command below on Mac OS.
cmake ..  -DENABLE_TESTS=ON
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.

# To start using safeheron-crypto-suites-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build safeheron-crypto-suites-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoSuites REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoSuites_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSuites
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

# Some Examples

## Big Number(Calculate Jacobi Symbol)

```c++
#include "crypto-bn/bn.h"

using safeheron::bignum::BN;

int main(){
    // (1001, 9907) = -1
    BN k(1001);
    BN n(9907);
    EXPECT_TRUE(BN::JacobiSymbol(k, n) == -1);

    // (19, 45) = 1
    k = BN(19);
    n = BN(45);
    EXPECT_TRUE(BN::JacobiSymbol(k, n) == 1);

    // (8, 21) = -1
    k = BN(8);
    n = BN(21);
    EXPECT_TRUE(BN::JacobiSymbol(k, n) == -1);

    // (5, 21) = 1
    k = BN(5);
    n = BN(21);
    EXPECT_TRUE(BN::JacobiSymbol(k, n) == 1);
}
```

## Operations on Curve

```c++
#include "crypto-curve/bn.h"
#include "crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

int main(){
    // p0 = g^10
    CurvePoint p0(BN("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f", 16),
                         BN("878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773", 16),
                         CurveType::P256);
    // p1 = g^100
    CurvePoint p1(BN("490a19531f168d5c3a5ae6100839bb2d1d920d78e6aeac3f7da81966c0f72170", 16),
                         BN("bbcd2f21db581bd5150313a57cfa2d9debe20d9f460117b588fcf9b0f4377794", 16),
                         CurveType::P256);
    // p2 = g^1000
    CurvePoint p2(BN("b8fa1a4acbd900b788ff1f8524ccfff1dd2a3d6c917e4009af604fbd406db702", 16),
                         BN("9a5cc32d14fc837266844527481f7f06cb4fb34733b24ca92e861f72cc7cae37", 16),
                         CurveType::P256);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::P256);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::P256);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);

    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::P256);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::P256);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);
    
    return 0;
}
```

## A Non-interactive proof of correct paillier keypair generation
```c++
using safeheron::zkp::pail::PailProof;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using safeheron::pail::CreatePailPubKey;

PailPubKey pail_pub;
PailPrivKey pail_priv;
CreateKeyPair2048(pail_priv, pail_pub);

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
BN r = RandomBNLt(curv->n);
CurvePoint point = curv->g * r;
BN index = RandomBNLtGcd(curv->n);

PailProof proof;
proof.Prove(pail_priv, index, point.x(), point.y());
ASSERT_TRUE(proof.Verify(pail_pub, index, point.x(), point.y()));
```

# Security Audit
Some sub-libs originate from the repository "Safeheron/mpc-dsa-lib", an internal project developed by Safeheron and was audited by Kudelski Security in December 2021.

Lots of changes after the audit, use at your own risk.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.


