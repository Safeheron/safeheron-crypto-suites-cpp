# crypto-zkp-cpp

![img](doc/logo.png)

This software implements a library for several zero knowledge protocols.

The library comes with serialize/deserialize support to be used in higher level code to implement networking.

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [GoogleTest](https://github.com/google/googletest). **You need it to compile and run test cases**. See the [GoogleTest Installation Instructions](./doc/GoogleTest-Installation.md)
- [crypto-bn-cpp](https://github.com/safeheron/crypto-bn-cpp.git). See the [crypto-bn-cpp Installation Instructions](https://github.com/safeheron/crypto-bn-cpp/blob/main/README.md#build-and-install)
- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
- [crypto-encode-cpp](https://github.com/safeheron/crypto-encode-cpp.git). See the [crypto-encode-cpp Installation Instructions](https://github.com/safeheron/crypto-encode-cpp/blob/main/README.md#build-and-install)
- [crypto-curve-cpp](https://github.com/safeheron/crypto-curve-cpp.git). See the [crypto-curve-cpp Installation Instructions](https://github.com/safeheron/crypto-curve-cpp/blob/main/README.md#build-and-install)
- [crypto-paillier-cpp](https://github.com/safeheron/crypto-paillier-cpp.git). See the [crypto-paillier-cpp Installation Instructions](https://github.com/safeheron/crypto-paillier-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-zkp-cpp.git
cd crypto-zkp-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test # If you set ENABLE_TESTS ON
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-sss-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-zkp-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoZKP REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoZKP_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoZKP
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

# Usage
## A Schnorr Proof
```c++
using safeheron::zkp::dlog::DLogProof;

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
BN r = RandomBNLt(curv->n);
BN sk = RandomBNLt(curv->n);
DLogProof proof(CurveType::SECP256K1);
proof.ProveWithR(sk, r);
EXPECT_TRUE(proof.Verify());
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

## A proof of strong RSA modulus
```c++
int PRIME_BYTE_LEN = 1024 / 8;
BN P = RandomSafePrime(PRIME_BYTE_LEN);
BN Q = RandomSafePrime(PRIME_BYTE_LEN);
BN N_tilde = P * Q;

BN p = (P-1)/2;
BN q = (Q-1)/2;
BN pq = p * q;
BN f = RandomBNLtGcd(N_tilde);
BN alpha = RandomBNLtGcd(N_tilde);
BN beta = alpha.InvM(pq);

BN h1 = ( f * f ) % N_tilde;
BN h2 = h1.PowM(alpha, N_tilde);

dln_proof::DLNProof dln_proof;
dln_proof.Prove(N_tilde, h1, h2, p, q , alpha);
ASSERT_TRUE(dln_proof.Verify(N_tilde, h1, h2));
```

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
