# safeheron-crypto-suites-cpp

![img](doc/logo.png)

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [GoogleTest](https://github.com/google/googletest). You need it to compile and run test cases. See the [GoogleTest Installation Instructions](./doc/GoogleTest-Installation.md)

# Introduction


SafeheronCryptoSuites is a foundational cryptographic library developed by Safeheron that covers multiple cryptographic algorithms and primitives, including the following modules:

- crypto-bn: Provides object-oriented big integer algorithms, supporting modular arithmetic, GCD calculation, primality testing, prime generation, bit manipulation, Jacobi symbol calculation, and other number theory algorithms.
- crypto-curve: Provides a unified abstraction interface for elliptic curve, widely used in elliptic curve cryptography.
  - Supports short elliptic curves such as Secp256k1, P256(Secp256r1), and STARK curves.
  - Supports Edwards curves such as Ed25519 curve.
   
- crypto-commitment: Provides various commitment schemes.
- crypto-hash: Supports multiple hashing algorithms, such as SHA1, SHA256, SHA512, RIPEMD160, Hash160, Hash256, HMAC_SHA256, HMAC_SHA512, and ChaCha20.
- crypto-encode: Provides encoding and decoding interfaces for HEX, Base58, and Base64.
- crypto-paillier: Implements the Paillier's encryption scheme.
- crypto-sss: Implements secret sharing schemes.
- crypto-zkp: Provides various zero-knowledge protocols.
- crypto-bip32: Supports the BIP32 standard, including BIP32-Secp256k1 and BIP32-Ed25519.
- crypto-bip39: Implements BIP39.
- crypto-ecies: Implements the Elliptic Curve Integrated Encryption Scheme (ECIES) based on IEEE 1363, a standardization project for public-key cryptography by the IEEE.

# Build and Install

This project supports Linux and macOS by default, and also provides build support for Android, iOS, and WebAssembly (WASM) platforms. 
In addition, it supports the Intel SGX trusted computing platform.

Note: For Android, iOS, and WASM, you must first cross-compile compatible versions of OpenSSL and Protobuf as dependencies.

## Clone the Repository

```shell
# Clone with submodules
git clone --recurse-submodules https://github.com/safeheron/safeheron-crypto-suites-cpp.git
cd safeheron-crypto-suites-cpp
```

## Build for Default Platform (non-SGX)
```shell
mkdir build && cd build
cmake .. -DENABLE_TESTS=ON
make -j
make test
sudo make install
```

## Build for SGX Platform
```shell
mkdir build-sgx && cd build-sgx
cmake .. -DPLATFORM=SGX
make -j
sudo make install
```

# To start using safeheron-crypto-suites-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build safeheron-crypto-suites-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(MyProject)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(CryptoSuites REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSuites
        pthread )
```

# Security Audit
Some sub-libs originate from an internal repository by Safeheron and were audited by Kudelski Security in December 2021.

We asked LeastAuthority to conduct an audit of our library in the second half of 2023, and this is [the audit report](doc/Safeheron_Crypto_Suites__Multiparty_ECDSA_Updated_Final_Audit_Report_Least_Authority.pdf) which can be found in [LeastAuthority website](https://leastauthority.com/wp-content/uploads/2024/02/Safeheron_Crypto_Suites__Multiparty_ECDSA_Updated_Final_Audit_Report_Least_Authority.pdf).

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.


