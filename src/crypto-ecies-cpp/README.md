# crypto-ecies-cpp
ECIES is a public-key authenticated encryption scheme, which uses a KDF (key-derivation function) for deriving separate MAC key and symmetric encryption key from the ECDH shared secret. 

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./Protocol-Buffers-Installation.md)
- [crypto-bn-cpp](https://github.com/safeheron/crypto-bn-cpp.git). See the [crypto-bn-cpp Installation Instructions](https://github.com/safeheron/crypto-bn-cpp/blob/main/README.md#build-and-install)
- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
- [crypto-encode-cpp](https://github.com/safeheron/crypto-encode-cpp.git). See the [crypto-encode-cpp Installation Instructions](https://github.com/safeheron/crypto-encode-cpp/blob/main/README.md#build-and-install)
- [crypto-curve-cpp](https://github.com/safeheron/crypto-curve-cpp.git). See the [crypto-curve-cpp Installation Instructions](https://github.com/safeheron/crypto-curve-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-ecies-cpp.git
cd crypto-ecies-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
cmake ..
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-ecies-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-ecies-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
find_package(CryptoECIES REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PUBLIC
        ${OPENSSL_INCLUDE_DIR}
        ${CryptoECIES_INCLUDE_DIRS}
        /usr/local/include # for Mac os
)

target_link_directories(example PUBLIC /usr/local/lib) # for Mac os
target_link_libraries(example PUBLIC
        CryptoECIES
        OpenSSL::Crypto
        pthread )
```

## Example

```c++
#include <cstring>
#include "crypto-bn/rand.h"
#include "crypto-curve/curve.h"
#include "crypto-encode/hex.h"
#include "crypto-ecies/ecies.h"
#include "crypto-ecies/auth_enc.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::ecies::ECIES;
using safeheron::ecies::AuthEnc;

int main(int argc, char **argv) {
    bool ok = true;
    std::string str;
    std::string data;
    const Curve *curv = GetCurveParam(CurveType::P256);

    std::string message = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18};
    std::string plain;
    std::string cypher;
    std::string iv;

    // private key
    BN priv = safeheron::rand::RandomBNLt(curv->n);
    priv.ToBytes32BE(data);
    std::cout << "priv: " << safeheron::encode::hex::EncodeToHex(data) << std::endl;

    // public key(in full format)
    CurvePoint pub = curv->g * priv;
    uint8_t buf65[65];
    pub.EncodeFull(buf65);
    std::cout << "pub(full format): " << safeheron::encode::hex::EncodeToHex(buf65, 65) << std::endl;

    // ecies encryption
    ECIES enc;
    enc.set_curve_type(CurveType::P256);
    ok = enc.Encrypt(pub, message, iv, cypher);
    std::cout << "succeed to encrypt: " << ok << std::endl;
    std::cout << "iv: " << safeheron::encode::hex::EncodeToHex(iv) << std::endl;
    std::cout << "cypher: " << safeheron::encode::hex::EncodeToHex(cypher) << std::endl;

    // ecies decryption
    ok = enc.Decrypt(priv, cypher, iv, plain);
    std::cout << "succeed to encrypt: " << ok << std::endl;
    std::cout << "plain: " << safeheron::encode::hex::EncodeToHex(plain) << std::endl;

    // comparison
    bool is_same = true;
    for(size_t i = 0; i < message.length(); i ++){
        if(message[i] != plain[i]){
            is_same = false;
            break;
        }
    }
    std::cout << "compare: " << is_same << std::endl;

    return 0;
}
```

## Compile and Run

- Compile:
 
```shell
cmake .. -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@1.1 -DENABLE_TESTS=ON
make                                                                       
```

- Run:

```shell
./example           

priv: c8f9d6f833664e41b9c4fa7ee812554472eb2f4e08da44f148b989ad433f3d53
pub(full format): 0461f92e2f41ccecd99bbe8c772c807c933d8b9929f34b8e90f4b77fcd25b2994067580b47a1ce50a5af2a5dd43cccf2cf97a8344639cc0c736802cb4f76dd2c8e
succeed to encrypt: 1
iv: 6286107cb65bd0e31ea944d5e9c88d18
cypher: 045a8ec0ac293719d1e6c53b3b38e525e4feefeab03277830a67a3d877863f3593942bdd8174701b7fd570be4bf61a08bc0ae2a3715d0db86e8efc007b2b35f991f122c014b7b5d845dfd518a2215e0ee8afe5e7b34176ebdf19a79607e8794a8b22b0d2f2a4b81ea5b0b6b77fce6d57d327ff39df211790ee50e6b33ab6690a956d539739ab3ada9976ac025feaa9d27ce498e8c0f01edc80200024e1a60d463f
succeed to encrypt: 1
plain: 000102030405060708090a0b0c0d0e0f1112
compare: 1
```

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
