# crypto-curve-cpp

![img](doc/logo.png)

This software implements a library for elliptic curves based cryptography (ECC).
- It contains an extremely simple mathematical interface to onboard new elliptic curves. Use this library for general purpose elliptic curve cryptography.
- It provides interfaces on ecdsa to Sepcp256k1 and P256.
- It provides interfaces on eddsa to ed25519.

The library has a built in support for some useful operations/primitives such as verifiable secret sharing, commitment schemes, zero knowledge proofs etc.
The library comes with serialize/deserialize support to be used in higher level code to implement networking.

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./Protocol-Buffers-Installation.md)
- [GoogleTest](https://github.com/google/googletest). **You need it to compile and run test cases**. See the [GoogleTest Installation Instructions](./GoogleTest-Installation.md)
- [crypto-bn-cpp](https://github.com/safeheron/crypto-bn-cpp.git). See the [crypto-bn-cpp Installation Instructions](https://github.com/safeheron/crypto-bn-cpp/blob/main/README.md#build-and-install)
- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
- [crypto-encode-cpp](https://github.com/safeheron/crypto-encode-cpp.git). See the [crypto-encode-cpp Installation Instructions](https://github.com/safeheron/crypto-encode-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-curve-cpp.git
cd crypto-curve-cpp
git submodule update --init --recursive 
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.

# Currently Supported Elliptic Curves

|Curve| 	low level library                                             |	curve description|
|---|----------------------------------------------------------------|---|
|Secp256k1	| [OpenSSL](https://github.com/openssl/openssl)	                 |bitcoin wiki|
|P-256	| [OpenSSL](https://github.com/openssl/openssl)	                                                       |NIST.FIPS.186.4|
|Ed25519	| [ed25519-donna](https://github.com/floodyberry/ed25519-donna)	 |[Ed25519: high-speed high-security signatures](https://ed25519.cr.yp.to)/

Note: Curve25519, SM2 and BLS12-381 will be supported soon.

# To start using crypto-curve-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-curve-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoCurve REQUIRED)

add_executable(${PROJECT_NAME} example.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoCurve_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        /usr/local/include  # This directory is included default on linux but not on Mac os
        )

# This directory is included default on linux but not on Mac os
target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoCurve
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

## Example

```c++
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

int main(int argc, char **argv) {
    // p0 = g^10
    CurvePoint p0;
    if(!p0.PointFromXY(BN("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f", 16),
                      BN("878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773", 16),
                      CurveType::P256)){
        return 0;
    }

    // p1 = g^100
    CurvePoint p1;
    if(!p1.PointFromXY(BN("490a19531f168d5c3a5ae6100839bb2d1d920d78e6aeac3f7da81966c0f72170", 16),
                       BN("bbcd2f21db581bd5150313a57cfa2d9debe20d9f460117b588fcf9b0f4377794", 16),
                       CurveType::P256)){
        return 0;
    }

    // p2 = g^1000
    CurvePoint p2;
    if(!p2.PointFromXY(BN("b8fa1a4acbd900b788ff1f8524ccfff1dd2a3d6c917e4009af604fbd406db702", 16),
                       BN("9a5cc32d14fc837266844527481f7f06cb4fb34733b24ca92e861f72cc7cae37", 16),
                       CurveType::P256)){
        return 0;
    }

    std::cout << (p0 * 10 == p1) << std::endl;
    std::cout << (p1 * 10 == p2) << std::endl;

    CurvePoint p3(CurveType::P256);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    std::cout << (p3 == p1) << std::endl;

    CurvePoint p4(CurveType::P256);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    std::cout << (p4 == p2) << std::endl;

    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::P256);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    std::cout << (p5 == p1) << std::endl;

    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::P256);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    std::cout << (p6 == p0) << std::endl;


    CurvePoint p7;
    std::cout << (p7.PointFromXY(p1.x(), p1.y(), p1.GetCurveType())) << std::endl;
    std::cout << (p7.PointFromXY(p2.x(), p2.y(), p2.GetCurveType())) << std::endl;
    std::cout << (p7.PointFromXY(p3.x(), p3.y(), p3.GetCurveType())) << std::endl;
    return 0;
}
```

# Usage

## Class - safeheron::curve::CurvePoint
#### Constructor, Destructor and Assignment
>- explicit CurvePoint() - Constructor.
>- explicit CurvePoint(CurveType c_type) - Constructor.
>- CurvePoint(const CurvePoint &point) - Copy constructor.
>- explicit CurvePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type) - Constructor.
>- CurvePoint &operator=(const CurvePoint &point) - Copy Assignment.
>- ~CurvePoint() - Destructor.
 
#### Serialization and deserialization
>- ToProtoObject(safeheron::proto::CurvePoint &curvePoint) - Convert to an object of protobuf.
>- FromProtoObject(const safeheron::proto::CurvePoint &curvePoint) - Recover from an object of protobuf.

>- ToBase64(std::string& base64) const - Convert to a string encoded in base64 format.
>- FromBase64(const std::string& base64) - Recover from a string encoded in base64 format.

>- ToJsonString(std::string &json_str) const - Convert to a string encoded in json format.
>- FromJsonString(const std::string &json_str) - Recover from a string encoded in json format.

#### Encode and decode
>- EncodeCompressed(uint8_t* pub33) - Encode into compressed public key (33 bytes) 
>- DecodeCompressed(const uint8_t* pub33, CurveType c_type) - Decode from compressed public key (33 bytes)

>- EncodeFull(uint8_t* pub65) - Encode into full public key (65 bytes)
>- DecodeFull(const uint8_t* pub65, CurveType c_type) - Decode from full public key (65 bytes)

>- void EncodeEdwardsPoint(uint8_t *pub32) - Encode into edwards public key (32 bytes)
>- bool DecodeEdwardsPoint(uint8_t *pub32, CurveType c_type) - Decode from edwards public key (32 bytes)

#### Comparison
>- bool operator==(const CurvePoint &point) - P1 == P2.
>- bool operator!=(const CurvePoint &point) - P1 != P2.

#### Addition, Subtraction and Multiplication
>- CurvePoint operator+(const CurvePoint &point) - Res = P1 + P2.
>- CurvePoint operator-(const CurvePoint &point) - Res = P1 - P2.
>- CurvePoint operator*(const safeheron::bignum::BN &bn) - Res = P1 * n.
>- CurvePoint operator*(long n) - Res = P1 * n.

>- CurvePoint &operator+=(const CurvePoint &point) - P1 += P2.
>- CurvePoint &operator-=(const CurvePoint &point)- P1 -= P2.
>- CurvePoint &operator*=(const safeheron::bignum::BN &bn) - P1 *= n.
>- CurvePoint &operator*=(long n) - P1 *= n.

#### Auxiliary Function
>- ValidatePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type) - Check if the point with specified x and y is valid.
>- IsValid() - Check if the curve point is valid.
>- IsInfinity() - Check if the curve point is infinity.
>- PointFromXY(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type) - Return a CurvePoint by coordinate x and y.
>- PointFromX(safeheron::bignum::BN &x, bool yIsOdd, CurveType c_type) - Recover point from coordinate x.
>- PointFromY(safeheron::bignum::BN &y, bool xIsOdd, CurveType c_type) - Recover point from coordinate y, only for edwards point
>- CurveType GetCurveType() - Return the type of CurvePoint.

## Namespace - safeheron::curve::ecdsa
>- Sign(...) - Sign in ecdsa.
>- Verify(...) - Verify signature in ecdsa.
>- Sig64ToDer(...) - Convert signature from 64 bytes into der format.
>- DerToSig64(...) - Convert signature from der format into 64 bytes.
>- RecoverPublicKey(...) - Recover public key from signature.
>- VerifyPublicKey(...) - Verify Public key.
 
## Namespace - safeheron::curve::eddsa
>- Sign(...) - Sign in ecdsa.
>- Verify(...) - Verify signature in ecdsa.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.