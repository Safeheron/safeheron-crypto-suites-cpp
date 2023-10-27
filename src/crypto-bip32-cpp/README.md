# crypto-bip32-cpp
A BIP32 compatible library written in C++. Supports bip32-secp256k1 and bip32-ed25519.

Since there is currently no standard for the BIP32 derivation algorithm based on elliptic curve $Ed25519$, I have formulated our own BIP32-Ed25519 algorithm based on the existing related standards on the market and several "BIP32-Ed25519" algorithm implementations.

# Usage

It's an example where the key length is 1024, the number of parties is 3 and threshold is 2.
```c++
#include "crypto-bn/bn.h"
#include "exception/located_exception.h"
#include "crypto-curve/curve.h"
#include "crypto-bip32/bip32.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/base58.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

int main(int argc, char **argv) {
    HDKey root_hd_key;
    string seed("000102030405060708090a0b0c0d0e0f");
    string path("m/0'/1/2'/2/1000000000");
    string data = hex::DecodeFromHex(seed);
    bool ok = root_hd_key.FromSeed(CurveType::SECP256K1, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    string xprv, xpub;
    root_hd_key.ToExtendedPrivateKey(xprv);
    root_hd_key.ToExtendedPublicKey(xpub);
    std::cout << "xprv: " << xprv << std::endl;
    std::cout << "xprv(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    std::cout << "xpub: " << xpub << std::endl;
    std::cout << "xpub(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(xpub)) << std::endl;

    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    std::cout << "child_xprv: " << child_xprv << std::endl;
    std::cout << "child_xprv(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    std::cout << "child_xpub: " << child_xpub << std::endl;
    std::cout << "child_xpub(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    return 0;
}
```

Here is the CMakeList.txt:

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
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)
find_package(CryptoCurve REQUIRED)
find_package(CryptoBIP32 REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${CryptoBIP32_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(example PUBLIC
        CryptoBN
        CryptoCurve
        CryptoBIP32
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        ${GTEST_BOTH_LIBRARIES}
        pthread )
```

Compile and run:
```shell
xprv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
xprv(hex)     :  0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35e77e9d71
xpub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
xpub(hex)     :  0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2ab473b21
child_xprv: xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76
child_xprv(hex): 0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c81e57a871
child_xpub: xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
child_xpub(hex): 0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f701118d3a268
```

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
