# crypto-sss-cpp

![img](doc/logo.png)

This software implements a library for secret sharing scheme. 

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [GoogleTest](https://github.com/google/googletest). **You need it to compile and run test cases**. See the [GoogleTest Installation Instructions](./doc/GoogleTest-Installation.md)
- [crypto-bn-cpp](https://github.com/safeheron/crypto-bn-cpp.git). See the [crypto-bn-cpp Installation Instructions](https://github.com/safeheron/crypto-bn-cpp/blob/main/README.md#build-and-install)
- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
- [crypto-encode-cpp](https://github.com/safeheron/crypto-encode-cpp.git). See the [crypto-encode-cpp Installation Instructions](https://github.com/safeheron/crypto-encode-cpp/blob/main/README.md#build-and-install)
- [crypto-curve-cpp](https://github.com/safeheron/crypto-curve-cpp.git). See the [crypto-curve-cpp Installation Instructions](https://github.com/safeheron/crypto-curve-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-sss-cpp.git
cd crypto-sss-cpp
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

To build crypto-sss-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoSSS REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoSSS_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSSS
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

## Example

```c++
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-sss/vsss_secp256k1.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::sss::Point;
using safeheron::sss::Polynomial;
using std::vector;

int main(){
    // 4 shares with threshold 2: 2/4
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 2;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("1", 16));
    shareIndexs.push_back(BN("2", 16));
    shareIndexs.push_back(BN("3", 16));
    shareIndexs.push_back(BN("4", 16));
    safeheron::sss::vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, shareIndexs);

    for(int i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "index: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "share: " << str << std::endl;
        EXPECT_TRUE(safeheron::sss::vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    safeheron::sss::vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);
    
    return 0;
}
```

# Usage
## Class - safeheron::sss::Polynomial
>- Polynomial(const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime) - Constructor of Polynomial
>- Polynomial(const safeheron::bignum::BN &secret, const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime) - Constructor of Polynomial
>- CreateRandomPolynomial(const safeheron::bignum::BN &secret, int threshold, const safeheron::bignum::BN &prime) - Create a random Polynomial with specified secret and threshold.

>- GetY(safeheron::bignum::BN &y, const safeheron::bignum::BN &x) - Get coordinate y of point with specified coordinate x for current polynomial.
>- GetYArray(std::vector<safeheron::bignum::BN> &yArr, const std::vector<safeheron::bignum::BN> &xArr) - Get an array of coordinate y of point with specified array of coordinate  x for current polynomial.
>- GetPoints(std::vector<Point> &vecPoint, const std::vector<safeheron::bignum::BN> &xArr) - Get an array of points with specified array of coordinate  x for current polynomial.
>- GetCommits(std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::curve::CurvePoint &g) - Get commitment of current polynomial.

>- VerifyCommits(const std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, const safeheron::curve::CurvePoint &g, const safeheron::bignum::BN &prime) - Verify commitment of current polynomial.
>- LagrangeInterpolate(safeheron::bignum::BN &y, const safeheron::bignum::BN &x, const std::vector<Point> &vecPoint, const safeheron::bignum::BN &prime ) - Lagrange interpolate.
>- GetLArray(std::vector<safeheron::bignum::BN> &lArr, const safeheron::bignum::BN &x, const std::vector<safeheron::bignum::BN> &xArr, const safeheron::bignum::BN &prime ) - Get coefficients for Lagrange interpolating.
 
## Namespace - safeheron::sss::vsss

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme. 
>- RecoverSecret(...) - Recover secret.

## Namespace - safeheron::sss::vsss_ed25519

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme.
>- RecoverSecret(...) - Recover secret.
 
## Namespace - safeheron::sss::vsss_secp256k1

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme.
>- RecoverSecret(...) - Recover secret.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
