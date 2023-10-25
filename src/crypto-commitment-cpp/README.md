# crypto-commitment-cpp

![img](doc/logo.png)

This software implements a library for commitment scheme. The library comes with serialize/deserialize support to be used in higher level code to implement networking.

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
git clone https://github.com/safeheron/crypto-commitment-cpp.git
cd crypto-commitment-cpp
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


# To start using crypto-commitment-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-commitment-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoCommitment REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoCommitment_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoCommitment
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

## Example

```c++
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-commitment/commitment.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::commitment::KgdCurvePoint;
using safeheron::commitment::KgdNumber;

int main(){
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;

    // Create a commitment
    std::string str;
    BN com_point = safeheron::commitment::CreateComWithBlind(point, blind_factor);
    com_point.ToHexStr(str);
    std::cout << "commitment of point:" << str << std::endl;
    
    return 0;
}
```

# Usage

## Namespace - safeheron::commitment
>- CreateComWithBlind(safeheron::bignum::BN &num, safeheron::bignum::BN &blind_factor) - Create a commitment of big number with specified blind factor.
>- CreateComWithBlind(curve::CurvePoint &point, safeheron::bignum::BN &blind_factor) - Create a commitment of CurvePoint with specified blind factor.
>- CreateComWithBlind(std::vector<curve::CurvePoint> &points, safeheron::bignum::BN &blind_factor) - Create an array of CurvePoint of big number with specified blind factor.

>- CreateCom(safeheron::bignum::BN &num) - Create a commitment of big number.
>- CreateCom(curve::CurvePoint &point, safeheron::bignum::BN &blind_facto) - Create a commitment of CurvePoint.
>- CreateCom(std::vector<curve::CurvePoint> &points) - Create an array of CurvePoint of big number.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
