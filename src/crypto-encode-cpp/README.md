# crypto-encode-cpp

![img](doc/logo.png)

Encoding library in C++ for hex, base58 and base64.

# Prerequisites

- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
 
# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-encode-cpp.git
cd crypto-encode-cpp
mkdir build && cd build
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
make
make test # If you set ENABLE_TESTS ON
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-encode-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-bn-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(CryptoEncode REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CryptoEncode_INCLUDE_DIRS}
        /usr/local/include  # This directory is included default on linux but not on Mac os
        )

# This directory is included default on linux but not on Mac os
target_link_directories(example PUBLIC /usr/local/lib)

target_link_libraries(${PROJECT_NAME} PRIVATE
        CryptoHash
        )
```

## Example

```c++
#include <iostream>
#include "crypto-encode/base58.h"

using namespace safeheron::encode;

int main(int argc, char **argv) {
    const std::string expected_data("hello world");
    const std::string expected_b58("3vQB7B6MrGQZaxCuFg4oh");
    //encode
    std::string b58 = base58::EncodeToBase58Check(expected_data);
    std::cout << b58 << std::endl;

    // decode
    std::string data = base58::DecodeFromBase58Check(b58);
    std::cout << data << std::endl;
    return 0;
}
```

# Usage

#### Namespace - safeheron::encode::hex
>- EncodeToHex(const std::string &data) - Encode the string into hex format.
>- EncodeToHex(const unsigned char * buf, size_t buf_len) - Encode the string into hex format.
>- DecodeFromHex(const std::string &hex) - Decode the string from hex format.
 
#### Namespace - safeheron::encode::base64
>- EncodeToBase64(const std::string &data, bool url = false) - Encode the string into base64/base64url format.
>- EncodeToBase64(const unsigned char * buf, size_t buf_len, bool url = false) - Encode the string into base64/base64url format.
>- DecodeFromBase64(const std::string &hex) - Decode the string from base64/base64url format.

#### Namespace - safeheron::encode::base58
>- EncodeToBase58(const std::string &data) - Encode the string into base58 format.
>- EncodeToBase58(const unsigned char * buf, size_t buf_len) - Encode the string into base58 format.
>- DecodeFromBase58(const std::string &hex) - Decode the string from base58 format.

>- EncodeToBase58Check(const std::string &data) - Encode the string into base58-check format.
>- EncodeToBase58Check(const unsigned char * buf, size_t buf_len) - Encode the string into base58-check format.
>- DecodeFromBase58Check(const std::string &hex) - Decode the string from base58-check format.
 
# Some parts of the library come from external sources:
- ReneNyffenegger/cpp-base64: [https://github.com/ReneNyffenegger/cpp-base64](https://github.com/ReneNyffenegger/cpp-base64)
- Bitcoin Core:[https://github.com/bitcoin/bitcoin.git](https://github.com/bitcoin/bitcoin.git)
- tallymarker_hextobin from network(I did not find the real source while I have checked the logic of code).
 
# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
