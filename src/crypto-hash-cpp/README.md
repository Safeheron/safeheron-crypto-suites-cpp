# crypto-hash-cpp

![img](doc/logo.png)

Hash implementation in C++, such as sha1, sha256, sha512, ripemd160, hash160, hash256, hmac_sha256, hmac_sha512 and chacha20 .

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-hash-cpp.git
cd crypto-hash-cpp
mkdir build && cd build
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
make
make test # If you set ENABLE_TESTS ON
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-hash-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-bn-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(CryptoHash REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PRIVATE
        ${CryptoHash_INCLUDE_DIRS}
        )

target_link_libraries(example PRIVATE
        CryptoHash
        pthread )
```

## Example

```c++
#include <crypto-hash/sha256.h>

using safeheron::hash::CSHA256;

int main(int argc, char **argv) {
    const char *input = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    CSHA256 sha256;
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    sha256.Write((const uint8_t *)input, strlen(input));
    sha256.Finalize(digest);
    return 0;
}
```

# Usage

#### Class - safeheron::hash ::CSHA1
>- CSHA1() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::CSHA256
>- CSHA256() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::CSHA512
>- CSHA512() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::CRIPEMD160
>- CRIPEMD160() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::Hash160
>- CHash160() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::Hash256
>- CHash256() - Constructor
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
>- Reset() - Reset the hash status.

#### Class - safeheron::hash ::CHMAC_SHA256
>- CHMAC_SHA256(const unsigned char* key, size_t keylen) - Constructor with key.
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.

#### Class - safeheron::hash ::CHMAC_SHA512
>- CHMAC_SHA512(const unsigned char* key, size_t keylen) - Constructor with key.
>- Write(const unsigned char *data, size_t len) - Update hash status with input data.
>- Finalize(unsigned char hash[OUTPUT_SIZE]) - Output the digest.
 
# Some parts of the library come from external sources:
- Bitcoin Core:[https://github.com/bitcoin/bitcoin.git](https://github.com/bitcoin/bitcoin.git)

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.

# License
