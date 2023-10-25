# crypto-bn-cpp

![img](doc/logo.png)

Cross-platform library of big number in C++.

# Important Update

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


# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./OpenSSL-Installation.md)
- [GoogleTest](https://github.com/google/googletest). **You need it to compile and run test cases**. See the [GoogleTest Installation Instructions](./GoogleTest-Installation.md)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script. 

```shell
git clone https://gitlab.com/safeheron/algogroup/crypto-bn-cpp.git
cd crypto-bn-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-bn-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-bn-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CryptoBN_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PUBLIC
    CryptoBN
    OpenSSL::Crypto
    pthread 
    -ldl
)
```

## Using class BN 

```c++
#include "crypto-bn/bn.h"

using safeheron::bignum::BN;

int main(){
    BN n1 = BN::FromDecStr("351236171680578937197272793988364310158344798196852032811622206579");
    BN n2 = BN::FromDecStr("531137992816767098689588206552468627329593117727031923199444138200");
    BN n3 = BN::FromDecStr("206552468627329593117727031923199444195931177270319231994441382004");
    
    BN n4 = (n1 * n2) % n3;
    
    std::cout << "n4" << n4.Inspect() << std::endl;
    
    return 0;
}
```

## Generate Random BN

```c++
#include "crypto-bn/bn.h"

using safeheron::bignum::BN;
int main(){
    // Create a BN which is 256 bits (32 bytes) long. 
    BN n = safeheron::rand::RandomBN(256);
    max = n;
    n.ToHexStr(s);
    std::cout << s << std::endl;
    return 0;
}
```

# Usage

## Constructor

>- BN() - Construct a BN object and initialized it with 0.
>- BN(long i) - Construct a BN object and initialized it with word i.
>- BN(const char * str, int base) - Construct a BN objet and initialized it with str on specified base.
>- BN(const BN & num) - A copy constructor.
>- BN(BN && 	num	) A move constructor.

>- operator=(BN && num) - A move assignment.
>- operator=(const BN & 	num	) - A copy assignment.


## Bit operations

>- SetBit(unsigned long 	bit_index) - Set bits for this BN
>- ClearBit(unsigned long bit_index) - Clean bits for BN.
>- IsBitSet(unsigned long bit_index)	- Return true if this BN bit is set
>- BitLength() - Return bits size.
>- ByteLength() - Return bytes size.

>- operator<<(unsigned long ui) - Shift this to left by ui bits, and return the result
>- operator<<=(unsigned long ui) - Shift this to left by ui bits
>- operator>>(unsigned long 	ui)	- Shift this to right by ui bits, and return the result
>- operator>>=(unsigned long ui) - Shift this to right by ui bits

## Convertors

>- FromBytesBE(const uint8_t * buf, int len) - [static] Construct a BN object from byte buffer, in big endian
>- FromBytesBE(std::string & buf) - [static] Construct a BN object from byte string, in big endian

>- FromBytesLE(const uint8_t * buf, int len) - [static] Construct a BN object from byte buffer, in little endian
>- FromBytesLE(std::string & buf) - [static] - Construct a BN object from byte string, in little endian

>- FromDecStr(const char * 	str	) - [static] Construct a BN object from DEC char*
>- FromDecStr(const std::string & str) - [static] Construct a BN object from DEC string

>- FromHexStr(const char * 	str) - [static] Construct a BN object from HEX char*
>- FromHexStr(const std::string & str) - [static] Construct a BN object from HEX string

>- ToBytes32BE(std::string & buf) - Convert this BN to 32 bytes buff, in big endian
>- ToBytes32BE(uint8_t * 	buf32, int 	blen = 32) - Convert this BN to 32 bytes string, in big endian

>- ToBytes32LE(std::string & 	buf	) - Convert this BN to 32 bytes buff, in little endian
>- ToBytes32LE(uint8_t * 	buf32, int 	blen = 32) - Convert this BN to 32 bytes string, in little endian

>- ToBytesBE(std::string & 	buf	)	- Convert this BN to bytes string, in big endian

>- ToBytesLE(std::string & 	buf	)	- Convert this BN to bytes string, in little endian

>- ToDecStr(std::string & 	str	) - Convert this BN bits to a DEC string
 
>- ToHexStr(std::string & 	str	) - Convert this BN bits to a HEX string


## Arithmetics
>- operator+(const BN & num)	- Add the BN num with this, and return the result
>- operator+(long si) - Add the long value si with this, and return the result
>- operator+=(const BN & num) - Add the BN num with this
>- operator+=(long si) - Add the long value si with this


>- operator-(const BN & num)	- Sub the BN num from this, and return the result
>- operator-(long si) - Sub the long value si from this, and return the result
>- operator-=(const BN & num) - Sub the BN num from this
>- operator-=(long si) - Sub the long value si from this


>- operator*(const BN & num)	- Mul the BN num with this, and return the result
>- operator*(long si) - Mul the long value si with this, and return the result
>- operator*=(const BN & num) - Mul the BN num with this
>- operator*=(long si) - Mul the long value si with this


>- operator/(const BN & num)	- Div the BN num with this, and return the result
>- operator/(long si) - Div the long value si with this, and return the result
>- operator/=(const BN & num) - Div the BN num by this
>- operator/=(long si) - Div the long value si with this


>- operator%(const BN & num)	- Mod the BN num with this, and return the result
>- operator%(unsigned long ui) - Mod the ULONG value ui with this, and return the result


>- Neg() - Return the negative of this

## Comparison
>- operator==(const BN & num) - Return true if this._bn == num._bn
>- operator==(long num) - Return true if this._bn == num._bn


>- operator!=(const BN & num) - Return true if this._bn != num._bn
>- operator!=(long num) - Return true if this._bn != num._bn


>- operator<=(const BN & num) - Return true if this._bn <= num._bn
>- operator<=(long si) - Return true if this._bn <= si


>- operator<(const BN & num)	- Return true if this._bn < num._bn
>- operator<(long si) - Return true if this._bn < si


>- operator>(const BN & num)	- Return true if this._bn > num._bn
>- operator>(long si) - Return true if this._bn > si


>- operator>=(const BN & num) - Return true if this._bn >= num._bn
>- operator>=(long 	si) - Return true if this._bn >= si

## Auxiliary

>- IsEven() - Return true if this BN is a even number
>- IsNeg() - Return true if this BN is a negative number
>- IsOdd() - Return true if this BN is an odd number
>- IsZero() - Return true if this BN is 0

>- Max(const BN & a, const BN & 	b) - [static] Return the max one between a and b
>- Min(const BN & a, const BN & 	b) - [static] Return the min one between a and b
>- Swap(BN & a, BN & b) - [static] Swap the values between a and b

## Number Theory

>- IsProbablyPrime()	- Return true is this is a prime, otherwise return false
>- Div(const BN & d,  BN & q, BN & r) - Return quotient q = this / d and remainder r = this % d.
>- SqrtM(const BN & p) - Get square root on modulo m Return 'r' such that r^2 == this (mod p),
>- ExistSqrtM(const BN & p) - Return sqrt mod is exist or not.
>- Gcd(const BN & n)	- Return the greatest common divisor of this and n
>- Inspect(int base = 16) - Return the string of this BN
>- InvM(const BN & m) - Return the inverse of (this modulo m) Compute the inverse modulo mod. Be careful, mode must be prime!!!
>- Lcm(const BN & n)	const Return the least common multiple of this and n. lcm(a, b) = ab/gcd(a,b))
>- PowM(const BN & y, const BN & m) - Return the y-th power of this and modulo m r = (this ^ y) % m

# Some features
Refer to [Some-Features.md](./Some-Features.md)

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.

# License
