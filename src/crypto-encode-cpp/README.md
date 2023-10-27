# crypto-encode-cpp

![img](doc/logo.png)

Encoding library in C++ for hex, base58 and base64.



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
