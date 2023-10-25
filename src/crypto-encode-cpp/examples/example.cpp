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
