//
// Created by Sword03 on 2023/12/16.
//

#ifndef SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H
#define SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H

#include <crypto-suites/crypto-bip39/memzero.h>

namespace safeheron {
namespace common {

class ByteArrayDeleter {
public:
    void operator()(uint8_t* ptr) const {
        crypto_bip39_memzero(ptr, size_);
        delete[] ptr;
    }

    explicit ByteArrayDeleter(size_t size) : size_(size) {}

private:
    size_t size_;
};

}
}

#endif //SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H
