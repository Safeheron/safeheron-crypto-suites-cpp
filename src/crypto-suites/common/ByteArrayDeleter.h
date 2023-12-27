//
// Created by Sword03 on 2023/12/16.
//

#ifndef SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H
#define SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H

#include <cstring>

namespace safeheron {
namespace common {

class ByteArrayDeleter {
public:
    void operator()(uint8_t* ptr) const {
        memset_s(ptr, size_, 0, size_);
        delete[] ptr;
    }

    explicit ByteArrayDeleter(size_t size) : size_(size) {}

private:
    size_t size_;
};

}
}

#endif //SAFEHERONCRYPTOSUITES_BYTEARRAYDELETER_H
