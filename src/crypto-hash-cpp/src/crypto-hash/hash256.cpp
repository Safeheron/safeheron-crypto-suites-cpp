//
// Created by Sword03 on 2022/3/11.
//

#include "hash256.h"

namespace safeheron{
namespace hash{

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
void CHash256::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    unsigned char buf[CSHA256::OUTPUT_SIZE];
    sha.Finalize(buf);
    sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
}

CHash256& CHash256::Write(const unsigned char *data, size_t len) {
    sha.Write(data, len);
    return *this;
}

CHash256& CHash256::Reset() {
    sha.Reset();
    return *this;
}


}
}

