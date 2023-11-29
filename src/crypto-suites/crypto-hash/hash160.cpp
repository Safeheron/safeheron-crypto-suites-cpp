//
// Created by Sword03 on 2022/3/11.
//

#include "hash160.h"
#include "sha256.h"
#include "ripemd160.h"

namespace safeheron{
namespace hash{

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
void CHash160::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    unsigned char buf[CSHA256::OUTPUT_SIZE];
    sha.Finalize(buf);
    CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
}

CHash160& CHash160::Write(const unsigned char *data, size_t len) {
    sha.Write(data, len);
    return *this;
}

CHash160& CHash160::Reset() {
    sha.Reset();
    return *this;
}

}
}
