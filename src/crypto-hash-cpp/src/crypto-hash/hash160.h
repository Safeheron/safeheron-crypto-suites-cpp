//
// Created by Sword03 on 2022/3/11.
//

#ifndef CRYPTOHASH_HASH160_H
#define CRYPTOHASH_HASH160_H

#include "sha256.h"
#include "ripemd160.h"

namespace safeheron{
namespace hash{

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CHash160& Write(const unsigned char *data, size_t len);

    CHash160& Reset();
};


}
}


#endif //CRYPTOHASH_HASH160_H
