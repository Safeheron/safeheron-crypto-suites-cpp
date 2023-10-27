//
// Created by Sword03 on 2022/3/11.
//

#ifndef CRYPTOHASH_HASH256_H
#define CRYPTOHASH_HASH256_H

#include "sha256.h"

namespace safeheron{
namespace hash{

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CHash256& Write(const unsigned char *data, size_t len);

    CHash256& Reset();
};


}
}



#endif //CRYPTOHASH_HASH256_H
