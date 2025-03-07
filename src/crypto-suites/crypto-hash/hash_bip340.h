//
// Created by Sword03 on 2022/3/11.
//

#ifndef CRYPTOHASH_BIP340_H
#define CRYPTOHASH_BIP340_H

#include "crypto-suites/crypto-hash/sha256.h"
#include <cstring>

namespace safeheron{
namespace hash{

/**
 * Tagged Hashes Cryptographic hash functions are used for multiple purposes in the specification below and in Bitcoin
 * in general. To make sure hashes used in one context can't be reinterpreted in another one, hash functions can be
 * tweaked with a context-dependent tag name, in such a way that collisions across contexts can be assumed to be infeasible.
 * Such collisions obviously can not be ruled out completely, but only for schemes using tagging with a unique name.
 * As for other schemes collisions are at least less likely with tagging than without.
 *
 * Refer to https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 */
class CTaggedSHA256{
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    CTaggedSHA256(const unsigned char * tag, size_t tag_len);

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CTaggedSHA256& Write(const unsigned char *data, size_t len);
};

class CHashBIP340Nonce : public CTaggedSHA256 {
private:
    static const char * TAG;
public:
    CHashBIP340Nonce(): CTaggedSHA256((const unsigned char*)TAG, strlen(TAG)){};
};

class CHashBIP340Aux : public CTaggedSHA256 {
private:
    static const char * TAG;
public:
    CHashBIP340Aux(): CTaggedSHA256((const unsigned char*)TAG, strlen(TAG)){};
};

class CHashBIP340Challenge : public CTaggedSHA256 {
private:
    static const char * TAG;
public:
    CHashBIP340Challenge(): CTaggedSHA256((const unsigned char*)TAG, strlen(TAG)){};
};


}
}



#endif //CRYPTOHASH_BIP340_H
