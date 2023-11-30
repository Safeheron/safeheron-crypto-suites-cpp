#ifndef CRYPTOHASH_SAFE_HASH_SHA_256_H
#define CRYPTOHASH_SAFE_HASH_SHA_256_H

#include "crypto-suites/crypto-hash/sha256.h"

namespace safeheron{
namespace hash{

/** A Safe hasher class used in special cases, such as generating challenges or promises to avoid potential attacks.
 *
 *  SafeHash(e1 || e2 || ... || en) = Hash( (e1 || $ || len(e1) )
 *                                        ||(e2 || $ || len(e2) )
 *                                        .....................
 *                                        ||(en || $ || len(en) )
 *                                        || n )
 *  where n means the number of the elements.
 *
 * For example:
 * - SafeHash(a ) = Hash(a || $ || len(a) || 1)
 * - SafeHash(a || b ) = Hash(a || $ || len(a) || b || $ || len(b) || 2)
 * - SafeHash(a || b || c) = Hash(a || $ || len(a) || b || $ || len(b) ||  b || $ || len(b) || 3)
*/
class CSafeHash256 {
private:
    CSHA256 sha;
    uint32_t num{0};
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CSafeHash256& Write(const unsigned char *data, size_t len);

    CSafeHash256& Reset();
};


}
}



#endif //CRYPTOHASH_SAFE_HASH_SHA_256_H
