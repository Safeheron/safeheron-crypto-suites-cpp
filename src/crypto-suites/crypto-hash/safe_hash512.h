#ifndef CRYPTOHASH_SAFE_HASH_SHA_512_H
#define CRYPTOHASH_SAFE_HASH_SHA_512_H

#include "sha512.h"

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
class CSafeHash512 {
private:
    CSHA512 sha;
    uint32_t num{0};
public:
    static const size_t OUTPUT_SIZE = CSHA512::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CSafeHash512& Write(const unsigned char *data, size_t len);

    CSafeHash512& Reset();
};


}
}



#endif //CRYPTOHASH_SAFE_HASH_SHA_512_H
