#ifndef SAFEHERON_CRYPTO_HMAC_SHA256_H
#define SAFEHERON_CRYPTO_HMAC_SHA256_H

#include "sha256.h"

#include <stdint.h>
#include <stdlib.h>

namespace safeheron{
namespace hash{

/** A hasher class for HMAC-SHA-256. */
class CHMAC_SHA256
{
private:
    CSHA256 outer;
    CSHA256 inner;

public:
    static const size_t OUTPUT_SIZE = 32;

    CHMAC_SHA256(const unsigned char* key, size_t keylen);
    CHMAC_SHA256& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

}
}

#endif // SAFEHERON_CRYPTO_HMAC_SHA256_H
