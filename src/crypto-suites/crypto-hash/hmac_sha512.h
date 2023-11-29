#ifndef SAFEHERON_CRYPTO_HMAC_SHA512_H
#define SAFEHERON_CRYPTO_HMAC_SHA512_H

#include "sha512.h"

#include <stdint.h>
#include <stdlib.h>

namespace safeheron{
namespace hash{

/** A hasher class for HMAC-SHA-512. */
class CHMAC_SHA512
{
private:
    CSHA512 outer;
    CSHA512 inner;

public:
    static const size_t OUTPUT_SIZE = 64;

    CHMAC_SHA512(const unsigned char* key, size_t keylen);
    CHMAC_SHA512& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

};
};

#endif // SAFEHERON_CRYPTO_HMAC_SHA512_H
