#include "hash_wrapper.h"
#include "crypto-hash/sha256.h"
void _crypto_bip39_internal_sha256_wrapper(const unsigned char *data, size_t len, unsigned char digest[SHA256_OUTPUT_SIZE]) {
    safeheron::hash::CSHA256 hash;
    if (data && len > 0) {
        hash.Write(data, len);
        hash.Finalize(digest);
    }
}

