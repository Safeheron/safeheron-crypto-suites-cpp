#ifndef CRYPTOBIP39_HASH_WRAPPER_H
#define CRYPTOBIP39_HASH_WRAPPER_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
#define SHA256_OUTPUT_SIZE 32
void _crypto_bip39_internal_sha256_wrapper(const unsigned char *data, size_t len, unsigned char digest[SHA256_OUTPUT_SIZE]);
#ifdef __cplusplus
}
#endif

#endif //CRYPTOBIP39_HASH_WRAPPER_H
