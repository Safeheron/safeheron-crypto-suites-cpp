#ifndef CRYPTO_BIP39_C_MNEMONIC_H
#define CRYPTO_BIP39_C_MNEMONIC_H

#include <stddef.h>
#include "wordlist.h"

#ifdef __cplusplus
extern "C" {
#endif
struct words;
/**
 * Return a mnemonic representation of a block of bytes.
 *
 * @w: List of words.
 * @bytes: Bytes to convert to a mnemonic sentence.
 * @len: The length of @bytes in bytes.
 *
 * @bytes must be an even multiple of the number of bits in the wordlist used.
 */
char *mnemonic_from_bytes(
    const struct words *w,
    const unsigned char *bytes,
    size_t len);

/**
 * Convert a mnemonic representation into a block of bytes.
 *
 * @w: List of words.
 * @mnemonic: Mnemonic sentence to store.
 * @bytes_out: Where to store the converted representation.
 * @len: The length of @bytes_out in bytes.
 * @written: Destination for the number of bytes written.
 */
int mnemonic_to_bytes(
    const struct words *w,
    const char *mnemonic,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif //CRYPTO_BIP39_C_MNEMONIC_H
