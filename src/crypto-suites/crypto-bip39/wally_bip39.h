#ifndef CRYPTO_BIP39_C_BIP39_H
#define CRYPTO_BIP39_C_BIP39_H
#include <stddef.h>
#include "crypto-suites/crypto-bip39/wordlist.h"

#ifdef __cplusplus
extern "C" {
#endif

struct words;

/** Valid entropy lengths */
#define BIP39_ENTROPY_LEN_128 16
#define BIP39_ENTROPY_LEN_160 20
#define BIP39_ENTROPY_LEN_192 24
#define BIP39_ENTROPY_LEN_224 28
#define BIP39_ENTROPY_LEN_256 32
#define BIP39_ENTROPY_LEN_288 36
#define BIP39_ENTROPY_LEN_320 40

/** The number of words in a BIP39 compliant wordlist */
#define BIP39_WORDLIST_LEN 2048

/**
 * Get the list of default supported languages.
 *
 * ..note:: The string returned should be freed using `wally_free_string`.
 */
int bip39_get_languages(
    char **output);

/**
 * Get the default word list for a language.
 *
 * :param lang: Language to use. Pass NULL to use the default English list.
 * :param output: Destination for the resulting word list.
 *
 * .. note:: The returned structure should not be freed or modified.
 */
int bip39_get_wordlist(
    const char *lang,
    struct words **output);

/**
 * Get the 'index'th word from a word list.
 *
 * :param w: Word list to use. Pass NULL to use the default English list.
 * :param index: The 0-based index of the word in ``w``.
 * :param output: Destination for the resulting word.
 *
 * The string returned should be freed using `wally_free_string`.
 */
int bip39_get_word(
    const struct words *w,
    size_t index,
    char **output);

/**
 * Generate a mnemonic sentence from the entropy in ``bytes``.
 *
 * :param w: Word list to use. Pass NULL to use the default English list.
 * :param bytes: Entropy to convert.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param output: Destination for the resulting mnemonic sentence.
 *
 * .. note:: The string returned should be freed using `wally_free_string`.
 */
int bip39_mnemonic_from_bytes(
    const struct words *w,
    const unsigned char *bytes,
    size_t bytes_len,
    char **output);

/**
 * Convert a mnemonic sentence into entropy at ``bytes_out``.
 *
 * :param w: Word list to use. Pass NULL to use the default English list.
 * :param mnemonic: Mnemonic to convert.
 * :param bytes_out: Where to store the resulting entropy.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
int bip39_mnemonic_to_bytes(
    const struct words *w,
    const char *mnemonic,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Validate the checksum embedded in a mnemonic sentence.
 *
 * :param w: Word list to use. Pass NULL to use the default English list.
 * :param mnemonic: Mnemonic to validate.
 */
int bip39_mnemonic_validate(
    const struct words *w,
    const char *mnemonic);


#ifdef __cplusplus
}
#endif

#endif //CRYPTO_BIP39_C_BIP39_H
