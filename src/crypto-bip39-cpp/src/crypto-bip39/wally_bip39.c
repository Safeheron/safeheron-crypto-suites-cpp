#include "wally_bip39.h"

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "hash_wrapper.h"
#include "internal.h"
#include "wally_mnemonic.h"
#include "wordlist.h"

#include "data/wordlists/english.c"
#include "data/wordlists/chinese_simplified.c"
#include "data/wordlists/chinese_traditional.c"

/* Maximum length including up to 2 bytes for checksum */
#define BIP39_ENTROPY_LEN_MAX (BIP39_ENTROPY_LEN_320 + sizeof(unsigned char) * 2)

static const struct {
    const char name[4];
    const struct words *words;
} lookup[] = {
    { "en", &en_words},
    { "zhs", &zhs_words},
    { "zht", &zht_words}
    /* FIXME: Should 'zh' map to traditional or simplified? */
};

int bip39_get_languages(char **output)
{
    if (!output)
        return WALLY_EINVAL;
    *output = wally_strdup("en zhs zht");
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

int bip39_get_wordlist(const char *lang, struct words **output)
{
    size_t i;

    if (!output)
        return WALLY_EINVAL;

    *output = (struct words *)&en_words; /* Fallback to English if not found */

    if (lang)
        for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); ++i)
            if (!strcmp(lang, lookup[i].name)) {
                *output = (struct words *)lookup[i].words;
                break;
            }
    return WALLY_OK;
}

int bip39_get_word(const struct words *w, size_t idx,
                   char **output)
{
    const char *word;

    if (output)
        *output = NULL;

    w = w ? w : &en_words;

    if (!output || !(word = wordlist_lookup_index(w, idx)))
        return WALLY_EINVAL;

    *output = wally_strdup(word);
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

/* Convert an input entropy length to a mask for checksum bits. As it
 * returns 0 for bad lengths, it serves as a validation function too.
 */
static size_t len_to_mask(size_t len)
{
    switch (len) {
    case BIP39_ENTROPY_LEN_128: return 0xf0;
    case BIP39_ENTROPY_LEN_160: return 0xf8;
    case BIP39_ENTROPY_LEN_192: return 0xfc;
    case BIP39_ENTROPY_LEN_224: return 0xfe;
    case BIP39_ENTROPY_LEN_256: return 0xff;
    case BIP39_ENTROPY_LEN_288: return 0x80ff;
    case BIP39_ENTROPY_LEN_320: return 0xC0ff;
    }
    return 0;
}
static size_t bip39_checksum(const unsigned char *bytes, size_t bytes_len, size_t mask)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    _crypto_bip39_internal_sha256_wrapper(bytes, bytes_len, digest);
    size_t ret;
    ret = digest[0] | (digest[1] << 8);
    return ret & mask;
}

int bip39_mnemonic_from_bytes(const struct words *w,
                              const unsigned char *bytes, size_t bytes_len,
                              char **output)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_MAX];
    size_t checksum, mask;

    if (output)
        *output = NULL;

    if (!bytes || !bytes_len || !output)
        return WALLY_EINVAL;

    w = w ? w : &en_words;

    if (w->bits != 11u || !(mask = len_to_mask(bytes_len)))
        return WALLY_EINVAL;

    memcpy(tmp_bytes, bytes, bytes_len);
    checksum = bip39_checksum(bytes, bytes_len, mask);
    tmp_bytes[bytes_len] = checksum & 0xff;
    if (mask > 0xff)
        tmp_bytes[++bytes_len] = (checksum >> 8) & 0xff;
    *output = mnemonic_from_bytes(w, tmp_bytes, bytes_len + 1);
    wally_clear(tmp_bytes, sizeof(tmp_bytes));
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

static bool checksum_ok(const unsigned char *bytes, size_t idx, size_t mask)
{
    /* The checksum is stored after the data to sum */
    size_t calculated = bip39_checksum(bytes, idx, mask);
    size_t stored = bytes[idx];
    if (mask > 0xff)
        stored |= (bytes[idx + 1] << 8);
    return (stored & mask) == calculated;
}

int bip39_mnemonic_to_bytes(const struct words *w, const char *mnemonic,
                            unsigned char *bytes_out, size_t len,
                            size_t *written)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_MAX];
    size_t mask, tmp_len;
    int ret;

    /* Ideally we would infer the wordlist here. Unfortunately this cannot
     * work reliably because the default word lists overlap. In combination
     * with being sorted lexographically, this means the default lists
     * were poorly chosen. But we are stuck with them now.
     *
     * If the caller doesn't know which word list to use, they should iterate
     * over the available ones and try any resulting list that the mnemonic
     * validates against.
     */
    w = w ? w : &en_words;

    if (written)
        *written = 0;

    if (w->bits != 11u || !mnemonic || !bytes_out)
        return WALLY_EINVAL;

    ret = mnemonic_to_bytes(w, mnemonic, tmp_bytes, sizeof(tmp_bytes), &tmp_len);

    if (!ret) {
        /* Remove checksum bytes from the output length */
        --tmp_len;
        if (tmp_len > BIP39_ENTROPY_LEN_256)
            --tmp_len; /* Second byte required */

        if (tmp_len > sizeof(tmp_bytes))
            ret = WALLY_EINVAL; /* Too big for biggest supported entropy */
        else {
            if (tmp_len <= len) {
                if (!(mask = len_to_mask(tmp_len)) ||
                    !checksum_ok(tmp_bytes, tmp_len, mask)) {
                    tmp_len = 0;
                    ret = WALLY_EINVAL; /* Bad checksum */
                }
                else
                    memcpy(bytes_out, tmp_bytes, tmp_len);
            }
        }
    }

    wally_clear(tmp_bytes, sizeof(tmp_bytes));
    if (!ret && written)
        *written = tmp_len;
    return ret;
}

int bip39_mnemonic_validate(const struct words *w, const char *mnemonic)
{
    unsigned char buf[BIP39_ENTROPY_LEN_MAX];
    size_t len;
    int ret = bip39_mnemonic_to_bytes(w, mnemonic, buf, sizeof(buf), &len);
    wally_clear(buf, sizeof(buf));
    return ret;
}

