//
// Created by Sword03 on 2022/7/17.
//

#include <cstring>
#include "crypto-suites/crypto-bip39/bip39.h"
#include "crypto-suites/crypto-bip39/wally_bip39.h"
#include "crypto-suites/crypto-bip39/wordlist.h"
#include "crypto-suites/crypto-bip39/internal.h"

/* Maximum length including up to 2 bytes for checksum */
#define BIP39_ENTROPY_LEN_MAX (BIP39_ENTROPY_LEN_320 + sizeof(unsigned char) * 2)

namespace safeheron {
namespace bip39 {

static const char *get_language_str(Language lang) {
    static const char *en = "en";
    static const char *zht = "zht";
    static const char *zhs = "zhs";
    if (lang == Language::ENGLISH) {
        return en;
    } else if (lang == Language::SIMPLIFIED_CHINESE) {
        return zhs;
    } else {
        return zht;
    }
}

/**
 *
 * CS = ENT / 32
 * MS = (ENT + CS) / 11
 *
 *              |        ENT       | CS | ENT+CS |  MS  |
 *              +------------------+----+--------+------+
 *              |  128 (16 bytes)  |  4 |   132  |  12  |
 *              |  160 (20 bytes)  |  5 |   165  |  15  |
 *              |  192 (24 bytes)  |  6 |   198  |  18  |
 *              |  224 (28 bytes)  |  7 |   231  |  21  |
 *              |  256 (32 bytes)  |  8 |   264  |  24  |
 *              |  288 (36 bytes)  |  9 |   297  |  27  |
 *              |  320 (40 bytes)  | 10 |   330  |  30  |
 *
 * @param word_count
 * @return
 */
//static size_t get_entropy_size(size_t word_count) {
//    size_t enc_cs = word_count * 11;
//    size_t cs = enc_cs / 32;
//    size_t enc = enc_cs - cs;
//    return enc;
//}

static bool is_valid_word_count(size_t word_count) {
    return (word_count == 12) ||
           (word_count == 15) ||
           (word_count == 18) ||
           (word_count == 21) ||
           (word_count == 24) ||
           (word_count == 27) ||
           (word_count == 30);
}

static bool is_valid_entropy_size(size_t entropy_size) {
    return (entropy_size == 16) ||
           (entropy_size == 20) ||
           (entropy_size == 24) ||
           (entropy_size == 28) ||
           (entropy_size == 32) ||
           (entropy_size == 36) ||
           (entropy_size == 40);
}

static void Trim(const std::string& mnemonic, std::string& trim_mnemonic) {
    trim_mnemonic.reserve(mnemonic.size());

    for (size_t i = 0; i < mnemonic.length(); ++i) {
        // Meet a new word
        if (mnemonic[i] != ' ') {
            // trim spaces in front of mnemonic, otherwise just append a space
            if (trim_mnemonic.length() > 0) {
                trim_mnemonic += ' ';
            }
            // Append every char of the word
            while (i < mnemonic.length() && mnemonic[i] != ' ') {
                trim_mnemonic += mnemonic[i];
                ++i;
            }
        }
    }
}

bool MnemonicToWords(std::vector<std::string> &words, const std::string &mnemonic, Language lang) {
    std::string trim_mnemonic;
    Trim(mnemonic, trim_mnemonic);
    struct words *mnemonic_w = NULL;
    mnemonic_w = wordlist_init(trim_mnemonic.c_str());

    if (!mnemonic_w) {
        return false;
    }

    if (!is_valid_word_count(mnemonic_w->len)) {
        wordlist_free(mnemonic_w);
        return false;
    }

    words.clear();
    for (size_t i = 0; i < mnemonic_w->len; i++) {
        words.emplace_back(mnemonic_w->indices[i]);
    }
    wordlist_free(mnemonic_w);

    wally_clear((uint8_t *)trim_mnemonic.c_str(), trim_mnemonic.length());

    return true;
}

bool MnemonicToBytes(std::string &bytes, const std::string &mnemonic, Language lang) {
    std::vector<std::string> word_list;
    bool ok = MnemonicToWords(word_list, mnemonic, lang);
    if (!ok) return false;

    if (!is_valid_word_count(word_list.size())) {
        return false;
    }

    struct words *lang_words = nullptr;
    const char *lang_type = get_language_str(lang);
    bip39_get_wordlist(lang_type, &lang_words);

    std::string trim_mnemonic;
    Trim(mnemonic, trim_mnemonic);
    uint8_t bytes_out[BIP39_ENTROPY_LEN_MAX];
    size_t written; // written to bytes_out
    int ret = bip39_mnemonic_to_bytes(lang_words, trim_mnemonic.c_str(), bytes_out, sizeof(bytes_out), &written);
    if (ret != WALLY_OK) {
        return false;
    }
    bytes.assign((const char *) bytes_out, written);
    wally_clear(bytes_out, BIP39_ENTROPY_LEN_MAX);
    wally_clear((uint8_t *)trim_mnemonic.c_str(), trim_mnemonic.length());
    return true;
}

bool BytesToMnemonic(std::string &mnemonic, const std::string &bytes, Language lang) {
    return BytesToMnemonic(mnemonic, (const uint8_t *) bytes.c_str(), bytes.size(), lang);
}

bool BytesToMnemonic(std::string &mnemonic, const uint8_t *bytes, size_t len, Language lang) {
    if (!is_valid_entropy_size(len)) {
        return false;
    }

    struct words *lang_words = nullptr;
    const char *lang_type = get_language_str(lang);
    bip39_get_wordlist(lang_type, &lang_words);

    char *mnemonic_ptr = nullptr;
    int ret = bip39_mnemonic_from_bytes(lang_words, bytes, len, &mnemonic_ptr);
    if (ret != WALLY_OK) {
        return false;
    }

    mnemonic.assign(mnemonic_ptr);
    clear_and_free(mnemonic_ptr, strlen(mnemonic_ptr));
    return true;
}

}
}
