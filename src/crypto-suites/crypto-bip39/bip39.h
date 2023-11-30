//
// Created by Sword03 on 2022/7/17.
//

#ifndef SAFEHERON_CRYPTO_BIP39_H
#define SAFEHERON_CRYPTO_BIP39_H

#include<string>
#include<vector>
#include "crypto-suites/crypto-bip39/language.h"

namespace safeheron {
namespace bip39 {

/**
 * Convert mnemonic to bytes.
 * @param bytes
 * @param mnemonic_str
 * @param lang
 * @return
 */
bool MnemonicToBytes(std::string &bytes, const std::string &mnemonic, Language lang);

/**
 * Convert bytes to mnemonic.
 * @param mnemonic
 * @param bytes
 * @param lang
 * @return
 */
bool BytesToMnemonic(std::string &mnemonic, const std::string &bytes, Language lang);

/**
 * Convert bytes to mnemonic.
 * @param mnemonic
 * @param bytes
 * @param lang
 * @return
 */
bool BytesToMnemonic(std::string &mnemonic, const uint8_t *bytes, size_t len, Language lang);

/**
 * Split mnemonic into word array.
 * @param words
 * @param mnemonic_str
 * @param lang
 * @return
 */
bool MnemonicToWords(std::vector<std::string>& words, const std::string &mnemonic, Language lang);

}
}


#endif //SAFEHERON_CRYPTO_BIP39_H
