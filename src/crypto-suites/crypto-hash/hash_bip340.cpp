#include "crypto-suites/crypto-hash/hash_bip340.h"

namespace safeheron{
namespace hash{

CTaggedSHA256::CTaggedSHA256(const unsigned char * tag, size_t tag_len){
    unsigned char hash_tag[CSHA256::OUTPUT_SIZE];
    sha.Write((const uint8_t *)tag, tag_len);
    sha.Finalize(hash_tag);

    sha.Reset();
    sha.Write((const uint8_t *)hash_tag, sizeof hash_tag);
    sha.Write((const uint8_t *)hash_tag, sizeof hash_tag);
}

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
void CTaggedSHA256::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    sha.Finalize(hash);
}

CTaggedSHA256& CTaggedSHA256::Write(const unsigned char *data, size_t len) {
    sha.Write(data, len);
    return *this;
}

/**
 * Refer to https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 */
const char* CHashBIP340Nonce::TAG = "BIP0340/nonce";

const char* CHashBIP340Aux::TAG = "BIP0340/aux";

const char* CHashBIP340Challenge::TAG = "BIP0340/challenge";

}
}

