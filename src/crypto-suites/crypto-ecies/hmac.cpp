#include "hmac.h"
#include <openssl/hmac.h>

namespace safeheron {
namespace ecies {

bool IHMAC::calcMAC(const unsigned char *key,
                    size_t key_size,
                    const unsigned char *input,
                    size_t in_size,
                    std::string &out) {
    bool ret = false;
    unsigned int mdlen = 0;
    unsigned char md[EVP_MAX_MD_SIZE] = {0};
    HMAC_CTX *ctx = nullptr;
    std::string iv_len_tag;

    if (!key || key_size <= 0) {
        return false;
    }
    if (!input || in_size <= 0) {
        return false;
    }

    iv_len_tag = getLengthTag(iv_);

    if (!(ctx = HMAC_CTX_new())) {
        return false;
    }

    // hamc key
    if (!HMAC_Init_ex(ctx, key, key_size, md_, nullptr))
        goto err;

    // shared in ecies
    if (!HMAC_Update(ctx, input, in_size))
        goto err;
    
    // encoding iv
    if (iv_.length() > 0) {
        if (!HMAC_Update(ctx, (const uint8_t*)iv_.c_str(), iv_.length()))
            goto err;
    }

    // encoding iv length tag
    if (!HMAC_Update(ctx, (const uint8_t*)iv_len_tag.c_str(), iv_len_tag.length()))
        goto err;

    // get the hmac
    if (!HMAC_Final(ctx, md, &mdlen))
        goto err;
    
    out.assign((char*)md, mdlen);
    ret = true;
err:
    if (ctx) {
        HMAC_CTX_free(ctx);
        ctx = nullptr;
    }
    return ret;
}

bool IHMAC::calcMAC(const std::string &key,
                    const std::string &input,
                    std::string &out) {
    return calcMAC((const unsigned char *) key.c_str(), key.length(),
                   (const unsigned char *) input.c_str(), input.length(), out);
}

// as described in Shroup's paper and P1363a
std::string IHMAC::getLengthTag(const std::string & str)
{
    uint8_t tag[8] = { 0 };
    long len = 8 * str.length();    //in bits
    std::string res;

    if (len > 0) {
        tag[7] = len & 0xFF;
        tag[6] = (len >> 8) & 0xFF;
        tag[5] = (len >> 16) & 0xFF;
        tag[4] = (len >> 24) & 0xFF;
        tag[3] = (len >> 32) & 0xFF;
        tag[2] = (len >> 40) & 0xFF;
        tag[1] = (len >> 48) & 0xFF;
        tag[0] = (len >> 56) & 0xFF;
    }
    res.assign((char*)tag, sizeof(tag));
    return res;
}

}
}
