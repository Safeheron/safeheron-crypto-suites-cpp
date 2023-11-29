#include "symm.h"
#include <string.h>

namespace safeheron {
namespace ecies {

// The base symmetic process functions for openssl EVP Cipher
bool ISYMM::encrypt(const unsigned char *in_plain,
                    size_t in_plain_len,
                    std::string &out_cypher) {
    bool ret = false;
    int out_len = 0;
    unsigned char *out_buff = nullptr;
    EVP_CIPHER_CTX *ctx = nullptr;

    if (!cipher_) {
        return false;
    }
    if (key_.length() <= 0 || cbc_iv_.length() <= 0) {
        return false;
    }
    if (!in_plain || in_plain_len <= 0) {
        return false;
    }
    out_cypher.clear();

    out_len = in_plain_len + EVP_MAX_BLOCK_LENGTH;
    out_buff = (unsigned char *) OPENSSL_malloc(out_len);
    memset(out_buff, 0, out_len);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return false;
    }
    if (!EVP_CipherInit_ex(ctx, cipher_, nullptr,
                           (const unsigned char *) key_.c_str(),
                           (const unsigned char *) cbc_iv_.c_str(), 1)) {
        goto err;
    }
    if (!EVP_CipherUpdate(ctx, out_buff, &out_len, in_plain, in_plain_len)) {
        goto err;
    }
    out_cypher.append((char *) out_buff, out_len);
    out_len = in_plain_len + EVP_MAX_BLOCK_LENGTH;
    if (!EVP_CipherFinal_ex(ctx, out_buff, &out_len)) {
        goto err;
    }
    out_cypher.append((char *) out_buff, out_len);

    ret = true;

    err:
    if (out_buff) {
        OPENSSL_free(out_buff);
        out_buff = nullptr;
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }
    return ret;
}

bool ISYMM::encrypt(const std::string &in_plain,
                    std::string &out_cypher) {
    return encrypt((const unsigned char *) in_plain.c_str(), in_plain.length(), out_cypher);
}

bool ISYMM::decrypt(const unsigned char *in_cypher,
                    size_t in_cypher_len,
                    std::string &out_plain) {
    bool ret = false;
    int out_len = 0;
    unsigned char *out_buff = nullptr;
    EVP_CIPHER_CTX *ctx = nullptr;

    if (!cipher_) {
        return false;
    }
    if (key_.length() <= 0 || cbc_iv_.length() <= 0) {
        return false;
    }
    if (!in_cypher || in_cypher_len <= 0) {
        return false;
    }
    out_plain.clear();

    out_len = in_cypher_len;
    out_buff = (unsigned char *) OPENSSL_malloc(out_len);
    memset(out_buff, 0, out_len);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return false;
    }
    if (!EVP_CipherInit_ex(ctx, cipher_, nullptr,
                           (const unsigned char *) key_.c_str(),
                           (const unsigned char *) cbc_iv_.c_str(), 0)) {
        goto err;
    }
    if (!EVP_CipherUpdate(ctx, out_buff, &out_len, in_cypher, in_cypher_len)) {
        goto err;
    }
    out_plain.append((char *) out_buff, out_len);
    out_len = in_cypher_len;
    if (!EVP_CipherFinal_ex(ctx, out_buff, &out_len)) {
        goto err;
    }
    out_plain.append((char *) out_buff, out_len);

    ret = true;

    err:
    if (out_buff) {
        OPENSSL_free(out_buff);
        out_buff = nullptr;
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }
    return ret;
}

bool ISYMM::decrypt(const std::string &in_cypher,
                    std::string &out_plain) {
    return decrypt((const unsigned char *) in_cypher.c_str(), in_cypher.length(), out_plain);
}


bool DESede::initKey_CBC(const unsigned char *key,
                         size_t key_size,
                         const unsigned char *iv,
                         size_t iv_size) {
    if (!key || key_size != 24) {
        return false;
    }
    if (!iv || iv_size != 8) {
        return false;
    }

    key_.clear();
    cbc_iv_.clear();
    key_.assign((char *) key, key_size);
    cbc_iv_.assign((char *) iv, iv_size);
    cipher_ = EVP_des_ede3_cbc();

    return true;
}

bool DESede::initKey_CBC(const std::string &key,
                         const std::string &iv) {
    return initKey_CBC((const unsigned char *) key.c_str(), key.length(),
                       (const unsigned char *) iv.c_str(), iv.length());
}


bool AES::initKey_CBC(const unsigned char *key,
                      size_t key_size,
                      const unsigned char *iv,
                      size_t iv_size) {
    if (!key) {
        return false;
    }
    if (!iv || iv_size != 16) {
        return false;
    }

    // support AES 128/192/256
    switch (key_size) {
        case 16:  //AES128
            cipher_ = EVP_aes_128_cbc();
            break;
        case 24:  //AES192
            cipher_ = EVP_aes_192_cbc();
            break;
        case 32:  //AES256
            cipher_ = EVP_aes_256_cbc();
            break;
        default:
            return false;
    }

    key_.clear();
    cbc_iv_.clear();
    key_.assign((char *) key, key_size);
    cbc_iv_.assign((char *) iv, iv_size);

    return true;
}

bool AES::initKey_CBC(const std::string &key,
                      const std::string &iv) {
    return initKey_CBC((const unsigned char *) key.c_str(), key.length(),
                       (const unsigned char *) iv.c_str(), iv.length());
}

}
}