#include "kdf.h"
#include <string.h>
#include <openssl/evp.h>

#define KDF_MAX_LEN    (1 << 30)

namespace safeheron {
namespace ecies {

/**
 * @brief Use a hash function to derivate data from input data
 * 
 * @param hash_nid: openssl EVP_MD nid
 * @param iter_from: The start index of I2OSP, 0 for KDF1_18033, and 1 for X9_63 and KDF2_18033  
 * @param input: Input data, can't be null 
 * @param in_size: Input data size, in bytes 
 * @param salt: Salt data for X9_63 
 * @param salt_size: Salt data size, in bytes 
 * @param out_size: The size of derivated data, in bytes 
 * @param out: Return the result 
 * @return true 
 * @return false 
 */
bool IKDF::baseKDF(int hash_nid, int iter_from,
                   const unsigned char *input, size_t in_size,
                   const unsigned char *salt, size_t salt_size,
                   size_t out_size, std::string &out) {
    int mdlen = 0;
    int leftlen = 0;
    bool ret = false;
    unsigned char ctr[4] = {0};
    unsigned char buff[EVP_MAX_MD_SIZE] = {0};
    EVP_MD_CTX *ctx = nullptr;
    const EVP_MD *md = nullptr;

    if (!input || in_size <= 0) {
        return false;
    }
    if (in_size > KDF_MAX_LEN || out_size > KDF_MAX_LEN) {
        return false;
    }

    // get md result size in bytes
    switch (hash_nid) {
        case NID_sha1:
            md = EVP_sha1();
            break;
        case NID_sha256:
            md = EVP_sha256();
            break;
        case NID_sha384:
            md = EVP_sha384();
            break;
        case NID_sha512:
            md = EVP_sha512();
            break;
        default:
            return false;
    }
    mdlen = EVP_MD_size(md);

    if (!(ctx = EVP_MD_CTX_new()))
        return false;

    // loop until leftlen = 0
    leftlen = out_size;
    for (int i = iter_from;; i++) {
        // I2OSP
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;

        // calc md of input||ctr||iv_
        memset(buff, 0, EVP_MAX_MD_SIZE);
        if (!EVP_DigestInit_ex(ctx, md, nullptr))
            goto err;
        if (!EVP_DigestUpdate(ctx, input, in_size))
            goto err;
        if (!EVP_DigestUpdate(ctx, ctr, sizeof(ctr)))
            goto err;
        if (salt && salt_size > 0) {
            if (!EVP_DigestUpdate(ctx, salt, salt_size))
                goto err;
        }
        if (!EVP_DigestFinal(ctx, buff, nullptr))
            goto err;

        // append this md to out string
        if (leftlen > mdlen) {
            out.append((const char *) buff, mdlen);
            leftlen -= mdlen;
        } else {
            out.append((const char *) buff, leftlen);
            ret = true;
            break;
        }
    }

    err:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
        ctx = nullptr;
    }

    return ret;
}

//  Key derivation function from X9.63/SECG 
//  key = Hash(x||I2OSP(1, 4)||iv) || · · · ||Hash(x||I2OSP(k, 4)||iv))
//    where k = out_size/Hash.len
bool KDF_X9_63::generateBytes(const unsigned char *input,
                              size_t in_size,
                              size_t out_size,
                              std::string &out) {
    return IKDF::baseKDF(hash_nid_, 1, input, in_size,
                         (const unsigned char *) iv_.c_str(),
                         iv_.length(), out_size, out);
}

bool KDF_X9_63::generateBytes(const std::string &input,
                              size_t out_size,
                              std::string &out) {
    return generateBytes((const unsigned char *) input.c_str(),
                         input.length(), out_size, out);
}

//  Key derivation function1 (KDF1) from 18033-2 
//  key = Hash(x||I2OSP(0, 4)) || · · · ||Hash(x||I2OSP(k-1, 4)))
//    where k = out_size/Hash.len
bool KDF1_18033::generateBytes(const unsigned char *input,
                               size_t in_size,
                               size_t out_size,
                               std::string &out) {
    return IKDF::baseKDF(hash_nid_, 0, input, in_size, nullptr, 0, out_size, out);
}

bool KDF1_18033::generateBytes(const std::string &input,
                               size_t out_size,
                               std::string &out) {
    return generateBytes((const unsigned char *) input.c_str(),
                         input.length(), out_size, out);
}

//  Key derivation function2 (KDF2) from 18033-2 
//  key = Hash(x||I2OSP(1, 4)) || · · · ||Hash(x||I2OSP(k, 4)))
//    where k = out_size/Hash.len
bool KDF2_18033::generateBytes(const unsigned char *input,
                               size_t in_size,
                               size_t out_size,
                               std::string &out) {
    return IKDF::baseKDF(hash_nid_, 1, input, in_size, nullptr, 0, out_size, out);
}

bool KDF2_18033::generateBytes(const std::string &input,
                               size_t out_size,
                               std::string &out) {
    return generateBytes((const unsigned char *) input.c_str(),
                         input.length(), out_size, out);
}

}
}