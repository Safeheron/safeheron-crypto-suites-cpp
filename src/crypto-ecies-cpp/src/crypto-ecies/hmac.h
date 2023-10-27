#ifndef SAFEHERON_CRYPTO_ECIES_HMAC_H
#define SAFEHERON_CRYPTO_ECIES_HMAC_H

#include <string>
#include <openssl/evp.h>

namespace safeheron {
namespace ecies {

class IHMAC {
public:
    IHMAC() { md_ = nullptr; };

    virtual ~IHMAC() {};

    virtual int getOutSize() { return 8 * EVP_MD_size(md_); };

    virtual int getBlockSize() { return 8 * EVP_MD_block_size(md_); };

    virtual void setIV(const std::string iv) { iv_ = iv; };

    virtual void getIV(std::string &iv) { iv = iv_; };

    virtual bool
    calcMAC(const unsigned char *key, size_t key_size, const unsigned char *input, size_t in_size, std::string &out);

    virtual bool calcMAC(const std::string &key, const std::string &input, std::string &out);

protected:
    std::string getLengthTag(const std::string & str);

protected:
    const EVP_MD *md_;
    std::string iv_;
};

class HMAC_sha1 : public IHMAC {
public:
    HMAC_sha1() { md_ = EVP_sha1(); };

    virtual ~HMAC_sha1() {};
};

class HMAC_sha224 : public IHMAC {
public:
    HMAC_sha224() { md_ = EVP_sha224(); };

    virtual ~HMAC_sha224() {};
};

class HMAC_sha256 : public IHMAC {
public:
    HMAC_sha256() { md_ = EVP_sha256(); };

    virtual ~HMAC_sha256() {};
};

class HMAC_sha384 : public IHMAC {
public:
    HMAC_sha384() { md_ = EVP_sha384(); };

    virtual ~HMAC_sha384() {};
};

class HMAC_sha512 : public IHMAC {
public:
    HMAC_sha512() { md_ = EVP_sha512(); };

    virtual ~HMAC_sha512() {};
};

}
}

#endif //SAFEHERON_CRYPTO_ECIES_HMAC_H
