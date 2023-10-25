#ifndef SAFEHERON_CRYPTO_ECIES_SYMM_H
#define SAFEHERON_CRYPTO_ECIES_SYMM_H

#include <string>
#include <openssl/evp.h>

namespace safeheron {
namespace ecies {

class ISYMM {
public:
    ISYMM() {
        cipher_ = nullptr;
        key_size_ = 0;
    };

    virtual ~ISYMM() {};

    virtual int getKeySize() { return key_size_; };

    virtual int getIVSize() { return block_size_; };

    virtual bool initKey_CBC(const unsigned char *key, size_t key_size, const unsigned char *iv, size_t iv_size) = 0;

    virtual bool initKey_CBC(const std::string &key, const std::string &iv) = 0;

    virtual bool encrypt(const unsigned char *in_plain, size_t in_plain_len, std::string &out_cypher);

    virtual bool encrypt(const std::string &in_plain, std::string &out_cypher);

    virtual bool decrypt(const unsigned char *in_cypher, size_t in_cypher_len, std::string &out_plain);

    virtual bool decrypt(const std::string &in_cypher, std::string &out_plain);

protected:
    const EVP_CIPHER *cipher_;
    size_t key_size_;       // in bits
    size_t block_size_;     // in bits
    std::string key_;
    std::string cbc_iv_;
};

class DESede : public ISYMM {
public:
    DESede() {
        cipher_ = nullptr;
        key_size_ = 24 * 8;
        block_size_ = 8 * 8;
    };

    virtual ~DESede() {};
public:
    bool initKey_CBC(const unsigned char *key, size_t key_size, const unsigned char *iv, size_t iv_size);

    bool initKey_CBC(const std::string &key, const std::string &iv);
};

class AES : public ISYMM {
public:
    AES(size_t key_size) {
        cipher_ = nullptr;
        key_size_ = key_size;
        block_size_ = 16 * 8;
    };

    virtual ~AES() {};
public:
    bool initKey_CBC(const unsigned char *key, size_t key_size, const unsigned char *iv, size_t iv_size);

    bool initKey_CBC(const std::string &key, const std::string &iv);
};

}
}

#endif //SAFEHERON_CRYPTO_ECIES_SYMM_H
