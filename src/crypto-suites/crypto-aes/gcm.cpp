#include "gcm.h"
#include "Formatter.h"
#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/common/custom_assert.h"
#include <openssl/rand.h>
#include <openssl/evp.h>

using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::LocatedException;

// The tag length for GCM
#define GCM_TAG_LEN    16

// The nonce sizes supported by this instance: 12 bytes (96 bits).
// Ref: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.noncebytesizes?view=net-8.0 
#define GCM_IV_LEN     12  
                        
namespace safeheron{
namespace aes{

GCM::GCM(uint8_t *p_key, int key_len)
{
    ASSERT_THROW(p_key);
    ASSERT_THROW(key_len == 16 || key_len == 24 || key_len == 32);
    key_.assign((char*)p_key, key_len);
}

GCM::GCM(const std::string &key)
{
    ASSERT_THROW(key.length() == 16 || key.length() == 24 || key.length() == 32);
    key_ = key;
}

void GCM::Encrypt(const uint8_t* p_in_plaindata, int in_plaindata_len,
                 const uint8_t* p_in_iv, int in_iv_len,
                const uint8_t* p_in_associatedData, int in_associated_data_len,
                uint8_t* &p_out_tag, int &out_tag_len,
                uint8_t* &p_out_cipherdata, int &out_cipherdata_len)
{
    int len = 0;
    const EVP_CIPHER *cipher = nullptr;
    EVP_CIPHER_CTX *ctx = nullptr;

    if (!p_in_plaindata || in_plaindata_len <= 0) {
        throw new std::invalid_argument("Parameter p_in_plaindata cannot be null or empty.");
    }
    if (!p_in_iv || in_iv_len != GCM_IV_LEN) {
        throw new std::invalid_argument("Parameter p_in_iv cannot be null and length must be 12 bytes.");
    }

    // support AES-GCM with 128/192/256 bytes key
    switch (key_.length()) {
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 24:
            cipher = EVP_aes_192_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            throw new std::invalid_argument("AES-GCM Key length is wrong!");
    }

    out_cipherdata_len = 0;
    out_tag_len = GCM_TAG_LEN;
    p_out_tag = new uint8_t[GCM_TAG_LEN];
    p_out_cipherdata = new uint8_t[in_plaindata_len + EVP_MAX_BLOCK_LENGTH];

    // use p_in_associatedData as the AAD, and use a 16-bytes tag
    if (!(ctx = EVP_CIPHER_CTX_new()) ||
        (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr)) ||
        (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, (const uint8_t*)key_.c_str(), p_in_iv)) ||
        (1 != EVP_EncryptUpdate(ctx, nullptr, &len, p_in_associatedData, in_associated_data_len)) ||
        (1 != EVP_EncryptUpdate(ctx, p_out_cipherdata, &out_cipherdata_len, p_in_plaindata, in_plaindata_len)) ||
        (1 != EVP_EncryptFinal_ex(ctx, p_out_cipherdata + out_cipherdata_len, &len)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, p_out_tag)) ) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "EVP functions failed.");
    }
    EVP_CIPHER_CTX_free(ctx);
    out_cipherdata_len += len;
}

bool GCM::Decrypt(const uint8_t* p_in_cipherdata, int in_cipherdata_len,
                 const uint8_t* p_in_iv, int in_iv_len,
                const uint8_t* p_in_associatedData, int in_associated_data_len,
                const uint8_t* p_in_tag, int in_tag_len,
                uint8_t* &p_out_plaindata, int &out_plaindata_len)
{
    int len = 0;
    const EVP_CIPHER *cipher = nullptr;
    EVP_CIPHER_CTX *ctx = nullptr;

    if (!p_in_cipherdata || in_cipherdata_len <= 0) {
        throw new std::invalid_argument("Parameter p_in_cipherdata cannot be null or empty.");
    }
    if (!p_in_iv || in_iv_len != GCM_IV_LEN) {
        throw new std::invalid_argument("Parameter p_in_iv cannot be null and length must be 12 bytes.");
    }
    if (!p_in_tag || in_tag_len != GCM_TAG_LEN) {
        throw new std::invalid_argument("Parameter p_in_tag cannot be null or empty.");
    }

    // support AES-GCM with 128/192/256 bytes key
    switch (key_.length()) {
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 24:
            cipher = EVP_aes_192_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            throw new std::invalid_argument("AES-GCM Key length is wrong!");
    }
    
    out_plaindata_len = 0;
    p_out_plaindata = new uint8_t[in_cipherdata_len];

    // use p_in_associatedData as the AAD, and use a 16-bytes tag
    if (!(ctx = EVP_CIPHER_CTX_new()) ||
        (1 != EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, in_iv_len, nullptr)) ||
        (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, (const uint8_t*)key_.c_str(), p_in_iv)) ||
        (1 != EVP_DecryptUpdate(ctx, nullptr, &len, p_in_associatedData, in_associated_data_len)) ||
        (1 != EVP_DecryptUpdate(ctx, p_out_plaindata, &out_plaindata_len, p_in_cipherdata, in_cipherdata_len)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, in_tag_len, (void*)p_in_tag)) ||
        (1 != EVP_DecryptFinal_ex(ctx, p_out_plaindata + out_plaindata_len, &len)) ) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    out_plaindata_len += len;

    return true;
}

void GCM::EncryptPack(const uint8_t* p_in_plaindata, int in_plaindata_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 uint8_t* &p_out_cipherpack, int &out_cipherpack_len)
{
    int tag_len = 0;
    int cipher_len = 0;
    uint8_t* p_tag = nullptr;
    uint8_t* p_cipher = nullptr;
    uint8_t iv[GCM_IV_LEN] = {0};
    std::string out_cypher;
    Formatter fm;

    // use a random number as the iv
    RAND_bytes(iv, GCM_IV_LEN);

    // encrypt plain data
    Encrypt(p_in_plaindata, in_plaindata_len, iv, GCM_IV_LEN, p_in_associatedData, 
            in_associated_data_len, p_tag, tag_len, p_cipher, cipher_len);

    // construct GCM cypher
    if (!fm.ConstructAESGCMCypher(p_cipher, cipher_len, p_tag, tag_len, iv, GCM_IV_LEN, out_cypher)) {
        delete []p_tag;
        delete []p_cipher;
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "ConstructAESGCMCypher() failed.");
    }

    // return result
    p_out_cipherpack = new uint8_t[out_cypher.length()];
    memcpy(p_out_cipherpack, out_cypher.c_str(), out_cypher.length());
    out_cipherpack_len = out_cypher.length();

    delete []p_tag;
    delete []p_cipher;
    p_tag = nullptr;
    p_cipher = nullptr;
}

bool GCM::DecryptPack(const uint8_t* p_in_cipherpack, int in_cipherpack_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 uint8_t* &p_out_plaindata, int &out_plaindata_len)
{
    int len = 0;
    int out_len = 0;
    const uint8_t *p_encrypted_data = nullptr;
    uint32_t encrypted_data_len = -1;
    const uint8_t *p_tag = nullptr;
    uint32_t tag_len = -1;
    const uint8_t *p_iv = nullptr;
    uint32_t iv_len = -1;
    Formatter fm;

    if (!p_in_cipherpack || in_cipherpack_len <= 0) {
        throw new std::invalid_argument("Parameter p_in_cipherpack cannot be null or empty.");
    }

    // parser GCM cypher
    if (!fm.ParseAESGCMCypher(p_in_cipherpack, in_cipherpack_len,
                              p_encrypted_data, encrypted_data_len,
                              p_tag, tag_len,
                              p_iv, iv_len)) {
        throw new std::invalid_argument("Parameter p_in_cipherpack in not valid.");
    }

    // decrypt
    return Decrypt(p_encrypted_data, encrypted_data_len, p_iv, iv_len, p_in_associatedData, 
            in_associated_data_len, p_tag, tag_len, p_out_plaindata, out_plaindata_len);
}

void GCM::EncryptPack(const std::string &in_plaindata,
                    const std::string &in_associatedData,
                    std::string &out_cipherpack)
{
    int out_cipherpack_len = 0;
    uint8_t* p_out_cipherpack = nullptr;

    EncryptPack((uint8_t*)in_plaindata.c_str(), in_plaindata.length(),
                (uint8_t*)in_associatedData.c_str(), in_associatedData.length(),
                p_out_cipherpack, out_cipherpack_len);

    out_cipherpack.assign((char*)p_out_cipherpack, out_cipherpack_len);
    delete []p_out_cipherpack;
    p_out_cipherpack = nullptr;
}

void GCM::DecryptPack(const std::string &in_cipherpack,
                     const std::string &in_associatedData,
                     std::string &out_plaindata)
{
    int out_plaindata_len = 0;
    uint8_t* p_out_plaindata = nullptr;

    DecryptPack((uint8_t*)in_cipherpack.c_str(), in_cipherpack.length(),
                (uint8_t*)in_associatedData.c_str(), in_associatedData.length(),
                p_out_plaindata, out_plaindata_len);

    out_plaindata.assign((char*)p_out_plaindata, out_plaindata_len);
    delete []p_out_plaindata;
    p_out_plaindata = nullptr;
}


}   //aes
}   //safeheron