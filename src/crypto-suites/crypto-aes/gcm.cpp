#include "gcm.h"
#include "Formatter.h"
#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/common/custom_assert.h"
#include "crypto-suites/common/custom_memzero.h"
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
    key_.resize(key_len);
    memcpy(key_.data(), p_key, key_len);
}

GCM::GCM(const std::string &key)
{
    ASSERT_THROW(key.length() == 16 || key.length() == 24 || key.length() == 32);
    key_.resize(key.length());
    memcpy(key_.data(), key.c_str(), key.length());
}

GCM::~GCM() 
{
    // fill the buffer with 0 before release
    crypto_memzero(key_.data(), key_.size());
}

bool GCM::Encrypt(const uint8_t* p_in_plaindata, int in_plaindata_len,
                 const uint8_t* p_in_iv, int in_iv_len,
                const uint8_t* p_in_associatedData, int in_associated_data_len,
                uint8_t* &p_out_tag, int &out_tag_len,
                uint8_t* &p_out_cipherdata, int &out_cipherdata_len)
{
    int len = 0;
    const EVP_CIPHER *cipher = nullptr;
    EVP_CIPHER_CTX *ctx = nullptr;

    error_msg_ = "";

    if (!p_in_plaindata || in_plaindata_len <= 0) {
        error_msg_ = "Parameter p_in_plaindata cannot be null or empty.";
        return false;
    }
    if (!p_in_iv || in_iv_len != GCM_IV_LEN) {
        error_msg_ = "Parameter p_in_iv cannot be null and length must be 12 bytes.";
        return false;
    }
    if (!p_in_associatedData && in_associated_data_len > 0) {
        error_msg_ = "Parameter p_in_associatedData cannot be null when in_associated_data_len > 0.";
        return false;
    }
    if (p_in_associatedData && in_associated_data_len <= 0) {
        error_msg_ = "Parameter in_associated_data_len cannot be 0 or less 0 when p_in_associatedData is not null.";
        return false;
    }

    // support AES-GCM with 128/192/256 bytes key
    switch (key_.size()) {
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
            error_msg_ = "AES-GCM Key length is wrong.";
            return false;
    }

    // create and initialize cipher context
    if (!(ctx = EVP_CIPHER_CTX_new()) ||
        (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr)) ||
        (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), p_in_iv))) {
        EVP_CIPHER_CTX_free(ctx);
        error_msg_ = "Create and initialize cipher context failed.";
        return false;
    }

    // add AAD data
    if (p_in_associatedData && in_associated_data_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, p_in_associatedData, in_associated_data_len)) {
            EVP_CIPHER_CTX_free(ctx);
            error_msg_ = "Try to add AAD data failed.";
            return false;
        }
    }

    // encrypt plain data
    out_cipherdata_len = 0;
    out_tag_len = GCM_TAG_LEN;
    p_out_tag = new uint8_t[GCM_TAG_LEN];
    p_out_cipherdata = new uint8_t[in_plaindata_len + EVP_MAX_BLOCK_LENGTH];
    if ((1 != EVP_EncryptUpdate(ctx, p_out_cipherdata, &out_cipherdata_len, p_in_plaindata, in_plaindata_len)) ||
        (1 != EVP_EncryptFinal_ex(ctx, p_out_cipherdata + out_cipherdata_len, &len)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, p_out_tag)) ) {
        delete []p_out_tag;
        delete []p_out_cipherdata;
        p_out_tag = nullptr;
        p_out_cipherdata = nullptr;
        EVP_CIPHER_CTX_free(ctx);
        error_msg_ = "Encrypt data failed.";
        return false;
    }

    // return ciphertext data length
    out_cipherdata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return true;
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

    error_msg_ = "";

    if (!p_in_cipherdata || in_cipherdata_len <= 0) {
        error_msg_ = "Parameter p_in_cipherdata cannot be null or empty.";
        return false;
    }
    if (!p_in_iv || in_iv_len != GCM_IV_LEN) {
        error_msg_ = "Parameter p_in_iv cannot be null and length must be 12 bytes.";
        return false;
    }
    if (!p_in_tag || in_tag_len != GCM_TAG_LEN) {
        error_msg_ = "Parameter p_in_tag cannot be null or empty.";
        return false;
    }
    if (!p_in_associatedData && in_associated_data_len > 0) {
        error_msg_ = "Parameter p_in_associatedData cannot be null when in_associated_data_len > 0.";
        return false;
    }
    if (p_in_associatedData && in_associated_data_len <= 0) {
        error_msg_ = "Parameter in_associated_data_len cannot be 0 or less 0 when p_in_associatedData is not null.";
        return false;
    }

    // support AES-GCM with 128/192/256 bytes key
    switch (key_.size()) {
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
            error_msg_ = "AES-GCM Key length is wrong!";
            return false;
    }

    // create and initialize cipher context
    if (!(ctx = EVP_CIPHER_CTX_new()) ||
        (1 != EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, in_iv_len, nullptr)) ||
        (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), p_in_iv))) {
        EVP_CIPHER_CTX_free(ctx);
        error_msg_ = "Create and initialize cipher context failed.";
        return false;
    }

    // add AAD data
    if (p_in_associatedData && in_associated_data_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, p_in_associatedData, in_associated_data_len)) {
            EVP_CIPHER_CTX_free(ctx);
            error_msg_ = "Try to add AAD data failed.";
            return false;
        }
    }
    
    // decrypt ciphertext data
    out_plaindata_len = 0;
    p_out_plaindata = new uint8_t[in_cipherdata_len];
    if ((1 != EVP_DecryptUpdate(ctx, p_out_plaindata, &out_plaindata_len, p_in_cipherdata, in_cipherdata_len)) ||
        (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, in_tag_len, (void*)p_in_tag)) ||
        (1 != EVP_DecryptFinal_ex(ctx, p_out_plaindata + out_plaindata_len, &len)) ) {
        delete []p_out_plaindata;
        p_out_plaindata = nullptr;
        EVP_CIPHER_CTX_free(ctx);
        error_msg_ = "Decrypt data failed.";
        return false;
    }

    // return decrypted data length
    out_plaindata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool GCM::EncryptPack(const uint8_t* p_in_plaindata, int in_plaindata_len,
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

    error_msg_ = "";

    // use a random number as the iv
    RAND_bytes(iv, GCM_IV_LEN);

    // encrypt plain data
    if (!Encrypt(p_in_plaindata, in_plaindata_len, iv, GCM_IV_LEN, p_in_associatedData, 
            in_associated_data_len, p_tag, tag_len, p_cipher, cipher_len)) {
        return false;
    }

    // construct GCM cypher
    if (!fm.ConstructAESGCMCypher(p_cipher, cipher_len, p_tag, tag_len, iv, GCM_IV_LEN, out_cypher)) {
        delete []p_tag;
        delete []p_cipher;
        error_msg_ = "Construct ciphertext data package failed.";
        return false;
    }

    // return result
    p_out_cipherpack = new uint8_t[out_cypher.length()];
    memcpy(p_out_cipherpack, out_cypher.c_str(), out_cypher.length());
    out_cipherpack_len = out_cypher.length();

    delete []p_tag;
    delete []p_cipher;
    p_tag = nullptr;
    p_cipher = nullptr;
    return true;
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

    error_msg_ = "";

    if (!p_in_cipherpack || in_cipherpack_len <= 0) {
        error_msg_ = "Parameter p_in_cipherpack cannot be null or empty.";
        return false;
    }

    // parser GCM cypher
    if (!fm.ParseAESGCMCypher(p_in_cipherpack, in_cipherpack_len,
                              p_encrypted_data, encrypted_data_len,
                              p_tag, tag_len,
                              p_iv, iv_len)) {
        error_msg_ = "Parameter p_in_cipherpack in not valid.";
        return false;
    }

    // decrypt
    return Decrypt(p_encrypted_data, encrypted_data_len, p_iv, iv_len, p_in_associatedData, 
            in_associated_data_len, p_tag, tag_len, p_out_plaindata, out_plaindata_len);
}

bool GCM::EncryptPack(const std::string &in_plaindata,
                    const std::string &in_associatedData,
                    std::string &out_cipherpack)
{
    int out_cipherpack_len = 0;
    uint8_t* p_out_cipherpack = nullptr;

    error_msg_ = "";

    if (!EncryptPack((uint8_t*)in_plaindata.c_str(), in_plaindata.length(),
                (uint8_t*)in_associatedData.c_str(), in_associatedData.length(),
                p_out_cipherpack, out_cipherpack_len)) {
        return false;
    }

    out_cipherpack.assign((char*)p_out_cipherpack, out_cipherpack_len);
    delete []p_out_cipherpack;
    p_out_cipherpack = nullptr;
    return true;
}

bool GCM::DecryptPack(const std::string &in_cipherpack,
                     const std::string &in_associatedData,
                     std::string &out_plaindata)
{
    int out_plaindata_len = 0;
    uint8_t* p_out_plaindata = nullptr;

    error_msg_ = "";

    if (!DecryptPack((uint8_t*)in_cipherpack.c_str(), in_cipherpack.length(),
                (uint8_t*)in_associatedData.c_str(), in_associatedData.length(),
                p_out_plaindata, out_plaindata_len)) {
        return false;
    }

    out_plaindata.assign((char*)p_out_plaindata, out_plaindata_len);
    delete []p_out_plaindata;
    p_out_plaindata = nullptr;
    return true;
}


}   //aes
}   //safeheron