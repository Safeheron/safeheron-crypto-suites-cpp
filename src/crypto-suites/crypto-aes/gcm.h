//
// Created by yyf on 2024/8/6.
//

#ifndef SAFEHERON_CRYPTO_GCM_H
#define SAFEHERON_CRYPTO_GCM_H

#include <cstdint>
#include <string>
#include <vector>

namespace safeheron{
namespace aes{

// Ref: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.-ctor?view=net-8.0#system-security-cryptography-aesgcm-ctor(system-byte()-system-int32)
//      https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.noncebytesizes?view=net-8.0 
                           
class GCM{
public:
    /**
     * Constructor
     * @param p_key: pointer to the secret key to use for this instance.
     * @param key_len: length of the secret key, only 16, 24, or 32 bytes (128, 192, or 256 bits)
     */
    GCM(uint8_t *p_key, int key_len);

    /**
     * Constructor
     * @param key: The secret key to use for this instance, length of which should only be 16, 24, or 32 bytes (128, 192, or 256 bits)
     */
    GCM(const std::string &key);

    /**
     * Destructor
     * 
     */
    ~GCM();

    /**
     * Encrypt
     *
     * - plaindata: The content to encrypt.
     * - iv: The iv data, must be 12 bytes length.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - tag: The generated authentication tag. The tag sizes supported by this instance: 12, 13, 14, 15, or 16 bytes (96, 104, 112, 120, or 128 bits).
     * - cipherdata: The encrypted contents.
     *
     * @param p_in_plaindata
     * @param in_plaindata_len
     * @param p_in_iv
     * @param in_iv_len
     * @param p_in_associatedData
     * @param in_associated_data_len
     * @param p_out_tag
     * @param out_tag_len
     * @param p_out_cipherdata
     * @param out_cipherdata_len
     */
    bool Encrypt(const uint8_t* p_in_plaindata, int in_plaindata_len,
                 const uint8_t* p_in_iv, int in_iv_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 uint8_t* &p_out_tag, int &out_tag_len,
                 uint8_t* &p_out_cipherdata, int &out_cipherdata_len);
    /**
     * Decrypt
     * - cipherdata: The encrypted contents.
     * - iv: The iv data, must be 12 bytes length.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - plaindata: The content to encrypt.
     * - tag: The generated authentication tag. The tag sizes supported by this instance: 12, 13, 14, 15, or 16 bytes (96, 104, 112, 120, or 128 bits).
     *
     * @param p_in_cipherdata
     * @param in_cipherdata_len
     * @param p_in_iv
     * @param in_iv_len
     * @param p_in_associatedData
     * @param in_associated_data_len
     * @param p_in_tag
     * @param in_tag_len
     * @param p_out_plaindata
     * @param out_plaindata_len
     * @return
     */
    bool Decrypt(const uint8_t* p_in_cipherdata, int in_cipherdata_len,
                 const uint8_t* p_in_iv, int in_iv_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 const uint8_t* p_in_tag, int in_tag_len,
                 uint8_t* &p_out_plaindata, int &out_plaindata_len);

    /**
     * EncryptPack. IV will be generated randomly in this function.
     * 
     * - plaindata: The content to encrypt.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - cipherpack: The encrypted data pack, including cipher + iv + tag.
     * 
     * @param p_in_plaindata
     * @param in_plaindata_len
     * @param p_in_associatedData
     * @param in_associated_data_len
     * @param p_out_cipherpack
     * @param out_cipherpack_len
     */
    bool EncryptPack(const uint8_t* p_in_plaindata, int in_plaindata_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 uint8_t* &p_out_cipherpack, int &out_cipherpack_len);
    /**
     * DecryptPack
     * 
     * - cipherpack: The cipher data pack to decrypt, including cipher + iv + tag.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - plaindata: The decrypted plain data.
     * 
     * @param p_in_cipherpack
     * @param in_cipherpack_len
     * @param p_in_associatedData
     * @param in_associated_data_len
     * @param p_out_plaindata
     * @param out_plaindata_len
     * @return
     */
    bool DecryptPack(const uint8_t* p_in_cipherpack, int in_cipherpack_len,
                 const uint8_t* p_in_associatedData, int in_associated_data_len,
                 uint8_t* &p_out_plaindata, int &out_plaindata_len);

    /**
     * EncryptPack. IV will be generated randomly in this function.
     * 
     * - plaindata: The content to encrypt.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - cipherpack: The encrypted data pack, including cipher + iv + tag.
     * 
     * @param in_plaindata
     * @param in_associatedData
     * @param out_cipherpack
     */
    bool EncryptPack(const std::string &in_plaindata,
                     const std::string &in_associatedData,
                     std::string &out_cipherpack);

    /**
     * DecryptPack
     * 
     * - cipherpack: The cipher data pack to decrypt, including cipher + iv + tag.
     * - associatedData: Extra data associated with this message, which must also be provided during decryption.
     * - plaindata: The decrypted plain data.
     * 
     * @param in_cipherpack
     * @param in_associatedData
     * @param out_plaindata
     */
    bool DecryptPack(const std::string &in_cipherpack,
                     const std::string &in_associatedData,
                     std::string &out_plaindata);
    
    /**
     * @brief Get the Error Message
     *     Use this function to return a detailed error message when an encryption or decryption function fails.
     * 
     * @return std::string 
     */
    std::string GetErrorMessage() const { return error_msg_; }

private:
    std::vector<uint8_t> key_;
    std::string error_msg_;
};


};
};

#endif //SAFEHERON_CRYPTO_GCM_H
