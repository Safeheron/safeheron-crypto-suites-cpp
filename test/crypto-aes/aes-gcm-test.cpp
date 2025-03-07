#include "gtest/gtest.h"
#include "crypto-aes/gcm.h"

using namespace safeheron;
using namespace safeheron::aes;

TEST(aes_gcm, encrypt)
{
    const std::string plain = "This is a test string!";
    const std::string associated_data = "aaaa";
    const std::string key = "12345678901234567890123456789012";
    const std::string iv = "123456789012";
    int tag_len = 0;
    int cipher_len = 0;
    int decrypted_len = 0;
    uint8_t* p_tag = nullptr;
    uint8_t* p_cipher = nullptr;
    uint8_t* p_decrypted = nullptr;
    
    printf("Plain: %s\n", plain.c_str());

    GCM gcm(key);
    gcm.Encrypt((uint8_t*)plain.c_str(), plain.length(), 
                (uint8_t*)iv.c_str(), iv.length(), 
                (uint8_t*)associated_data.c_str(), associated_data.length(), 
                p_tag, tag_len, p_cipher, cipher_len);
    printf("Tag length: %d\n", tag_len);
    printf("Cipher length: %d\n", cipher_len);

    gcm.Decrypt(p_cipher, cipher_len, 
                (uint8_t*)iv.c_str(), iv.length(), 
                (uint8_t*)associated_data.c_str(), associated_data.length(), 
                p_tag, tag_len, 
                p_decrypted, decrypted_len);
    printf("Decrypted: %s\n", p_decrypted);

    EXPECT_TRUE(decrypted_len == (int)plain.length());
    EXPECT_TRUE(memcmp(p_decrypted, plain.c_str(), decrypted_len) == 0);

    delete[] p_decrypted;
    delete[] p_cipher;
    delete[] p_tag;
}


TEST(aes_gcm, encrypt_pack)
{
    const std::string plain = "This is a test string!";
    const std::string associated_data = "aaaa";
    const std::string key = "12345678901234567890123456789012";
    int cipherpack_len = 0;
    int decrypted_len = 0;
    uint8_t* p_cipherpack = nullptr;
    uint8_t* p_decrypted = nullptr;
    
    printf("Plain: %s\n", plain.c_str());

    GCM gcm(key);
    gcm.EncryptPack((uint8_t*)plain.c_str(), plain.length(),
                (uint8_t*)associated_data.c_str(), associated_data.length(),
                p_cipherpack, cipherpack_len);
    printf("Cipher Pack length: %d\n", cipherpack_len);

    gcm.DecryptPack(p_cipherpack, cipherpack_len,
                (uint8_t*)associated_data.c_str(), associated_data.length(), 
                p_decrypted, decrypted_len);
    printf("Decrypted: %s\n", p_decrypted);

    EXPECT_TRUE(decrypted_len == (int)plain.length());
    EXPECT_TRUE(memcmp(p_decrypted, plain.c_str(), decrypted_len) == 0);

    delete[] p_decrypted;
    delete[] p_cipherpack;
}

TEST(aes_gcm, batch_encrypt_pack)
{
    const int KEY_COUNT = 3;
    const int DATA_COUNT = 3;
    const std::string plain[DATA_COUNT] = {"This is a test string!", "&^(%($%))ABC)(*(*(*)))", "1234560987653134000"};
    const std::string key[KEY_COUNT] = {"1234567890123456","123456789012345678901234","12345678901234567890123456789012"};
    const std::string associated_data = "aaaabbbccc";
    std::string cipher_pack;
    std::string decrypted;
    int cipherpack_len = 0;
    int decrypted_len = 0;
    uint8_t* p_cipherpack = nullptr;
    uint8_t* p_decrypted = nullptr;

    for (int i = 0; i < KEY_COUNT; i++) {
        for (int j = 0; j < DATA_COUNT; j ++) {
            GCM gcm(key[i]);
            cipher_pack.clear();
            decrypted.clear();

            gcm.EncryptPack(plain[j], associated_data, cipher_pack);
            printf("Key: %d, Data: %d, Cipher Pack length: %d\n", i+1, j+1, (int)cipher_pack.length());

            gcm.DecryptPack(cipher_pack, associated_data, decrypted);
            printf("Key: %d, Data: %d, Decrypted: %s\n", i+1, j+1, decrypted.c_str());

            EXPECT_TRUE(decrypted.length() == plain[j].length());
            EXPECT_TRUE(decrypted.compare(plain[j])==0);
        }
    }
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}