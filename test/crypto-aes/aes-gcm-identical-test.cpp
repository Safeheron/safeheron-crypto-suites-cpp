#include "gtest/gtest.h"
#include "crypto-suites/crypto-aes/gcm.h"
#include "crypto-suites/crypto-encode/hex.h"

using namespace safeheron;
using namespace safeheron::aes;
using namespace safeheron::encode;
std::string bytes_to_hex(const std::string &bytes) {
    return safeheron::encode::hex::EncodeToHex(bytes);
}
std::string bytes_to_hex(const uint8_t* bytes, size_t len) {
    return safeheron::encode::hex::EncodeToHex(bytes, len);
}
std::string hex_to_bytes(const std::string &hex) {
    return safeheron::encode::hex::DecodeFromHex(hex);
}

// Test data references: https://github.com/weidai11/cryptopp/blob/master/TestVectors/gcm.txt
std::vector<std::vector<std::string>> key_128_data = {
        {
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf"
        },
        {
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4"
        },
        {
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47"
        },
};

std::vector<std::vector<std::string>> key_192_data = {
        {
                "000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "",
                "00000000000000000000000000000000",
                "98e7247c07f0fe411c267e4384b0f600",
                "2ff58d80033927ab8ef4d4587514f0fb"
        },
        {
                "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                "cafebabefacedbaddecaf888",
                "",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
                "9924a7c8587336bfb118024db8674a14"
        },
        {
                "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                "cafebabefacedbaddecaf888",
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
                "2519498e80f1478f37ba55bd6d27618c"
        },
};

std::vector<std::vector<std::string>> key_256_data = {
        {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "",
                "00000000000000000000000000000000",
                "cea7403d4d606b6e074ec5d3baf39d18",
                "d0d1c8a799996bf0265b98b5d48ab919"
        },
        {
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                "",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                "b094dac5d93471bdec1a502270e3cc6c"
        },
        {
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b"
        },
};

std::vector<std::vector<std::string>> long_test_vector = {
        {
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "",
            "006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "BD70C168B0D4371B0A85B4B5D65D92569B17F9A3D0A25B9F608E2C34621CF4D37357845431E04E585CDAAD7527BF8A2426DEEF451320C78D5EF09F5B11A8B8C700CD329A3D4CDED92C20F6BF28CB3627681C5B0AF2B5692CC7EC9049008ACBBD127A9CD8DEF00425697E0BCF67E05AEE70EA1A5D7EE95E3B88FBAF3C196AAAECB73E09BDF057AF701A0242394BCC104FF4F75F15D287325FCFFDB7E7FF3A939A80A6A3A9D7570E6EF6AD0BBE6E291338938D2FEBBC7D5EE95CD73E752ACD48915DCAE0A0807E6F4B2ADADBD945667318264EF7D8C2ECC0B8FB67A43614C5F5EA51CADD4AEE91DC371A7FC5A3B4581D1D9DD99608CD2BB0338F82933C19F5B8EBAD6BBA583835FBD29136302BAC163F86CA9E3E6F3B5BFDEFAB3E4B019190AE2EBC0B71034EA9BF882879139FFE76DD997F6729425F3D5C5392762C245769D18CC963C92211B71F564203AFBF68626C0833031D449B02DFA5C0F09FAFCE951FE35F4AD8122AB682A4AF28931113F75615E12DB05DD9247973F1C6057666848C13EDE41192F38948366D468D84CAF896EFF724082D2BAB2376E2813B41A014999B0EE7377758715D9554926AB3514EEB96A0ABD501D94A05692D858190D5AD307CEB6E6C8A63841A8257BEC2527C4B937840AA51292E15834AB801F0275A6A4B1B6E969B7A7FCE217D6F823CDE1760F847E8F46CBDE152A24F2319EC2A7089D2954259D30332089FF928034391D1B0B8AFD7C8A5D4F8E0DAB5883CA7D581F78E4848DC3B01E5F2A5C01BA8910D0F144BC494E29450271174B866868EE8DC6B0DD396ED9D72F83DE3BB6DE6FEBC64178961E011D0D746C2CE3A0FBD05CDF8FA79AC03E94C88368BD903E1427FCFC30C9D100E220B4CB9B7BA242DA49D334E930B6C4EB877D1DF2C0F8CF4AF7813E2F29592970719846FC52A47FCE6E71DC5E58FC5F49C91BDE56B7A2A68CFA994D6BFA5357A8403A2B37C69A6A0A435E4AB4C9E450473AF0CDFDBCC238A2DD7",
            "4FEA89D75727E82B3A9F9EEB5E217A3E"
        }
};

void test_aes_gcm_identical_data(const std::vector<std::vector<std::string>> &test_data) {
    for (size_t i = 0; i < test_data.size(); ++i) {
        std::string key = hex_to_bytes(test_data[i][0]);
        std::string iv = hex_to_bytes(test_data[i][1]);
        std::string AAD = hex_to_bytes(test_data[i][2]);
        std::string plain = hex_to_bytes(test_data[i][3]);
        std::string cipher = hex_to_bytes(test_data[i][4]);
        std::string tag = hex_to_bytes(test_data[i][5]);
        //
        int tag_len = 0;
        int cipher_len = 0;
        int decrypted_data_len = 0;
        uint8_t* p_tag = nullptr;
        uint8_t* p_cipher = nullptr;
        uint8_t* p_decrypted_data = nullptr;

        GCM gcm(key);
        if (AAD.empty()) {
            gcm.Encrypt((uint8_t *) plain.c_str(), plain.length(),
                        (uint8_t *) iv.c_str(), iv.length(),
                        nullptr, 0,
                        p_tag, tag_len, p_cipher, cipher_len);
        } else {
            gcm.Encrypt((uint8_t *) plain.c_str(), plain.length(),
                        (uint8_t *) iv.c_str(), iv.length(),
                        (uint8_t *) AAD.c_str(), AAD.length(),
                        p_tag, tag_len, p_cipher, cipher_len);
        }
        EXPECT_TRUE((tag_len == (int)tag.length()) && (memcmp(p_tag, tag.c_str(), tag_len) == 0));
        EXPECT_TRUE((cipher_len == (int)cipher.length()) && (memcmp(p_cipher, cipher.c_str(), cipher_len) == 0));

        if (AAD.empty()) {
            gcm.Decrypt(p_cipher, cipher_len,
                        (uint8_t *) iv.c_str(), iv.length(),
                        nullptr, 0,
                        p_tag, tag_len,
                        p_decrypted_data, decrypted_data_len);
        } else {
            gcm.Decrypt(p_cipher, cipher_len,
                        (uint8_t *) iv.c_str(), iv.length(),
                        (uint8_t *) AAD.c_str(), AAD.length(),
                        p_tag, tag_len,
                        p_decrypted_data, decrypted_data_len);
        }
        EXPECT_TRUE((decrypted_data_len == (int)plain.length()) && memcmp(p_decrypted_data, plain.c_str(), decrypted_data_len) == 0);

        std::cout << "Encrypt:" << std::endl;
        std::cout << "Key: " << bytes_to_hex(key) << std::endl;
        std::cout << "IV: "  << bytes_to_hex(iv) << std::endl;
        std::cout << "AAD: "  << bytes_to_hex(AAD) << std::endl;
        std::cout << "Plaintext: " << bytes_to_hex(p_decrypted_data, decrypted_data_len) << std::endl;
        std::cout << "Ciphertext: " << bytes_to_hex(p_cipher, cipher_len) << std::endl;
        std::cout << "tag: " << bytes_to_hex(p_tag, tag_len) << std::endl;

        delete[] p_cipher;
        delete[] p_decrypted_data;
        delete[] p_tag;
    }
}

TEST(aes_gcm, identical_test)
{
    test_aes_gcm_identical_data(key_128_data);
    test_aes_gcm_identical_data(key_192_data);
    test_aes_gcm_identical_data(key_256_data);
    //test_aes_gcm_identical_data(long_test_vector);
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}