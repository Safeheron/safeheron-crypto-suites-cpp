//
// Created by EDY on 2024/6/13.
//

#include "gtest/gtest.h"
#include "crypto-hash/keccak256.h"
#include "crypto-encode/hex.h"
#include "util-test.h"

struct DigestMessage {
    const char* data;
    const char* expected_value;
};

DigestMessage digest_message_arr[] = {

        // The test cases are from https://github.com/ethereum/js-ethereum-cryptography and https://github.com/emn178/js-sha3.
        {
                "",
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        },

        {
                "A",
                "03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760"
        },

        {
                "asd",
                "87c2d362de99f75a4f2755cdaaad2d11bf6cc65dc71356593c445535ff28f43d"
        },

        {
                "The quick brown fox jumps over the lazy dog",
                "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        },

        {
                "The quick brown fox jumps over the lazy dog.",
                "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"
        },

        // more than 128 bytes
        {
                "The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.",
                "e35949d2ca446ea2fd99f49bed23c60e0b9849f5384661bc574a5c55fcaeb4bd"
        },

        {
                "The MD5 message-digest algorithm is a widely used cryptographic hash function producing a 128-bit (16-byte) hash value, typically expressed in text format as a 32 digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications, and is also commonly used to verify data integrity.",
                "af20018353ffb50d507f1555580f5272eca7fdab4f8295db4b1a9ad832c93f6d"
        },

        // utf-8
        {
                "中文",
                "70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eee"
        },

        {
                "aécio",
                "d7d569202f04daf90432810d6163112b2695d7820da979327ebd894efb0276dc"
        },

        {
                "\xF0\xA0\x9C\x8E",
                "16a7cc7a58444cbf7e939611910ddc82e7cba65a99d3e8e08cfcda53180a2180"
        },

        // utf-8 more than 128 bytes
        {
                "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一",
                "d1021d2d4c5c7e88098c40f422af68493b4b64c913cbd68220bf5e6127c37a88"
        },

        {
                "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。",
                "ffabf9bba2127c4928d360c9905cb4911f0ec21b9c3b89f3b242bccc68389e36"
        }


};

void run_case(struct DigestMessage& digest_message, uint8_t hash[32]) {
    safeheron::hash::CKeccak256 keccak256;
    keccak256.Write((uint8_t*)digest_message.data, strlen(digest_message.data));
    keccak256.Finalize(hash);
}


TEST(hash, keccak256){
    uint8_t hash[32];
    for (auto& it: digest_message_arr) {
        memset(hash, 0, 32);
        run_case(it, hash);
        EXPECT_TRUE(safeheron::encode::hex::EncodeToHex(hash, 32) == it.expected_value);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
