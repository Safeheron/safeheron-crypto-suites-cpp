#include <vector>
#include "gtest/gtest.h"
#include "official_test_data.h"
#include "crypto-bip39/bip39.h"
#include "crypto-encode/hex.h"

TEST(bip39, offical_english_menmonic_test) {
    std::vector<std::vector<std::string>> &entropy_mnemonic_vec = english_mnemonic_vec;
    bool ok;
    for (size_t i = 0; i < entropy_mnemonic_vec.size(); ++i) {
        std::string mnemonic;
        ok = safeheron::bip39::BytesToMnemonic(mnemonic,
                                               safeheron::encode::hex::DecodeFromHex(entropy_mnemonic_vec[i][0]),
                                               safeheron::bip39::Language::ENGLISH);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][1] == mnemonic);
        std::string bytes;
        ok = safeheron::bip39::MnemonicToBytes(bytes,
                                               entropy_mnemonic_vec[i][1],
                                               safeheron::bip39::Language::ENGLISH);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][0] == safeheron::encode::hex::EncodeToHex(bytes));
    }
}

TEST(bip39, offical_simplified_chinese_menmonic_test) {
    std::vector<std::vector<std::string>> &entropy_mnemonic_vec = simplified_chinese_mnemonic_vec;
    bool ok;
    for (size_t i = 0; i < entropy_mnemonic_vec.size(); ++i) {
        std::string mnemonic;
        ok = safeheron::bip39::BytesToMnemonic(mnemonic,
                                               safeheron::encode::hex::DecodeFromHex(entropy_mnemonic_vec[i][0]),
                                               safeheron::bip39::Language::SIMPLIFIED_CHINESE);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][1] == mnemonic);
        std::string bytes;
        ok = safeheron::bip39::MnemonicToBytes(bytes,
                                               entropy_mnemonic_vec[i][1],
                                               safeheron::bip39::Language::SIMPLIFIED_CHINESE);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][0] == safeheron::encode::hex::EncodeToHex(bytes));
    }
}

TEST(bip39, offical_traditional_chinese_menmonic_test) {
    std::vector<std::vector<std::string>> &entropy_mnemonic_vec = traditional_chinese_mnemonic_vec;
    bool ok;
    for (size_t i = 0; i < entropy_mnemonic_vec.size(); ++i) {
        std::string mnemonic;
        ok = safeheron::bip39::BytesToMnemonic(mnemonic,
                                               safeheron::encode::hex::DecodeFromHex(entropy_mnemonic_vec[i][0]),
                                               safeheron::bip39::Language::TRADITIONAL_CHINESE);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][1] == mnemonic);
        std::string bytes;
        ok = safeheron::bip39::MnemonicToBytes(bytes,
                                               entropy_mnemonic_vec[i][1],
                                               safeheron::bip39::Language::TRADITIONAL_CHINESE);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(entropy_mnemonic_vec[i][0] == safeheron::encode::hex::EncodeToHex(bytes));
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
