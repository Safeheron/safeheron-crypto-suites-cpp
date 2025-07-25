#include <vector>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bip39/bip39.h"
#include "ventropy_28.h"
#include "vmnemonic_en_21.h"
#include "vmnemonic_zhs_21.h"
#include "vmnemonic_zht_21.h"
#include "crypto-suites/crypto-encode/hex.h"

TEST(bip39, verify_28bytes) {
    for(int i = 0; i < 1000; ++i) {
        std::string mnemonic;
        std::string bytes_out;

        std::string bytes = safeheron::encode::hex::DecodeFromHex(ventropy_28[i]);

        bool ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, safeheron::bip39::Language::ENGLISH);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(mnemonic == vmnemonic_en_21[i]);
        ret = safeheron::bip39::MnemonicToBytes(bytes_out, vmnemonic_en_21[i], safeheron::bip39::Language::ENGLISH);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(bytes_out == bytes);

        ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, safeheron::bip39::Language::SIMPLIFIED_CHINESE);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(mnemonic == vmnemonic_zhs_21[i]);
        ret = safeheron::bip39::MnemonicToBytes(bytes_out, vmnemonic_zhs_21[i], safeheron::bip39::Language::SIMPLIFIED_CHINESE);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(bytes_out == bytes);

        ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, safeheron::bip39::Language::TRADITIONAL_CHINESE);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(mnemonic == vmnemonic_zht_21[i]);
        ret = safeheron::bip39::MnemonicToBytes(bytes_out, vmnemonic_zht_21[i], safeheron::bip39::Language::TRADITIONAL_CHINESE);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(bytes_out == bytes);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
