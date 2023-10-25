#include <vector>
#include "gtest/gtest.h"
#include "crypto-bip39/bip39.h"

TEST(bip39, BytesToMnemonic) {
    uint8_t bytes[32] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    std::string mnemonic;
    std::string expected_mnemonic;

    bool ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, sizeof(bytes), safeheron::bip39::Language::ENGLISH);
    expected_mnemonic = "abandon math mimic master filter design carbon crystal rookie group knife wrap absurd much snack melt grid rough chapter fever rubber humble room trophy";
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mnemonic == expected_mnemonic);

    ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, sizeof(bytes), safeheron::bip39::Language::SIMPLIFIED_CHINESE);
    expected_mnemonic = "的 雄 粗 尺 载 属 海 酸 柯 沙 赶 祸 人 桥 滩 典 欢 悲 转 找 票 促 页 亭";
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mnemonic == expected_mnemonic);

    ret = safeheron::bip39::BytesToMnemonic(mnemonic, bytes, sizeof(bytes), safeheron::bip39::Language::TRADITIONAL_CHINESE);
    expected_mnemonic = "的 雄 粗 尺 載 屬 海 酸 柯 沙 趕 禍 人 橋 灘 典 歡 悲 轉 找 票 促 頁 亭";
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mnemonic == expected_mnemonic);
}

TEST(bip39, MnemonicToBytes) {
    std::string bytes_out;
    std::string mnemonic;
    uint8_t expected_bytes[32] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    std::string bytes_str((const char*)expected_bytes, 32);

    mnemonic = "abandon math mimic master filter design carbon crystal rookie group knife wrap absurd much snack melt grid rough chapter fever rubber humble room trophy";
    bool ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::ENGLISH);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);

    mnemonic = "的 雄 粗 尺 载 属 海 酸 柯 沙 赶 祸 人 桥 滩 典 欢 悲 转 找 票 促 页 亭";
    ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::SIMPLIFIED_CHINESE);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);

    mnemonic = "的 雄 粗 尺 載 屬 海 酸 柯 沙 趕 禍 人 橋 灘 典 歡 悲 轉 找 票 促 頁 亭";
    ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::TRADITIONAL_CHINESE);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);
}

TEST(bip39, MnemonicWithSpaces) {
    std::string bytes_out;
    std::string mnemonic;

    uint8_t expected_bytes[32] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    std::string bytes_str((const char*)expected_bytes, 32);

    mnemonic = "  abandon  math mimic  master filter design carbon crystal  rookie group knife wrap absurd  much snack melt grid rough chapter fever rubber humble room   trophy    ";
    bool ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::ENGLISH);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);

    mnemonic = "  的  雄 粗 尺 载 属 海 酸 柯 沙 赶        祸 人 桥   滩 典 欢 悲 转 找 票 促 页  亭  ";
    ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::SIMPLIFIED_CHINESE);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);

    mnemonic = " 的  雄 粗 尺 載 屬 海 酸 柯 沙 趕  禍 人   橋  灘 典 歡 悲 轉  找 票 促 頁 亭  ";
    ret = safeheron::bip39::MnemonicToBytes(bytes_out, mnemonic, safeheron::bip39::Language::TRADITIONAL_CHINESE);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bytes_str == bytes_out);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}

