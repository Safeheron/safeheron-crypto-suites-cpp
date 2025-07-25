#include "gtest/gtest.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-bip39/wally_bip39.h"
#include "crypto-suites/crypto-bip39/wordlist.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-bip39/internal.h"

TEST(bip39, words) {
    //test bip39_get_languages
    char *lang = nullptr;
    bip39_get_languages(&lang);
    if(lang) {
        printf("supported languages: %s\n", lang);
    }
    wally_free(lang);

    //test bip39_get_wordlists
    struct words *en_words = nullptr, *zhs_words = nullptr, *zht_words = nullptr;
    bip39_get_wordlist("en", &en_words);
    bip39_get_wordlist("zhs", &zhs_words);
    bip39_get_wordlist("zht", &zht_words);
    //compare the first word
    EXPECT_TRUE(strcmp(en_words->str, "abandon") == 0);
    EXPECT_TRUE(strcmp(zhs_words->str, "的") == 0);
    EXPECT_TRUE(strcmp(zht_words->str, "的") == 0);

    //test bip39_get_word
    char *en_word = nullptr, *zhs_word = nullptr, *zht_word = nullptr;
    bip39_get_word(en_words, 12, &en_word);
    bip39_get_word(zhs_words, 12, &zhs_word);
    bip39_get_word(zht_words, 12, &zht_word);
    EXPECT_TRUE(strcmp(en_word, "account") == 0);
    EXPECT_TRUE(strcmp(zhs_word, "为") == 0);
    EXPECT_TRUE(strcmp(zht_word, "為") == 0);

    wally_free(en_word);
    wally_free(zhs_word);
    wally_free(zht_word);
}

void mnemonicTest(const char* lang, size_t count) {
    struct words *lang_words = nullptr;
    bip39_get_wordlist(lang, &lang_words);

    for (size_t i = 0; i < count; ++i) {
        char *mnemonic = nullptr;
        const int ENTROPY_SIZE = BIP39_ENTROPY_LEN_256;
        uint8_t bytes[ENTROPY_SIZE];
        safeheron::rand::RandomBytes(bytes, ENTROPY_SIZE); //132 12
        bip39_mnemonic_from_bytes(lang_words, bytes, ENTROPY_SIZE, &mnemonic);

        uint8_t bytes_out[ENTROPY_SIZE];
        size_t written; // written to bytes_out
        int ret = bip39_mnemonic_validate(lang_words, mnemonic);
        EXPECT_TRUE(ret == WALLY_OK);
        bip39_mnemonic_to_bytes(lang_words, mnemonic, bytes_out, sizeof(bytes_out), &written);
        std::string bytes_str, bytes_out_str;
        bytes_str = safeheron::encode::hex::EncodeToHex(bytes, ENTROPY_SIZE);
        bytes_out_str = safeheron::encode::hex::EncodeToHex(bytes_out, ENTROPY_SIZE);
        EXPECT_TRUE(strncmp(bytes_str.c_str(), bytes_out_str.c_str(), ENTROPY_SIZE * 2) == 0);
        wally_free(mnemonic);
    }
}

TEST(bip39, mnemonic) {
    mnemonicTest("en", 1000);
    mnemonicTest("zhs", 1000);
    mnemonicTest("zht", 1000);
}

TEST(bip39, en) {
    struct words *en_words = nullptr;
    char *mnemonic = nullptr;

    bip39_get_wordlist("en", &en_words);

    uint8_t bytes[16] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    bip39_mnemonic_from_bytes(en_words, bytes, 16, &mnemonic);
    std::string expected_mnemonic = "abandon math mimic master filter design carbon crystal rookie group knife young";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);

    for(int i = 0; i < 16; i++) {
        bytes[i] = 16 - 1 - i;
    }
    bip39_mnemonic_from_bytes(en_words, bytes, 16, &mnemonic);
    expected_mnemonic = "audit idea drink bid party lottery bright scheme advice blossom leopard ability";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);
}

TEST(bip39, zhs) {
    struct words *zhs_words = nullptr;
    char *mnemonic = nullptr;

    bip39_get_wordlist("zhs", &zhs_words);

    uint8_t bytes[16] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    bip39_mnemonic_from_bytes(zhs_words, bytes, 16, &mnemonic);
    std::string expected_mnemonic = "的 雄 粗 尺 载 属 海 酸 柯 沙 赶 艇";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);

    for(int i = 0; i < 16; i++) {
        bytes[i] = 16 - 1 - i;
    }
    bip39_mnemonic_from_bytes(zhs_words, bytes, 16, &mnemonic);
    expected_mnemonic = "那 希 落 最 钻 塔 知 伐 对 象 泽 一";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);
}

TEST(bip39, zht) {
    struct words *zht_words = nullptr;
    char *mnemonic = nullptr;

    bip39_get_wordlist("zht", &zht_words);

    uint8_t bytes[16] = {0x00,0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    bip39_mnemonic_from_bytes(zht_words, bytes, 16, &mnemonic);
    std::string expected_mnemonic = "的 雄 粗 尺 載 屬 海 酸 柯 沙 趕 艇";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);

    for(int i = 0; i < 16; i++) {
        bytes[i] = 16 - 1 - i;
    }
    bip39_mnemonic_from_bytes(zht_words, bytes, 16, &mnemonic);
    expected_mnemonic = "那 希 落 最 鑽 塔 知 伐 對 象 澤 一";
    EXPECT_TRUE(strcmp(mnemonic, expected_mnemonic.c_str()) == 0);
    wally_free(mnemonic);
}

TEST(bip39, long_entropy_36) {
    struct words *en_words = nullptr;
    struct words *zhs_words = nullptr;
    struct words *zht_words = nullptr;

    bip39_get_wordlist("en", &en_words);
    bip39_get_wordlist("zhs", &zhs_words);
    bip39_get_wordlist("zht", &zht_words);

    char* mnemonic = nullptr;
    uint8_t bytes_out[36];

    uint8_t bytes[36] = {0xdc,0xe4,0x26, 0x39, 0x44, 0xaf, 0x36, 0x56, 0x88, 0xac, 0xff, 0x34, 0x79, 0x26, 0xde, 0x99, 0x42, 0xf9, 0xf7, 0xed, 0xfd,
                         0x19, 0xe1, 0xe4, 0xf3, 0x4f, 0x90, 0x34, 0xdd, 0xe1, 0x32, 0xf9, 0x32, 0xf1, 0x34, 0x26};

    std::string expected_mnemonic = "table cancel mixture matter vibrant clip cargo paper crucial since response crater convince winner retire permit tiger chest stadium call evidence vacuum slogan chaos van patrol possible";
    bip39_mnemonic_from_bytes(en_words, bytes, 36, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    size_t written;
    bip39_mnemonic_to_bytes(en_words, mnemonic, bytes_out, 36, &written);
    for (int i = 0; i < 36; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);

    expected_mnemonic = "棱 即 碎 泛 骑 科 东 冰 般 纠 妹 千 织 疫 珍 售 纬 花 穗 队 富 丢 凤 采 挡 郭 摩";
    bip39_mnemonic_from_bytes(zhs_words, bytes, 36, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    bip39_mnemonic_to_bytes(zhs_words, mnemonic, bytes_out, 36, &written);
    for (int i = 0; i < 36; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);

    expected_mnemonic = "棱 即 碎 泛 騎 科 東 冰 般 糾 妹 千 織 疫 珍 售 緯 花 穗 隊 富 丟 鳳 採 擋 郭 摩";
    bip39_mnemonic_from_bytes(zht_words, bytes, 36, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    bip39_mnemonic_to_bytes(zht_words, mnemonic, bytes_out, 36, &written);
    for (int i = 0; i < 36; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);
}

TEST(bip39, long_entropy_40) {
    struct words *en_words = nullptr;
    struct words *zhs_words = nullptr;
    struct words *zht_words = nullptr;

    bip39_get_wordlist("en", &en_words);
    bip39_get_wordlist("zhs", &zhs_words);
    bip39_get_wordlist("zht", &zht_words);

    char* mnemonic = nullptr;
    uint8_t bytes_out[40];

    uint8_t bytes[40] = {0xdc,0xe4,0x26, 0x39, 0x44, 0xaf, 0x36, 0x56, 0x88, 0xac, 0xff, 0x34, 0x79, 0x26, 0xde, 0x99, 0x42, 0xf9, 0xf7, 0xed, 0xfd,
                         0x19, 0xe1, 0xe4, 0xf3, 0x4f, 0x90, 0x34, 0xdd, 0xe1, 0x32, 0xf9, 0x32, 0xf1, 0x34, 0x26, 0x98, 0x97, 0x96, 0x11};

    std::string expected_mnemonic = "table cancel mixture matter vibrant clip cargo paper crucial since response crater convince winner retire permit tiger chest stadium call evidence vacuum slogan chaos van patrol plate connect genre similar";
    bip39_mnemonic_from_bytes(en_words, bytes, 40, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    size_t written;
    bip39_mnemonic_to_bytes(en_words, mnemonic, bytes_out, 40, &written);
    for (int i = 0; i < 40; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);

    expected_mnemonic = "棱 即 碎 泛 骑 科 东 冰 般 纠 妹 千 织 疫 珍 售 纬 花 穗 队 富 丢 凤 采 挡 郭 柴 究 稳 掘";
    bip39_mnemonic_from_bytes(zhs_words, bytes, 40, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    bip39_mnemonic_to_bytes(zhs_words, mnemonic, bytes_out, 40, &written);
    for (int i = 0; i < 40; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);

    expected_mnemonic = "棱 即 碎 泛 騎 科 東 冰 般 糾 妹 千 織 疫 珍 售 緯 花 穗 隊 富 丟 鳳 採 擋 郭 柴 究 穩 掘";
    bip39_mnemonic_from_bytes(zht_words, bytes, 40, &mnemonic);
    EXPECT_TRUE(strcmp(expected_mnemonic.c_str(), mnemonic) == 0);
    bip39_mnemonic_to_bytes(zht_words, mnemonic, bytes_out, 40, &written);
    for (int i = 0; i < 40; ++i) {
        EXPECT_TRUE(bytes_out[i] == bytes[i]);
    }
    wally_free(mnemonic);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}

