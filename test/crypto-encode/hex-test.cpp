#include <cstring>
#include "gtest/gtest.h"
#include "crypto-encode/base64.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/hex_imp.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

std::vector<std::string> valid_hex_vec = {
        "01",
        "012345",
        "0123456789",
        "0123456789abcd",
        "0123456789abcdef01",
        "0123456789abcdef012345",
        "0123456789abcdef0123456789",
        "0123456789abcdef0123456789abcdef",
};

void test_valid_hex(const std::string &hex){
    std::string bin = safeheron::encode::hex::DecodeFromHex(hex);
    std::string hex2 = safeheron::encode::hex::EncodeToHex(bin);
    std::string bin2 = safeheron::encode::hex::DecodeFromHex(hex2);
    EXPECT_TRUE( bin.length() == bin2.length());
    EXPECT_TRUE( 0 == memcmp(bin.c_str(), bin2.c_str(), bin.length()) );
    EXPECT_TRUE( hex.length() == hex2.length());
    EXPECT_TRUE( 0 == memcmp(hex.c_str(), hex2.c_str(), hex.length()) );
}

TEST(Hex, Valid_Hex)
{
    for(auto& hex: valid_hex_vec){
        test_valid_hex(hex);
    }
}

std::vector<std::string> invalid_hex_vec = {
        "0",
        "012",
};

void test_invalid_hex(const std::string &hex){
    try{
        std::string bin = safeheron::encode::hex::DecodeFromHex(hex);
        std::string hex2 = safeheron::encode::hex::EncodeToHex(bin);
        std::string bin2 = safeheron::encode::hex::DecodeFromHex(hex2);
        EXPECT_TRUE( bin.length() == bin2.length());
        EXPECT_TRUE( 0 == memcmp(bin.c_str(), bin2.c_str(), bin.length()) );
        EXPECT_TRUE( hex.length() == hex2.length());
        EXPECT_TRUE( 0 == memcmp(hex.c_str(), hex2.c_str(), hex.length()) );

        EXPECT_TRUE(false);
    }catch (const std::exception &e){
        std::cout << "exception: " << e.what() << std::endl;
    }
}

TEST(Hex, Invalid_Hex)
{
    for(auto& hex: invalid_hex_vec){
        test_invalid_hex(hex);
    }
}

/** Invalid char out of "0123456789abcdefABCDEF" is tread as 0 **/
std::vector<std::vector<std::string>> special_hex_vec = {
        {"1X", "10"},
        {"1Y24", "1024"},
        {"123456M8", "12345608"},
};

void test_special_hex(const std::string &left, const std::string &right){
        std::string bin = safeheron::encode::hex::DecodeFromHex(left);
        std::string hex = safeheron::encode::hex::EncodeToHex(bin);
        std::cout << hex << std::endl;
        EXPECT_TRUE( hex.length() == right.length());
        EXPECT_TRUE( 0 == memcmp(hex.c_str(), right.c_str(), hex.length()) );

}

TEST(Hex, Test_Special_Hex)
{
    for(auto& pair: special_hex_vec){
        const std::string left = pair[0];
        const std::string right = pair[1];
        test_special_hex(left, right);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
