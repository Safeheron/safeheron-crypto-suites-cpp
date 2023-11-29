#include <cstring>
#include "gtest/gtest.h"
#include "crypto-encode/base58.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

using namespace safeheron::encode;

void test_base58(const std::string &expected_data, const std::string &expected_b58){
    //encode
    std::cout << expected_data.length() << std::endl;
    std::string b58 = base58::EncodeToBase58(expected_data);
    EXPECT_EQ(b58, expected_b58);

    // decode
    std::string data = base58::DecodeFromBase58(b58);
    EXPECT_EQ(data, expected_data);

}

TEST(Base58, ToBase58_FromBase58)
{
    //test("", "");
    test_base58("hello world", "StV1DL6CwTryKyV");
}

void test_base58_check(const std::string &expected_data, const std::string &expected_b58){
    //encode
    std::cout << expected_data.length() << std::endl;
    std::string b58 = base58::EncodeToBase58Check(expected_data);
    EXPECT_EQ(b58, expected_b58);

    // decode
    std::string data = base58::DecodeFromBase58Check(b58);
    EXPECT_EQ(data, expected_data);

}

TEST(Base58Check, ToBase58Check_FromBase58Check)
{
    //test("", "");
    test_base58_check("hello world", "3vQB7B6MrGQZaxCuFg4oh");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
