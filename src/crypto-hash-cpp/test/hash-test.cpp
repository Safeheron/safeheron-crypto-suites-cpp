//
// Created by Sword03 on 2020/10/22.
//
#include "gtest/gtest.h"
#include "../src/crypto-hash/sha256.h"
#include "util-test.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

using safeheron::hash::CSHA256;

std::vector<std::vector<std::string>> test_case_for_sha256 = {
        {
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
};

void run_case(const uint8_t * input, size_t  input_len, const char * expected_digest_hex){
    CSHA256 sha256;
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    sha256.Write(input, input_len);
    sha256.Finalize(digest);

    std::string digest_hex = bytes2hex(digest, CSHA256::OUTPUT_SIZE);

    EXPECT_TRUE(strcmp(expected_digest_hex, digest_hex.c_str()) == 0);
}

TEST(HASH, SHA256)
{
    for(const auto &data: test_case_for_sha256) {
        const uint8_t * input = reinterpret_cast<const uint8_t *>(data[0].c_str());
        size_t  input_len = data[0].length();
        const char * expected_digest_hex = data[1].c_str();
        run_case(input, input_len, expected_digest_hex);
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
