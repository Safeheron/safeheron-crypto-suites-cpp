#include <vector>
#include <string>

#include "gtest/gtest.h"
#include "crypto-hash/shake128.h"
#include "../utils/HexUtil.h"
#include "shake128_vectors_pretty.h"

using ssgx_test::utils::BytesToHex;
using ssgx_test::utils::HexToBytes;

TEST(hash, shake128) {
    for (const auto& vec : shake128_vectors) {
        const std::string& expected_hex = vec.expected_hex;
        const std::string& input_hex = vec.input_hex;
        size_t input_byte_len = vec.input_bit_len / 8;
        size_t out_len = vec.output_byte_len;

        std::vector<uint8_t> input_bytes = HexToBytes(input_hex);

        safeheron::hash::CShake128 shake128(out_len);
        shake128.Write(input_bytes.data(), input_byte_len);
        std::vector<uint8_t> digest = shake128.Finalize();
        EXPECT_STRCASEEQ(BytesToHex(digest.data(), out_len).c_str(), expected_hex.c_str());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}