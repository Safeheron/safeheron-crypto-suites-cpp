#include "gtest/gtest.h"
#include "crypto-suites/crypto-hash/sha512.h"
#include "crypto-suites/crypto-hash/safe_hash512.h"
#include "util-test.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

using safeheron::hash::CSHA512;
using safeheron::hash::CSafeHash512;

static const char hash_input_delimiter = '$';

static void uint_to_byte8(uint8_t buf[8], uint64_t ui){
    // Big endian
    buf[7] = ui & 0x00000000000000ff;
    buf[6] = (ui & 0x000000000000ff00) >> 8;
    buf[5] = (ui & 0x0000000000ff0000) >> 16;
    buf[4] = (ui & 0x00000000ff000000) >> 24;
    buf[3] = (ui & 0x000000ff00000000) >> 32;
    buf[2] = (ui & 0x0000ff0000000000) >> 40;
    buf[1] = (ui & 0x00ff000000000000) >> 48;
    buf[0] = (ui & 0xff00000000000000) >> 56;
}

std::vector<std::string> data_arr = {
        "",
        "1111111111111111111111111111",
        "2222222222222222222222222222",
        "3333333333333333333333333333",
        "4444444444444444444444444444",
        "5555555555555555555555555555",
        "6666666666666666666666666666",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "6666666666666666666666666666666666666666666666666666666666666666"
};

void run_case_2(){
    std::cout << "- case 2: " << std::endl;
    for(size_t total_in_hash = 1; total_in_hash <= data_arr.size(); ++total_in_hash) {
        CSHA512 sha512;
        uint8_t digest[CSHA512::OUTPUT_SIZE];
        for(size_t i = 0; i < total_in_hash; ++i) {
            // (data || len || delimiter)
            uint8_t byte8[8];
            sha512.Write((const unsigned char *)data_arr[i].data(), data_arr[i].size());
            sha512.Write( (const unsigned char *)&hash_input_delimiter, 1);
            uint_to_byte8(byte8, data_arr[i].size());
            sha512.Write( byte8, 8);
        }
        // (num)
        uint8_t byte8[8];
        uint_to_byte8(byte8, total_in_hash);
        sha512.Write( byte8, 8);
        sha512.Finalize(digest);


        CSafeHash512 safe_hash;
        uint8_t safe_digest[CSafeHash512::OUTPUT_SIZE];
        for(size_t i = 0; i < total_in_hash; ++i) {
            // data
            safe_hash.Write((const unsigned char *)data_arr[i].data(), data_arr[i].size());
        }
        safe_hash.Finalize(safe_digest);

        std::string digest_hex_1 = bytes2hex(digest, CSHA512::OUTPUT_SIZE);
        std::string digest_hex_2 = bytes2hex(safe_digest, CSHA512::OUTPUT_SIZE);

        EXPECT_TRUE(memcmp(digest, safe_digest, CSHA512::OUTPUT_SIZE) == 0);
        std::cout << "digest_1 = " << digest_hex_1 << std::endl;
        std::cout << "digest_2 = " << digest_hex_2 << std::endl;
    }
}

void run_case_1(){
    // SafeHash(0x01,0x02)
    CSafeHash512 safe_hash;
    uint8_t safe_digest[CSafeHash512::OUTPUT_SIZE];
    uint8_t raw_data[2] = {0x01, 0x02};
    safe_hash.Write(raw_data, 2);
    safe_hash.Finalize(safe_digest);

    // Hash(0x01,0x02 || delimiter || len || 0x00000001)
    CSHA512 sha512;
    uint8_t digest[CSHA512::OUTPUT_SIZE];
    // data = (raw_data || '$' || len || n)
    uint8_t data[19] = {0x01, 0x02, '$', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    sha512.Write( (const unsigned char *)data, sizeof data);
    sha512.Finalize(digest);


    std::string digest_hex_1 = bytes2hex(digest, CSHA512::OUTPUT_SIZE);
    std::string digest_hex_2 = bytes2hex(safe_digest, CSHA512::OUTPUT_SIZE);
    std::cout << "- case 1: " << std::endl;
    std::cout << "digest_1 = " << digest_hex_1 << std::endl;
    std::cout << "digest_2 = " << digest_hex_2 << std::endl;

    EXPECT_TRUE(memcmp(digest, safe_digest, CSHA512::OUTPUT_SIZE) == 0);
}

TEST(HASH, SHA512)
{
    run_case_1();
    run_case_2();
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
