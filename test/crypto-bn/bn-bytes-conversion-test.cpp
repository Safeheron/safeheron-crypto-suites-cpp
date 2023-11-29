#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

TEST(BN, ByteConversion) {
    std::string str_buf = "cba";
    uint8_t ch_buf[10];
    ch_buf[0] = 'c';
    ch_buf[1] = 'b';
    ch_buf[2] = 'a';
    BN bn_big_endian("636261", 16);
    BN bn_little_endian("616263", 16);
    BN bn1 = BN::FromBytesBE(ch_buf, 3);
    BN bn2 = BN::FromBytesBE(str_buf);
    BN bn3 = BN::FromBytesLE(ch_buf,3);
    BN bn4 = BN::FromBytesLE(str_buf);
    EXPECT_EQ(bn1, bn_big_endian);
    EXPECT_EQ(bn2, bn_big_endian);
    EXPECT_EQ(bn3, bn_little_endian);
    EXPECT_EQ(bn4, bn_little_endian);
    BN bn5("0100001001000100", 2);
    std::string str_big_endian = "";
    std::string str_little_endian = "";
    bn5.ToBytesBE(str_big_endian);
    bn5.ToBytesLE(str_little_endian);
    EXPECT_EQ(str_big_endian, "BD");
    EXPECT_EQ(str_little_endian, "DB");
    BN bn6("1011110011000111", 2);
    uint8_t expected_big_endian[2] = { 0xbc, 0xc7};
    uint8_t expected_little_endian[2] = { 0xc7, 0xbc};
    bn6.ToBytesBE(str_big_endian);
    bn6.ToBytesLE(str_little_endian);
    std::cout << "str_big_endian: " << str_big_endian << std::endl;
    std::cout << "str_little_endian: " << str_little_endian << std::endl;
    for(int i = 0; i < 2; i++) {
        EXPECT_EQ((uint8_t)str_big_endian[i], expected_big_endian[i]);
        EXPECT_EQ((uint8_t)str_little_endian[i], expected_little_endian[i]);
    }

    BN bn32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
    uint8_t expected_ch_big[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t expected_ch_little[32] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                                      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t ch_big_endian[32], ch_little_endian[32];
    bn32.ToBytes32BE(str_big_endian);
    bn32.ToBytes32LE(str_little_endian);
    bn32.ToBytes32BE(ch_big_endian);
    bn32.ToBytes32LE(ch_little_endian);
    for(int i = 0; i < 32; i++) {
        EXPECT_EQ((uint8_t)str_big_endian[i], expected_ch_big[i]);
        EXPECT_EQ((uint8_t)str_little_endian[i], expected_ch_little[i]);
        EXPECT_EQ(ch_big_endian[i], expected_ch_big[i]);
        EXPECT_EQ(ch_little_endian[i], expected_ch_little[i]);
    }
}

TEST(BN, ToBytesFromBytes) {
    uint8_t ch[10];
    ch[0] = 0x01;
    ch[1] = 0x02;
    BN n1 = BN::FromBytesBE(ch, 2);
    BN n2 = BN::FromBytesLE(ch, 2);
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToDecStr(s2);

    EXPECT_TRUE(s1.compare("258") == 0);
    EXPECT_TRUE(s2.compare("513") == 0);

    std::string ns1, ns2;
    n1.ToBytesBE(ns1);
    n2.ToBytesBE(ns2);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
}

TEST(BN, ToBytes32FromBytes32)
{
    uint8_t num1[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t num2[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t num3[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00};
    uint8_t num4[33] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21};
    BN n1 = BN::FromBytesBE(num1, 32);
    uint8_t buf32BE[32];
    uint8_t buf32LE[32];
    n1.ToBytes32BE(buf32BE);
    n1.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num1[i], buf32BE[i]);
        EXPECT_EQ(num1[i], buf32LE[31 - i]);
    }
    BN n2 = BN::FromBytesBE(num2, 32);
    BN expected_n2 = BN::FromBytesBE(num2 + 1, 32 - 1);
    EXPECT_TRUE(n2 == expected_n2);
    n2.ToBytes32BE(buf32BE);
    n2.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num2[i], buf32BE[i]);
        EXPECT_EQ(num2[i], buf32LE[31 - i]);
    }
    BN n3 = BN::FromBytesLE(num3, 32);
    BN expected_n3 = BN::FromBytesLE(num3, 32 - 1);
    EXPECT_TRUE(n3 == expected_n3);
    n3.ToBytes32BE(buf32BE);
    n3.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num3[i], buf32LE[i]);
        EXPECT_EQ(num3[i], buf32BE[31 - i]);
    }
    BN n4 = BN::FromBytesBE(num4, 33);
    n4.ToBytes32BE(buf32BE);
    n4.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num4[i + 1], buf32BE[i]);
        EXPECT_EQ(num4[i + 1], buf32LE[31 - i]);
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
