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

TEST(BN, StringConversion) {
    //bn0: 1111 1111 1111 1111
    BN bn0("1111111111111111",2);
    std::string str_16 = "ffff";
    std::string str_10 = "65535";
    BN bn1 = BN::FromHexStr("ffff");
    BN bn2 = BN::FromHexStr(str_16);
    BN bn3 = BN::FromDecStr("65535");
    BN bn4 = BN::FromDecStr(str_10);
    EXPECT_EQ(bn0, bn1);
    EXPECT_EQ(bn0, bn2);
    EXPECT_EQ(bn0, bn3);
    EXPECT_EQ(bn0, bn4);
    //bn5: 101 0000 1111, bn6: 01 0111 0011
    BN bn5("10100001111", 2);
    BN bn6("0101110011",2);
    bn5.ToHexStr(str_16);
    bn5.ToDecStr(str_10);
    EXPECT_EQ(str_16, "050F");
    EXPECT_EQ(str_10, "1295");
    bn6.ToHexStr(str_16);
    bn6.ToDecStr(str_10);
    EXPECT_EQ(str_16, "0173");
    EXPECT_EQ(str_10, "371");
}

TEST(BN, ToStringFromString) {
    BN n1 = BN::FromDecStr("24785187341154544549914104546227");
    BN n2 = BN::FromHexStr("FFFFFFFFFFFFFFFF");
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToHexStr(s2);

    EXPECT_TRUE(s1.compare("24785187341154544549914104546227") == 0);
    EXPECT_TRUE(s2.compare("FFFFFFFFFFFFFFFF") == 0);
}

TEST(BN, FromAndTo)
{
    // DON'T SUPPORT convert "" to BIGNUM!!!
    // expect a/b/c are Zero
    //BN a("", 2);
    //BN b("", 10);
    //BN c("", 16);
    //EXPECT_TRUE(a.IsZero());
    //EXPECT_TRUE(b.IsZero());
    //EXPECT_TRUE(c.IsZero());

    // expect a/b/c are Zero
    std::string str;
    uint8_t buff[256] = {0};
    BN d1 = BN::FromHexStr("0");
    BN d2 = BN::FromDecStr("0");
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(str);
    d2 = BN::FromBytesLE(str);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(buff, 0);
    d2 = BN::FromBytesLE(buff, 0);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());

    // BigNum Zero to string
    BN n;
    std::string s1,s2;
    n.ToHexStr(s1);
    n.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("0") == 0);
    EXPECT_TRUE(s2.compare("0") == 0);
    n.ToBytesBE(s1);
    n.ToBytesLE(s2);
    EXPECT_TRUE(s1.compare("") == 0);   //TODO:
    EXPECT_TRUE(s2.compare("") == 0);   //TODO:

    // BigNum Zero to buff
    uint8_t buff32[32] = {0};
    n.ToBytes32BE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);
    n.ToBytes32LE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);

    BN m(5);
    m.ToHexStr(s1);
    m.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("05") == 0);
    EXPECT_TRUE(s2.compare("5") == 0);
    m = BN::FromHexStr("5");
    m.ToHexStr(s1);
    EXPECT_TRUE(s1.compare("05") == 0);

    BN p(-2);
    p.ToHexStr(s1);
    p.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("-02") == 0);
    EXPECT_TRUE(s2.compare("-2") == 0);
    p = BN::FromDecStr("-0");
    EXPECT_TRUE(p.IsZero());

}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
