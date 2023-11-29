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

//constructor tests for zero
TEST(BN, ZeroConstructor) {
    //test for 0
    BN bn0;
    BN bn1(0);
    BN bn2("0", 2);
    BN bn3("0", 10);
    BN bn4("0", 16);
    BN bn5 = bn0;
    BN bn6((BN()));// Move Constructor
    EXPECT_TRUE(bn0 == BN::ZERO);
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    EXPECT_TRUE(bn0 == bn4);
    EXPECT_TRUE(bn0 == bn5);
    EXPECT_TRUE(bn0 == bn6);

    //test for +0 and -0
    BN bn10(+0);
    BN bn11(-0);
    EXPECT_TRUE(bn0 == bn10);
    EXPECT_TRUE(bn0 == bn11);
}

//constructor tests for non-zero value
TEST(BN, NonZeroConstructor) {
    //test for positive number
    BN bn0(255);
    BN bn1("11111111",2);
    BN bn2("255", 10);
    BN bn3("ff",16);
    BN bn4 = bn1;
    BN bn5(BN(255)); // Move Constructor
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    EXPECT_TRUE(bn0 == bn4);
    EXPECT_TRUE(bn0 == bn5);
    //test for negative number
    BN bn6(-255);
    BN bn7("-11111111",2);
    BN bn8("-255",10);
    BN bn9("-ff",16);
    BN bn10 = bn6;
    BN bn11(BN(-255)); // Move constructor
    BN bn12(-256);
    EXPECT_TRUE(bn6 == bn7);
    /**********debug*************/
    std::cout << "bn9: " << bn9.Inspect(10) << std::endl;
    std::string str1, str2;
    bn6.ToDecStr(str1);
    bn7.ToDecStr(str2);
    std::cout << "str1:"<< str1 <<std::endl;
    std::cout << "str2:" << str2 <<std::endl;
    /**********debug*************/
    EXPECT_TRUE(bn6 == bn8);
    EXPECT_TRUE(bn6 == bn9);
    EXPECT_TRUE(bn6 == bn10);
    EXPECT_TRUE(bn6 == bn11);
    //test for different numbers
    EXPECT_TRUE(bn6 != bn12);
    EXPECT_TRUE(bn0 != bn6);
    EXPECT_TRUE(bn0.Neg() == bn6);
}

TEST(BN, WeirdInput) {
    //weird input for zero
    BN bn0(00000000);
    BN bn1("00000000",2);
    BN bn2("00000000",10);
    BN bn3("00000000",16);
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    //weird input for non-zero
    BN bn4(2748);
    BN bn5(0xabc);
    BN bn6(0x0000abc);
    BN bn7("00101010111100",2);
    BN bn8("002748",10);
    BN bn9("00abc",16);
    EXPECT_TRUE(bn4 == bn5);
    EXPECT_TRUE(bn4 == bn6);
    EXPECT_TRUE(bn4 == bn7);
    EXPECT_TRUE(bn4 == bn8);
    EXPECT_TRUE(bn4 == bn9);
    //illegal input
    BN bn10("0567",2);
    BN bn11("0abc", 10);
    BN bn12("0xyz", 16);
    EXPECT_TRUE(bn0 == bn10);
    EXPECT_TRUE(bn0 == bn11);
    EXPECT_TRUE(bn0 == bn12);

    // test for decimal, .非法字符
    BN bn14("1010.1", 2);
    BN bn15("10.5", 10);
    BN bn16("a.5", 16);
    std::string  bn14_str, bn15_str, bn16_str;
    bn14.ToDecStr(bn14_str);
    bn15.ToDecStr(bn15_str);
    bn16.ToDecStr(bn16_str);
    std::cout  << "bn14_str:" << bn14_str << ", " << "bn15_str:"
               << bn15_str << ", " << "bn16_str:" << bn16_str << std::endl;
    EXPECT_TRUE((bn14 == bn15) && (bn15 == bn16));
}

TEST(BN, BigNumConstructor) {
    //64 bits
    BN bn0("1111111111111111111111111111111111111111111111111111111111111111", 2);
    BN bn1("ffffffffffffffff",16);
    EXPECT_TRUE(bn0 == bn1);
    //128 bits
    BN bn2("ffffffffffffffffffffffffffffffff",16);
    EXPECT_TRUE(bn2.BitLength() == 128);
    EXPECT_TRUE((bn2 >> 64) == bn0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
