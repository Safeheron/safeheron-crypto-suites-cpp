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

TEST(BN, Const) {
    BN n0(0);
    BN n1("1", 10);
    BN n2("2", 10);
    BN n3("3", 10);
    BN n4("4", 10);
    BN n5("5", 10);
    EXPECT_TRUE( BN::ZERO == n0);
    EXPECT_TRUE( BN::ONE == n1);
    EXPECT_TRUE( BN::TWO == n2);
    EXPECT_TRUE( BN::THREE == n3);
    EXPECT_TRUE( BN::FOUR == n4);
    EXPECT_TRUE( BN::FIVE == n5);
}

TEST(BN, Assigment) {
    //test for copy assignment.
    BN bn0;
    BN bn1(1);
    EXPECT_TRUE(bn0 != bn1);
    bn0 = bn1;
    EXPECT_TRUE(bn0 == bn1);
    //test for move assignment.
    BN bn2;
    EXPECT_TRUE(bn2 != bn1);
    bn2 = std::move(bn0);
    // bn0 cann't be compared because bn.n_ == nullptr
    // EXPECT_TRUE(bn0 != bn1);
    EXPECT_TRUE(bn2 == bn1);
}

TEST(BN, SelfAssign)
{
    BN p = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    std::string str;
    p.ToHexStr(str);
    std::cout << "Before self-assignment: " << str << std::endl;
    p = std::move(p);
    p.ToHexStr(str);
    std::cout << "After self-assignment: " << str << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
