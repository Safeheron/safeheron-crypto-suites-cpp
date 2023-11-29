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

TEST(BN, Shift) {
    BN bn0("1011", 2);
    BN bn1("10110000000000",2);
    BN bn2("10",2);
    EXPECT_TRUE((bn0 << 10) == bn1);
    EXPECT_TRUE((bn0 >> 2) == bn2);
    EXPECT_TRUE((bn0 >> 4) == BN::ZERO);
    EXPECT_TRUE((bn0 >> 10) == BN::ZERO);
    EXPECT_TRUE((bn0 <<= 10) == bn1);
    EXPECT_TRUE((bn0 >>= 12) == bn2);
    EXPECT_TRUE((bn0 >>= 2) == BN::ZERO);
    EXPECT_TRUE((bn0 >>= 10) == BN::ZERO);

    BN bn3("-1011", 2);
    BN bn4("-10110000000000",2);
    BN bn5("-10",2);
    EXPECT_TRUE((bn3 << 10) == bn4);
    EXPECT_TRUE((bn3 >> 2) == bn5);
    EXPECT_TRUE((bn3 >> 4) == BN::ZERO);
    EXPECT_TRUE((bn3 >> 10) == BN::ZERO);
    EXPECT_TRUE((bn3 <<= 10) == bn4);
    EXPECT_TRUE((bn3 >>= 12) == bn5);
    EXPECT_TRUE((bn3 >>= 2) == BN::ZERO);
    EXPECT_TRUE((bn3 >>= 10) == BN::ZERO);
}

TEST(BN, BitOperation)
{
    uint8_t num1[3] = {0x01, 0x02, 0x03};
    BN n1 = BN::FromBytesBE(num1, 3);
    EXPECT_TRUE(n1.IsBitSet(0));
    EXPECT_TRUE(n1.IsBitSet(1));
    EXPECT_TRUE(!n1.IsBitSet(2));
    EXPECT_TRUE(n1.IsBitSet(9));
    EXPECT_TRUE(n1.IsBitSet(16));
    EXPECT_TRUE(n1 == 0x010203);
    n1.SetBit(23);
    EXPECT_TRUE(n1 == 0x810203);
    n1.SetBit(7);
    EXPECT_TRUE(n1 == 0x810283);
    n1.ClearBit(9);
    EXPECT_TRUE(n1 == 0x810083);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
