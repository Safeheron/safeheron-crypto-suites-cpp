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

TEST(BN, Auxiliary) {
    BN bn0;
    EXPECT_EQ(bn0.BitLength(), 0);
    EXPECT_EQ(bn0.ByteLength(), 0);
    EXPECT_EQ(bn0.IsNeg(), false);
    EXPECT_EQ(bn0.IsZero(), true);
    EXPECT_EQ(bn0.IsOdd(), false);
    EXPECT_EQ(bn0.IsEven(), true);
    bn0 = BN::FromDecStr("0");
    EXPECT_EQ(bn0.BitLength(), 0);
    EXPECT_EQ(bn0.ByteLength(), 0);
    EXPECT_EQ(bn0.IsNeg(), false);
    EXPECT_EQ(bn0.IsZero(), true);
    EXPECT_EQ(bn0.IsOdd(), false);
    EXPECT_EQ(bn0.IsEven(), true);
    BN bn1 = BN::FromDecStr("1");
    EXPECT_EQ(bn1.BitLength(), 1);
    EXPECT_EQ(bn1.ByteLength(), 1);
    EXPECT_EQ(bn1.IsNeg(), false);
    EXPECT_EQ(bn1.IsZero(), false);
    EXPECT_EQ(bn1.IsOdd(), true);
    EXPECT_EQ(bn1.IsEven(), false);
    BN bn2 = BN::FromDecStr("-258");
    EXPECT_EQ(bn2.BitLength(), 9);
    EXPECT_EQ(bn2.ByteLength(), 2);
    EXPECT_EQ(bn2.IsNeg(), true);
    EXPECT_EQ(bn2.IsZero(), false);
    EXPECT_EQ(bn2.IsOdd(), false);
    EXPECT_EQ(bn2.IsEven(), true);

    EXPECT_EQ(BN::Max(bn0, bn1), bn1);
    EXPECT_EQ(BN::Min(bn0,bn1), bn0);
    EXPECT_EQ(BN::Max(bn1, bn2), bn1);
    EXPECT_EQ(BN::Min(bn1,bn2), bn2);

    BN::Swap(bn1, bn2);
    EXPECT_EQ(bn1, -258);
    EXPECT_EQ(bn2, 1);
    BN::Swap(bn2, bn0);
    EXPECT_EQ(bn0, 1);
    EXPECT_EQ(bn2, 0);

    BN bn3("01111111",2);
    EXPECT_EQ(bn3.Inspect(), "7F");
    EXPECT_FALSE(bn3.IsBitSet(7));
    bn3.SetBit(7);
    EXPECT_EQ(bn3.Inspect(), "FF");
    EXPECT_TRUE(bn3.IsBitSet(7));
    EXPECT_EQ(bn3, 255);
    bn3.ClearBit(0);
    EXPECT_EQ(bn3.Inspect(), "FE");
    EXPECT_FALSE(bn3.IsBitSet(0));
    EXPECT_EQ(bn3, 254);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
