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

TEST(BN, Comparison) {
    //for positive
    BN bn1(2568);
    BN bn2(2568);
    BN bn3(2569);
    BN bn4(2567);
    EXPECT_TRUE(bn1 == bn2);
    EXPECT_FALSE(bn1 != bn2);
    EXPECT_TRUE(bn1 >= bn2);
    EXPECT_TRUE(bn1 <= bn2);
    EXPECT_FALSE((bn1 > bn2) || (bn1 < bn2));
    EXPECT_TRUE((bn1 < bn3) && (bn3 > bn1));
    EXPECT_TRUE((bn4 < bn1) && (bn1 > bn4));
    EXPECT_TRUE((bn1 <= bn3) && (bn3 >= bn1));
    EXPECT_TRUE((bn4 <= bn1) && (bn1 >= bn4));
    EXPECT_FALSE((bn1 > bn3) || (bn3 < bn1));
    EXPECT_FALSE((bn1 >= bn3) || (bn3 <= bn1));
    EXPECT_FALSE((bn1 < bn4) || (bn4 > bn1));
    EXPECT_FALSE((bn1 <= bn4) || (bn4 >= bn1));
    EXPECT_FALSE(bn1 == bn3);
    EXPECT_TRUE(bn1 != bn3);
    EXPECT_TRUE(bn1 > 0);
    EXPECT_TRUE(bn1 >= 0);
    EXPECT_FALSE(bn1 < 0);
    EXPECT_FALSE(bn1 <= 0);
    EXPECT_TRUE(bn1 == 2568);
    EXPECT_FALSE(bn1 != 2568);
    EXPECT_TRUE(bn1 >= 2568);
    EXPECT_TRUE(bn1 <= 2568);
    EXPECT_TRUE(bn1 > 2567);
    EXPECT_TRUE(bn1 < 2569);
    EXPECT_TRUE(bn1 >= 2567);
    EXPECT_TRUE(bn1 <= 2569);
    //for negative
    BN bn5("-abc",16);
    BN bn6("-ABC", 16);
    BN bn7("-aba", 16);
    BN bn8("-abd", 16);
    EXPECT_TRUE(bn5 == bn6);
    EXPECT_FALSE(bn5 != bn6);
    EXPECT_TRUE(bn5 >= bn6);
    EXPECT_TRUE(bn5 <= bn6);
    EXPECT_FALSE((bn5 > bn6) || (bn5 < bn6));
    EXPECT_TRUE((bn5 < bn7) && (bn7 > bn5));
    EXPECT_TRUE((bn8 < bn5) && (bn5 > bn8));
    EXPECT_TRUE((bn5 <= bn7) && (bn7 >= bn5));
    EXPECT_TRUE((bn8 <= bn5) && (bn5 >= bn8));
    EXPECT_FALSE((bn5 > bn7) || (bn7 < bn5));
    EXPECT_FALSE((bn5 >= bn7) || (bn7 <= bn5));
    EXPECT_FALSE((bn5 < bn8) || (bn8 > bn5));
    EXPECT_FALSE((bn5 <= bn8) || (bn8 >= bn5));
    EXPECT_FALSE(bn5 == bn7);
    EXPECT_TRUE(bn5 != bn7);
    EXPECT_TRUE(bn5 < 0);
    EXPECT_TRUE(bn5 <= 0);
    EXPECT_FALSE(bn5 > 0);
    EXPECT_FALSE(bn5 >= 0);
    EXPECT_TRUE(bn5 == -2748);
    EXPECT_FALSE(bn5 != -2748);
    EXPECT_TRUE(bn5 >= -2748);
    EXPECT_TRUE(bn5 <= -2748);
    EXPECT_TRUE(bn5 > -2749);
    EXPECT_TRUE(bn5 < -2746);
    EXPECT_TRUE(bn5 >= -2749);
    EXPECT_TRUE(bn5 <= -2746);
    //mix
    EXPECT_TRUE((bn1 > bn5) && (bn5 < bn1));
    EXPECT_TRUE((bn1 >= bn5) && (bn5 <= bn1));
    EXPECT_TRUE(bn1 != bn5);
    EXPECT_FALSE(bn1 == bn5);
    EXPECT_TRUE(bn1 > -2748);
    EXPECT_TRUE(bn5 < 2568);
    EXPECT_TRUE(bn1 >= -2748);
    EXPECT_TRUE(bn5 <= 2568);
    EXPECT_TRUE(bn1 != -2748);
    EXPECT_FALSE(bn1 == -2748);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
