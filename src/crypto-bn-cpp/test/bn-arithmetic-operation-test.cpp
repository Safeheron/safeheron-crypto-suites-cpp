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

TEST(BN, Add) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(66869);
    BN bn5(133738);
    BN bn6(133748);
    bn0 = bn1 + bn2 + bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 += bn1;
    bn0 += bn2;
    bn0 += bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 + 5;
    bn0 += 5;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ONE + BN::MINUS_ONE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE + BN::ZERO) == BN::ONE);
    EXPECT_TRUE((BN::ZERO + BN::ZERO) == BN::ZERO);
    EXPECT_TRUE((BN::TWO.Neg() + BN::TWO.Neg()) == BN::FOUR.Neg());
    EXPECT_TRUE((BN::FIVE.Neg() + BN::TWO) == BN::THREE.Neg());
}

TEST(BN, Sub) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(-66669);
    BN bn5(-133538);
    BN bn6(-133548);
    bn0 = bn1 - bn2 - bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 -= bn1;
    bn0 -= bn2;
    bn0 -= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 - 5;
    bn0 -= 5;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ONE - BN::ONE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE - BN::ZERO) == BN::ONE);
    EXPECT_TRUE((BN::ZERO - BN::ZERO) == BN::ZERO);
    EXPECT_TRUE((BN::TWO.Neg() - BN::THREE.Neg()) == BN::ONE);
    EXPECT_TRUE((BN::TWO.Neg() - BN::ONE.Neg()) == BN::ONE.Neg());
}

TEST(BN, Mul) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(8087019000);
    BN bn5("65399876306361000000", 10);
    BN bn6("653998763063610000000", 10);
    bn0 = bn1 * bn2 * bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 *= bn1;
    bn0 *= bn2;
    bn0 *= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 * 5;
    bn0 *= 2;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ZERO * BN::FIVE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE * BN::FIVE) == BN::FIVE);
    EXPECT_TRUE((BN::MINUS_ONE * BN::FIVE) == BN::FIVE.Neg());
    EXPECT_TRUE((BN::TWO.Neg() * BN::TWO.Neg()) == BN::FOUR);
    EXPECT_TRUE((BN::TWO.Neg() * BN::TWO) == BN::FOUR.Neg());
}

TEST(BN, Div) {
    BN bn0("65399876306361000101", 10);
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4("653998763063610001", 10);
    BN bn5(80870190);
    BN bn6(8087019);
    BN bn7(808701);
    bn0 = bn0 / bn1;
    EXPECT_TRUE(bn0 == bn4);
    bn0 /= bn1;
    bn0 /= bn2;
    bn0 /= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 / 5;
    bn0 /= 2;
    EXPECT_TRUE(bn0 == bn6);
    bn0 = bn0 / 5;
    bn0 /= 2;
    EXPECT_TRUE(bn0 == bn7);
    EXPECT_TRUE((BN::FIVE / BN::ONE) == BN::FIVE);
    EXPECT_TRUE((BN::ONE.Neg() / BN::FIVE) == BN::ZERO);
    EXPECT_TRUE((BN::FIVE.Neg() / BN::TWO.Neg()) == BN::TWO);
    EXPECT_TRUE((BN::FIVE / BN::TWO.Neg()) == BN::TWO.Neg());
    EXPECT_TRUE((BN::ZERO / BN::FIVE) == BN::ZERO);
}

TEST(BN, Modular) {
    BN bn0("25", 10);
    BN bn1("101", 2);
    BN bn2("a", 16);
    BN bn3;
    bn3 = bn0 % bn1;
    EXPECT_TRUE(bn3 == BN::ZERO);
    bn3 = bn0 % 5;
    EXPECT_TRUE(bn3 == BN::ZERO);
    bn3 = bn0 % bn2;
    EXPECT_TRUE(bn3 == BN::FIVE);
    bn3 = bn0 % 10;
    EXPECT_TRUE(bn3 == BN::FIVE);

    bn0 = BN(-23);
    bn3 = bn0 % bn1;
    EXPECT_TRUE(bn3 == BN::TWO);
    bn3 = bn0 % 5;
    std::cout << bn3.Inspect() << std::endl;
    EXPECT_EQ(bn1, 5);
    //   std::cout << "%5: " << bn3.Inspect(10) << std::endl;
    EXPECT_EQ(bn3, BN::TWO);
    bn3 = bn0 % bn2;
    EXPECT_TRUE(bn3 == 7);
    bn3 = bn0 % 10;
    //   EXPECT_EQ(bn2, 10);
    //   std::cout << "%10: " << bn3.Inspect(10) << std::endl;
    EXPECT_EQ(bn3, 7);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
