#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include <openssl/bn.h>

using safeheron::bignum::BN;

long test_long_sqrt(long x) 
{
    int r = 0;
    BN bn_x(x);
    BN bn_r;

    bn_r = bn_x.Sqrt();
    r = BN_get_word(bn_r.GetBIGNUM());

    return r;
}

TEST(BN, long_sqrt)
{
    int r = test_long_sqrt(25);
    EXPECT_TRUE(r == 5);
    r = test_long_sqrt(100);
    EXPECT_TRUE(r == 10);
    r = test_long_sqrt(256);
    EXPECT_TRUE(r == 16);
    r = test_long_sqrt(1024);
    EXPECT_TRUE(r == 32);
}

void test_bignum_sqrt(int bits)
{
    std::string s;
    BN n = safeheron::rand::RandomBN(bits);
    n.ToHexStr(s);
    std::cout << "BN(" << bits << "):" << s << std::endl;

    BN sqr = n * n;
    sqr.ToHexStr(s);
    std::cout << "-->sqr:"<< s << std::endl;

    BN sqrt = sqr.Sqrt();
    sqrt.ToHexStr(s);
    std::cout << "-->sqrt:"<< s << std::endl;
    EXPECT_TRUE(sqrt == n);

    std::cout << std::endl;
}

void test_bignum_sqrt_2(int bits)
{
    std::string s;
    // n
    BN n = safeheron::rand::RandomBN(bits);
    // n+1
    BN n_plus_1 = n + 1;
    // n^2
    BN n_sqr = n * n;
    // (n+1)^2
    BN n_plus_1_sqr = n_plus_1 * n_plus_1;

    // delta \in [0, (n+1)^2 - n^2)
    BN delta = safeheron::rand::RandomBNInRange(BN(0), n_plus_1_sqr - n_sqr);
    n.ToHexStr(s);
    std::cout << "BN(" << bits << "):" << s << std::endl;

    BN sqr = n * n;
    sqr.ToHexStr(s);
    std::cout << "-->sqr:"<< s << std::endl;

    // sqr = n^2 + delta
    sqr += delta;

    // check sqrt === n
    BN sqrt = sqr.Sqrt();
    sqrt.ToHexStr(s);
    std::cout << "-->sqrt:"<< s << std::endl;
    EXPECT_TRUE(sqrt == n);

    std::cout << std::endl;
}

TEST(BN, bignum_sqrt)
{
    test_bignum_sqrt(512);
    test_bignum_sqrt(1024);
    test_bignum_sqrt(2048);
    test_bignum_sqrt(4096);

    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(512);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(1024);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(2048);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(4096);
    }

    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(7);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(15);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(37);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(137);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(737);
    }
    for (int i = 0; i < 100; ++i) {
        test_bignum_sqrt_2(1393);
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

    return ret;
}
