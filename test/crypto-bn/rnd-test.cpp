//
// Created by 何剑虹 on 2020/10/22.
//
#include <cstdio>
#include <ctime>
#include "gtest/gtest.h"
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

TEST(Rand, random)
{
    BN max;
    BN p("983d0dc7e7f4d64dd03dc52ce8f85e096b37cd487223301619ae143b780b90cb", 16);
    EXPECT_TRUE(p.IsProbablyPrime());

    std::string s;
    BN n = safeheron::rand::RandomBN(256);
    n.ToHexStr(s);
    std::cout << "BN(256):"<< s << std::endl;

    n = safeheron::rand::RandomBNStrict(256);
    n.ToHexStr(s);
    std::cout << "BN(256):"<< s << std::endl;

    n = safeheron::rand::RandomPrime(256);
    n.ToHexStr(s);
    std::cout << "prime(256):"  << s << std::endl;

    n = safeheron::rand::RandomPrimeStrict(256);
    n.ToHexStr(s);
    std::cout << "prime(strict 256):"  << s << std::endl;

    for( int i = 0 ; i < 10 ; i++ ){
        n = safeheron::rand::RandomPrimeStrict(1024);
        n.ToHexStr(s);
        std::cout << "prime(strict 1024): " << s << std::endl;
    }

    max = n;
    max.ToHexStr(s);
    std::cout << "BN( max ): " << s << std::endl;
    n = safeheron::rand::RandomBNLt(max);
    n.ToHexStr(s);
    std::cout << "BN( x < max ): " << s << std::endl;

    n = safeheron::rand::RandomBNLtGcd(max);
    n.ToHexStr(s);
    std::cout << "BN( x < max, gcd(x, max) == 1 ): " << s << std::endl;
    EXPECT_TRUE(n.Gcd(max) == 1);
}

TEST(Rand, randomByte32Generator)
{
    clock_t start, finish;
    double  duration;
    start = clock();

    uint8_t b32[32];
    for(int i = 0; i < 100000; i++){
        safeheron::rand::RandomBytes(b32, 32);
        if(i % 10000 == 0) {
            std::cout << i << std::endl;
        }
    }

    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "randomByte32Generator: %f seconds\n", duration );
}

TEST(Rand, randomBNGenerator)
{
    clock_t start, finish;
    double  duration;
    start = clock();

    std::string str;
    for(int i = 0; i < 100000; i++){
        BN n = safeheron::rand::RandomBN(256);
        if(i % 10000 == 0) {
            std::cout << i << std::endl;
        }
    }

    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "randomBNGenerator: %f seconds\n", duration );
}

TEST(Rand, TestExecption)
{
    BN n;
    try{
        n = safeheron::rand::RandomBN(4000000000);
    }catch(const BadAllocException &e) {
        std::cout << "Catch BadAllocException: " << e.what() << std::endl;
    }catch(const RandomSourceException &e) {
        std::cout << "Catch RandomSourceException: " << e.what() << std::endl;
    }catch(const LocatedException &e) {
        std::cout << "Catch LocatedException: " << e.what() << std::endl;
    }catch(const std::exception &e) {
        std::cout << "Catch LocatedException: " <<__FILE__ << ", " << __LINE__ << ", " << __FUNCTION__ << ": " << e.what() << std::endl;
    }
    std::cout << n.Inspect() << std::endl;
}

TEST(Rand, PrimeGenerate)
{
    clock_t start, end;
    start = clock();
    for(int i = 0; i < 5; i++){
        int count = 0;
        while(true){
            count ++;
            BN n = safeheron::rand::RandomBN(1024);
            std::string str;
            if(n.IsProbablyPrime()){
                n.ToHexStr(str);
                std::cout << "prime1024(count :" << count << "): " << str << std::endl;
                break;
            }
        }
    }
    end = clock();
    std::cout << ">>>>>>>>>>>>>> time: " << double(end - start) / CLOCKS_PER_SEC << std::endl;
}

TEST(Rand, SafePrimes)
{
    BN p;
    int key_bit = 2048;
    p = safeheron::rand::RandomSafePrime(key_bit/2);
    std::string str;
    p.ToHexStr(str);
    std::cout << "safe primes.p: " << str << std::endl;

    p = safeheron::rand::RandomSafePrimeStrict(key_bit/2);
    p.ToHexStr(str);
    std::cout << "safe primes[strict length].p: " << str << std::endl;
}

void rand_bn_in_bits(size_t key_bit){
    std::string str;
    BN p;

    p = safeheron::rand::RandomBN(key_bit);
    p.ToHexStr(str);
    std::cout << "RandomBN(" << key_bit << "): " << str << std::endl;
    EXPECT_LE(p.BitLength(), key_bit);

    p = safeheron::rand::RandomPrime(key_bit/2);
    p.ToHexStr(str);
    std::cout << "RandomPrime(" << key_bit << "): " << str << std::endl;
    EXPECT_LE(p.BitLength(), key_bit);

    p = safeheron::rand::RandomBNStrict(key_bit);
    p.ToHexStr(str);
    std::cout << "RandomBNStrict(" << key_bit << "): "  << str << std::endl;
    EXPECT_EQ(p.BitLength(), key_bit);

    p = safeheron::rand::RandomPrimeStrict(key_bit);
    p.ToHexStr(str);
    std::cout << "RandomPrimeStrict(" << key_bit << "): "  << str << std::endl;
    EXPECT_EQ(p.BitLength(), key_bit);
}

TEST(Rand, SafePrimesInBits)
{
    rand_bn_in_bits(7);
    rand_bn_in_bits(9);
    rand_bn_in_bits(15);
    rand_bn_in_bits(17);
}

void rand_bn_in_sym_interval(size_t key_bit){
    std::string str;
    BN p;
    BN limit = BN::ONE << key_bit;

    p = safeheron::rand::RandomNegBNInSymInterval(key_bit);
    p.ToHexStr(str);
    std::cout << "RandomNegBNInSymInterval(" << key_bit << "): " << str << std::endl;
    EXPECT_LE(p.BitLength(), key_bit);

    p = safeheron::rand::RandomNegBNInSymInterval(limit);
    p.ToHexStr(str);
    std::cout << "RandomNegBNInSymInterval(" << key_bit << "): " << str << std::endl;
    EXPECT_LE(p.BitLength(), key_bit);
}

TEST(Rand, RandomNegBNInSymInterval)
{
    rand_bn_in_sym_interval(7);
    rand_bn_in_sym_interval(9);
    rand_bn_in_sym_interval(15);
    rand_bn_in_sym_interval(17);
}

TEST(Rand, RandomBNInRange)
{
    for (int i = 0; i < 10; ++i) {
        BN n = safeheron::rand::RandomBNInRange(BN(100), BN(1000));
        std::cout << "n = " << n.Inspect(10) << std::endl;
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
