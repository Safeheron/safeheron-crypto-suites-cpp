#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "crypto-curve/curve.h"
#include <random>

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

int test_random_sign(CurveType type, int times)
{
    int count = 0;
    const Curve *curv = GetCurveParam(type);

    std::random_device rd;
    std::mt19937 gen(rd());
    int lower_bound = 10;
    int upper_bound = 1000;
    std::uniform_int_distribution<> dis(lower_bound, upper_bound); // 生成 lower_bound 到 upper_bound 之间的整数

    do {
        int message_len = dis(gen);
        BN privkey = safeheron::rand::RandomBNLt(curv->n);

        CurvePoint pubkey = curv->g * privkey;

        char *message = new char[message_len];
        safeheron::rand::RandomBytes(reinterpret_cast<unsigned char *>(message), message_len);

        try {
            std::string sig = safeheron::curve::schnorr::Sign(type, privkey, (const uint8_t *)message, message_len, "aux",
                                                              safeheron::curve::schnorr::SchnorrPattern::Legacy);

            bool pass = safeheron::curve::schnorr::Verify(type, pubkey, (const uint8_t*)sig.c_str(), (const uint8_t *)message, message_len,
                                                          safeheron::curve::schnorr::SchnorrPattern::Legacy);
            EXPECT_TRUE(pass == true);
        }catch (const std::exception &e){
            printf("%s", e.what());
        }
        delete[] message;
    }while (++count < times);
    return 0;
}

TEST(SECP256K1, test_random_sign)
{
    printf("/*******************SECP256K1 Random Sign/Verify Begin (Legacy) *********************/\n");
    test_random_sign(CurveType::SECP256K1,  100);
    printf("/*******************SECP256K1 Random Sign/Verify End (Legacy) *********************/\n");
    printf("\n\n");
}

// test cases from BCH node (https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/master/src/secp256k1/src/modules/schnorr/tests_impl.h?ref_type=heads)
void run_schnorr_compact_test(void) {
    {
        /* Test vector 1 */
        static const unsigned char pkbuf[33] = {
                0x02,
                0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        };

        static const unsigned char msg[32] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        static const unsigned char sig[64] = {
                0x78, 0x7A, 0x84, 0x8E, 0x71, 0x04, 0x3D, 0x28,
                0x0C, 0x50, 0x47, 0x0E, 0x8E, 0x15, 0x32, 0xB2,
                0xDD, 0x5D, 0x20, 0xEE, 0x91, 0x2A, 0x45, 0xDB,
                0xDD, 0x2B, 0xD1, 0xDF, 0xBF, 0x18, 0x7E, 0xF6,
                0x70, 0x31, 0xA9, 0x88, 0x31, 0x85, 0x9D, 0xC3,
                0x4D, 0xFF, 0xEE, 0xDD, 0xA8, 0x68, 0x31, 0x84,
                0x2C, 0xCD, 0x00, 0x79, 0xE1, 0xF9, 0x2A, 0xF1,
                0x77, 0xF7, 0xF2, 0x2C, 0xC1, 0xDC, 0xED, 0x05,
        };


        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(pass);
    }

    {
        /* Test vector 2 */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
                0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
                0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
                0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD,
        };


        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(pass);
    }

    {
        /* Test vector 3 */
        static const unsigned char pkbuf[33] = {
                0x03,
                0xFA, 0xC2, 0x11, 0x4C, 0x2F, 0xBB, 0x09, 0x15,
                0x27, 0xEB, 0x7C, 0x64, 0xEC, 0xB1, 0x1F, 0x80,
                0x21, 0xCB, 0x45, 0xE8, 0xE7, 0x80, 0x9D, 0x3C,
                0x09, 0x38, 0xE4, 0xB8, 0xC0, 0xE5, 0xF8, 0x4B,
        };

        static const unsigned char msg[32] = {
                0x5E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A,
                0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D,
                0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33,
                0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C,
        };

        static const unsigned char sig[64] = {
                0x00, 0xDA, 0x9B, 0x08, 0x17, 0x2A, 0x9B, 0x6F,
                0x04, 0x66, 0xA2, 0xDE, 0xFD, 0x81, 0x7F, 0x2D,
                0x7A, 0xB4, 0x37, 0xE0, 0xD2, 0x53, 0xCB, 0x53,
                0x95, 0xA9, 0x63, 0x86, 0x6B, 0x35, 0x74, 0xBE,
                0x00, 0x88, 0x03, 0x71, 0xD0, 0x17, 0x66, 0x93,
                0x5B, 0x92, 0xD2, 0xAB, 0x4C, 0xD5, 0xC8, 0xA2,
                0xA5, 0x83, 0x7E, 0xC5, 0x7F, 0xED, 0x76, 0x60,
                0x77, 0x3A, 0x05, 0xF0, 0xDE, 0x14, 0x23, 0x80,
        };


        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(pass);
    }

    {
        /* Test vector 4 */
        static const unsigned char pkbuf[33] = {
                0x03,
                0xDE, 0xFD, 0xEA, 0x4C, 0xDB, 0x67, 0x77, 0x50,
                0xA4, 0x20, 0xFE, 0xE8, 0x07, 0xEA, 0xCF, 0x21,
                0xEB, 0x98, 0x98, 0xAE, 0x79, 0xB9, 0x76, 0x87,
                0x66, 0xE4, 0xFA, 0xA0, 0x4A, 0x2D, 0x4A, 0x34,
        };

        static const unsigned char msg[32] = {
                0x4D, 0xF3, 0xC3, 0xF6, 0x8F, 0xCC, 0x83, 0xB2,
                0x7E, 0x9D, 0x42, 0xC9, 0x04, 0x31, 0xA7, 0x24,
                0x99, 0xF1, 0x78, 0x75, 0xC8, 0x1A, 0x59, 0x9B,
                0x56, 0x6C, 0x98, 0x89, 0xB9, 0x69, 0x67, 0x03,
        };

        static const unsigned char sig[64] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x3B, 0x78, 0xCE, 0x56, 0x3F,
                0x89, 0xA0, 0xED, 0x94, 0x14, 0xF5, 0xAA, 0x28,
                0xAD, 0x0D, 0x96, 0xD6, 0x79, 0x5F, 0x9C, 0x63,
                0x02, 0xA8, 0xDC, 0x32, 0xE6, 0x4E, 0x86, 0xA3,
                0x33, 0xF2, 0x0E, 0xF5, 0x6E, 0xAC, 0x9B, 0xA3,
                0x0B, 0x72, 0x46, 0xD6, 0xD2, 0x5E, 0x22, 0xAD,
                0xB8, 0xC6, 0xBE, 0x1A, 0xEB, 0x08, 0xD4, 0x9D,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(pass);
    }

    {
        /* Test vector 4b */
        static const unsigned char pkbuf[33] = {
                0x03,
                0x1B, 0x84, 0xC5, 0x56, 0x7B, 0x12, 0x64, 0x40,
                0x99, 0x5D, 0x3E, 0xD5, 0xAA, 0xBA, 0x05, 0x65,
                0xD7, 0x1E, 0x18, 0x34, 0x60, 0x48, 0x19, 0xFF,
                0x9C, 0x17, 0xF5, 0xE9, 0xD5, 0xDD, 0x07, 0x8F,
        };

        static const unsigned char msg[32] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        static const unsigned char sig[64] = {
                0x52, 0x81, 0x85, 0x79, 0xAC, 0xA5, 0x97, 0x67,
                0xE3, 0x29, 0x1D, 0x91, 0xB7, 0x6B, 0x63, 0x7B,
                0xEF, 0x06, 0x20, 0x83, 0x28, 0x49, 0x92, 0xF2,
                0xD9, 0x5F, 0x56, 0x4C, 0xA6, 0xCB, 0x4E, 0x35,
                0x30, 0xB1, 0xDA, 0x84, 0x9C, 0x8E, 0x83, 0x04,
                0xAD, 0xC0, 0xCF, 0xE8, 0x70, 0x66, 0x03, 0x34,
                0xB3, 0xCF, 0xC1, 0x8E, 0x82, 0x5E, 0xF1, 0xDB,
                0x34, 0xCF, 0xAE, 0x3D, 0xFC, 0x5D, 0x81, 0x87,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(pass);
    }

    {
        /* Test vector 6: R.y is not a quadratic residue */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0xFA, 0x16, 0xAE, 0xE0, 0x66, 0x09, 0x28, 0x0A,
                0x19, 0xB6, 0x7A, 0x24, 0xE1, 0x97, 0x7E, 0x46,
                0x97, 0x71, 0x2B, 0x5F, 0xD2, 0x94, 0x39, 0x14,
                0xEC, 0xD5, 0xF7, 0x30, 0x90, 0x1B, 0x4A, 0xB7,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 7: Negated message hash, R.x mismatch */
        static const unsigned char pkbuf[33] = {
                0x03,
                0xFA, 0xC2, 0x11, 0x4C, 0x2F, 0xBB, 0x09, 0x15,
                0x27, 0xEB, 0x7C, 0x64, 0xEC, 0xB1, 0x1F, 0x80,
                0x21, 0xCB, 0x45, 0xE8, 0xE7, 0x80, 0x9D, 0x3C,
                0x09, 0x38, 0xE4, 0xB8, 0xC0, 0xE5, 0xF8, 0x4B,
        };

        static const unsigned char msg[32] = {
                0x5E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A,
                0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D,
                0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33,
                0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C,
        };

        static const unsigned char sig[64] = {
                0x00, 0xDA, 0x9B, 0x08, 0x17, 0x2A, 0x9B, 0x6F,
                0x04, 0x66, 0xA2, 0xDE, 0xFD, 0x81, 0x7F, 0x2D,
                0x7A, 0xB4, 0x37, 0xE0, 0xD2, 0x53, 0xCB, 0x53,
                0x95, 0xA9, 0x63, 0x86, 0x6B, 0x35, 0x74, 0xBE,
                0xD0, 0x92, 0xF9, 0xD8, 0x60, 0xF1, 0x77, 0x6A,
                0x1F, 0x74, 0x12, 0xAD, 0x8A, 0x1E, 0xB5, 0x0D,
                0xAC, 0xCC, 0x22, 0x2B, 0xC8, 0xC0, 0xE2, 0x6B,
                0x20, 0x56, 0xDF, 0x2F, 0x27, 0x3E, 0xFD, 0xEC,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 8: Negated s, R.x mismatch */
        static const unsigned char pkbuf[33] = {
                0x02,
                0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        };

        static const unsigned char msg[32] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        static const unsigned char sig[64] = {
                0x78, 0x7A, 0x84, 0x8E, 0x71, 0x04, 0x3D, 0x28,
                0x0C, 0x50, 0x47, 0x0E, 0x8E, 0x15, 0x32, 0xB2,
                0xDD, 0x5D, 0x20, 0xEE, 0x91, 0x2A, 0x45, 0xDB,
                0xDD, 0x2B, 0xD1, 0xDF, 0xBF, 0x18, 0x7E, 0xF6,
                0x8F, 0xCE, 0x56, 0x77, 0xCE, 0x7A, 0x62, 0x3C,
                0xB2, 0x00, 0x11, 0x22, 0x57, 0x97, 0xCE, 0x7A,
                0x8D, 0xE1, 0xDC, 0x6C, 0xCD, 0x4F, 0x75, 0x4A,
                0x47, 0xDA, 0x6C, 0x60, 0x0E, 0x59, 0x54, 0x3C,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 9: Negated P, R.x mismatch */
        static const unsigned char pkbuf[33] = {
                0x03,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
                0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
                0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
                0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 10: s * G = e * P, R = 0 */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0x8C, 0x34, 0x28, 0x86, 0x9A, 0x66, 0x3E, 0xD1,
                0xE9, 0x54, 0x70, 0x5B, 0x02, 0x0C, 0xBB, 0x3E,
                0x7B, 0xB6, 0xAC, 0x31, 0x96, 0x5B, 0x9E, 0xA4,
                0xC7, 0x3E, 0x22, 0x7B, 0x17, 0xC5, 0xAF, 0x5A,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 11: R.x not on the curve, R.x mismatch */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x4A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
                0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
                0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
                0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 12: r = p */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x2F,
                0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
                0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
                0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
                0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }

    {
        /* Test vector 13: s = n */
        static const unsigned char pkbuf[33] = {
                0x02,
                0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
                0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
                0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
                0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59,
        };

        static const unsigned char msg[32] = {
                0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
                0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
                0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
                0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
        };

        static const unsigned char sig[64] = {
                0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
                0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
                0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
                0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        };

        CurvePoint pubkey;
        EXPECT_TRUE(pubkey.DecodeCompressed(pkbuf, CurveType::SECP256K1));
        bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, pubkey, sig, msg, sizeof msg,
                                                      safeheron::curve::schnorr::SchnorrPattern::Legacy);
        EXPECT_TRUE(!pass);
    }
}

TEST(SECP256K1, verify_offcial)
{
    printf("/*******************SECP256K1 Verify (BCH Official test cases) begin *********************/\n");
    run_schnorr_compact_test();
    printf("/*******************SECP256K1 Verify (BCH Official test cases) end *********************/\n");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
