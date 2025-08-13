#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

void print_hex(const uint8_t* buff, size_t size)
{
    if (!buff) return;

    for (size_t i = 0; i < size; i++) {
        printf("%02X", buff[i]);
    }
    printf("\n");
}

int test_curve_sign(CurveType type, int times)
{
    int cur_time = 0;
    const int DIGEST_SIZE = 32;
    const int SIG_SIZE = 64;
    const Curve *curv = GetCurveParam(type);

    do {
        BN privkey = safeheron::rand::RandomBNLt(curv->n);
        printf("Private Key: %s\n", privkey.Inspect().c_str());

        CurvePoint pubkey = curv->g * privkey;
        printf("Public Key: %s\n", pubkey.Inspect().c_str());

        uint8_t digest[DIGEST_SIZE] = {0};
        safeheron::rand::RandomBytes(digest, DIGEST_SIZE);
        printf("data: "); print_hex(digest, DIGEST_SIZE);

        uint8_t sig[SIG_SIZE] = {0};
        //    memset(sig, 0, 64);
        safeheron::curve::ecdsa::Sign(type, privkey, digest, sig);
        printf("sign: "); print_hex(sig, SIG_SIZE);

        bool pass = safeheron::curve::ecdsa::Verify(type, pubkey, digest, sig);
        EXPECT_TRUE(pass == true);
        if (!pass) {
            printf("verify failed!\n");
        }
        else {
            printf("verify passed!\n");
        }
    }while (++cur_time < times);
    return 0;
}

int test_curve_sign_2(CurveType type, int times)
{
    int cur_time = 0;
    const int DIGEST_SIZE = 32;
    const int SIG_SIZE = 64;
    const Curve *curv = GetCurveParam(type);

    do {
        BN privkey = safeheron::rand::RandomBNLt(curv->n);
        printf("Private Key : %s\n", privkey.Inspect().c_str());

        CurvePoint pubkey = curv->g * privkey;
        printf("Public Key : %s\n", pubkey.Inspect().c_str());

        uint8_t digest[DIGEST_SIZE] = {0};
        safeheron::rand::RandomBytes(digest, DIGEST_SIZE);
        printf("data: "); print_hex(digest, DIGEST_SIZE);
        BN h = BN::FromBytesBE(digest, DIGEST_SIZE);

        uint8_t sig[SIG_SIZE] = {0};
        uint8_t v;
        safeheron::curve::ecdsa::Sign(v, type, privkey, digest, sig);
        printf("sign: "); print_hex(sig, SIG_SIZE);

        BN r = BN::FromBytesBE(sig, 32);
        BN s = BN::FromBytesBE(sig + 32, 32);

        bool ok = safeheron::curve::ecdsa::RecoverPublicKey(pubkey, type, h, r, s, v);
        EXPECT_TRUE(ok);

        std::cout << "Public Key(recovered): " << pubkey.Inspect() << std::endl;

        // check "recovered pubkey == pubkey"
        ok = curv->g * privkey == pubkey;
        EXPECT_TRUE(ok);

        // verify signature
        ok = safeheron::curve::ecdsa::Verify(type, pubkey, digest, sig);
        EXPECT_TRUE(ok);
        if (!ok) {
            printf("verify failed!\n");
        }
        else {
            printf("verify passed!\n");
        }

    }while (++cur_time < times);
    return 0;
}
TEST(curve, sign_and_verify)
{
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    test_curve_sign(CurveType::SECP256K1,  1000);
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    printf("\n\n");
    printf("/*******************P256 Sign/Verify*********************/\n");
    test_curve_sign(CurveType::P256,  1000);
    printf("/*******************P256 Sign/Verify*********************/\n");
    printf("\n\n");
    printf("/*******************STARK Sign/Verify*********************/\n");

#if ENABLE_STARK
    test_curve_sign(CurveType::STARK,  1000);
    printf("/*******************STARK Sign/Verify*********************/\n");
    printf("\n\n");
#endif // ENABLE_STARK
}

TEST(curve, sign_and_verify_2)
{
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    test_curve_sign_2(CurveType::SECP256K1,  1000);
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    printf("\n\n");
    printf("/*******************P256 Sign/Verify*********************/\n");
    test_curve_sign_2(CurveType::P256,  1000);
    printf("/*******************P256 Sign/Verify*********************/\n");
    printf("\n\n");
    printf("/*******************STARK Sign/Verify*********************/\n");

#if ENABLE_STARK
    test_curve_sign_2(CurveType::STARK,  1000);
    printf("/*******************STARK Sign/Verify*********************/\n");
    printf("\n\n");
#endif // ENABLE_STARK
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
