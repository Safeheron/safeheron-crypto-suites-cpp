#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "../src/crypto-curve/curve.h"

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

        std::string sig = safeheron::curve::eddsa::Sign(type, privkey, digest, DIGEST_SIZE);
        printf("sign: "); print_hex((uint8_t*)sig.c_str(), SIG_SIZE);

        bool pass = safeheron::curve::eddsa::Verify(type, pubkey, (const uint8_t*)sig.c_str(), digest, DIGEST_SIZE);
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

void test_verify(const std::string &msg, const std::string &pub, const std::string &sig)
{
    std::string m = safeheron::encode::hex::DecodeFromHex(msg);
    std::string p = safeheron::encode::hex::DecodeFromHex(pub);
    std::string s = safeheron::encode::hex::DecodeFromHex(sig);

    CurvePoint pubkey;
    pubkey.DecodeEdwardsPoint((uint8_t*)p.c_str(), CurveType::ED25519);

    bool pass = safeheron::curve::eddsa::Verify(CurveType::ED25519, pubkey, (const uint8_t*)s.c_str(), (const uint8_t*)m.c_str(), m.length());
    EXPECT_TRUE(pass == true);
    if (!pass) {
        printf("verify failed!\n");
    }
    else {
        printf("verify passed!\n");
    }
}

TEST(ed25519, verify)
{
    std::string msg = "1234567812345678123456781234567812345678123456781234567812345678";
    std::string pub = "be94d300187a1c0990bfedf3a22d11dabaa0c606c5c1f6fcb11d56f70185d049";
    std::string sig = "204092fc3a40f493351a4241a969345762e5321bdc3c68e34c59a04cc04e93d13264F73D12EFBE2B4376B9AC5395AF8AF0D94A07F5C958CC569D003F6B448807";
    test_verify(msg, pub, sig);

    msg = "4F1846DD7AD50E545D4CFBFFBB1DC2FF145DC123754D08AF4E44ECC0BC8C91411388BC7653E2D893D1EAC2107D05";
    pub = "be94d300187a1c0990bfedf3a22d11dabaa0c606c5c1f6fcb11d56f70185d049";
    sig = "465e389d708a8d23a0f6eade89e626b4eab7132868652242a0e3125bb79eb8b67A004468D0FFF2AE90A5F04BFA9F788CEB782EF423EDE9A38336AA2E4525280F";
    test_verify(msg, pub, sig);

    msg = "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101";
    pub = "0dd88727387d8b1516c47196643f727ce8166905a0f6ab1da0ed0c6a031fe9bb";
    sig = "68df7684c180479514f7e4ef9d3098db697025ec2595991dff5080a92adb9fe3299bcfdf9c647a156b9d64f78cdc6f25ae2990a7e1119d43ad488793f0dd890f";
    test_verify(msg, pub, sig);

    msg = "1234";
    pub = "14730232fa2fc3a6f0c87e1f63afaa3054f28cb4c5b7175f8504cba3633c1fc6";
    sig = "87ed45ea516ea0bcf4ddc339bce3d7a3269c230389753eb6775355e78ff3f05680891ed1747ab13e79e0df24190bb3bcbaadb77c573f511bf6fb05f2741dc602";
    test_verify(msg, pub, sig);
}

TEST(ed25519, sign_and_verify)
{
    printf("/*******************ED25519 Sign/Verify*********************/\n");
    test_curve_sign(CurveType::ED25519,  1000);
    printf("/*******************ED25519 Sign/Verify*********************/\n");
    printf("\n\n");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
