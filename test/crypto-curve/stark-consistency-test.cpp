#include <cstring>
#include "gtest/gtest.h"
#include "crypto-encode/hex.h"
#include "crypto-curve/curve.h"

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

TEST(curve, stark_curve_static)
{
    std::string x, y;
    const Curve *curv = GetCurveParam(CurveType::STARK);
    curv->g.x().ToHexStr(x);
    curv->g.y().ToHexStr(y);
    printf("g.x = %s\n", x.c_str());
    printf("g.y = %s\n", y.c_str());
    EXPECT_TRUE(x == "01EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA");
    EXPECT_TRUE(y == "5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F");

    CurvePoint point2 = curv->g * BN::TWO;
    point2.x().ToHexStr(x);
    point2.y().ToHexStr(y);
    printf("2g.x = %s\n", x.c_str());
    printf("2g.y = %s\n", y.c_str());
    EXPECT_TRUE(x == "0759CA09377679ECD535A81E83039658BF40959283187C654C5416F439403CF5");
    EXPECT_TRUE(y == "06F524A3400E7708D5C01A28598AD272E7455AA88778B19F93B562D7A9646C41");

    CurvePoint point3 = curv->g * BN::THREE;
    point3.x().ToHexStr(x);
    point3.y().ToHexStr(y);
    printf("3g.x = %s\n", x.c_str());
    printf("3g.y = %s\n", y.c_str());
    EXPECT_TRUE(x == "0411494B501A98ABD8262B0DA1351E17899A0C4EF23DD2F96FEC5BA847310B20");
    EXPECT_TRUE(y == "07E1B3EBAC08924D2C26F409549191FCF94F3BF6F301ED3553E22DFB802F0686");

    CurvePoint point4 = curv->g * BN::FOUR;
    point4.x().ToHexStr(x);
    point4.y().ToHexStr(y);
    printf("4g.x = %s\n", x.c_str());
    printf("4g.y = %s\n", y.c_str());
    EXPECT_TRUE(x == "A7DA05A4D664859CCD6E567B935CDFBFE3018C7771CB980892EF38878AE9BC");
    EXPECT_TRUE(y == "0584B0C2BC833A4C88D62B387E0EF868CAE2EAAA288F4CA7B34C84B46CA031B6");

    CurvePoint point7 = point3 + point4;
    point7.x().ToHexStr(x);
    point7.y().ToHexStr(y);
    printf("7g.x = %s\n", x.c_str());
    printf("7g.y = %s\n", y.c_str());
    EXPECT_TRUE(x == "0743829E0A179F8AFE223FC8112DFC8D024AB6B235FD42283C4F5970259CE7B7");
    EXPECT_TRUE(y == "E67A0A63CC493225E45B9178A3375596EA2A1D7012628A328DBC14C78CD1B7");
}

TEST(curve, stark_consistency_sign)
{
    const std::string privkey_hex = "03C1E9550E66958296D11B60F8E8E7A7AD990D07FA65D5F7652C4A6C87D4E3CC";
    const std::string pubkeyx_hex = "077A3B314DB07C45076D11F62B6F9E748A39790441823307743CF00D6597EA43";
    const std::string pubkeyy_hex = "054D7BEEC5EC728223671C627557EFC5C9A6508425DC6C900B7741BF60AFEC06";

    // test public key
    std::string x, y;
    const Curve *curv = GetCurveParam(CurveType::STARK);
    const BN privkey(privkey_hex.c_str(), 16);
    CurvePoint pubkey = curv->g * privkey;
    pubkey.x().ToHexStr(x);
    pubkey.y().ToHexStr(y);
    printf("pubkey.x = %s\n", x.c_str());
    printf("pubkey.y = %s\n", y.c_str());
    EXPECT_TRUE(x == pubkeyx_hex);
    EXPECT_TRUE(y == pubkeyy_hex);

    uint8_t digest[32] = {0};

    // test signature case 1
    std::string hash_hex = "01";
    std::string r_hex = "06fdd4e4bf3fcd781997f9deba654356e629177ce4d804bc527044f222828f25";
    std::string s_hex = "033302ce7c82a7e199a8d7faaae8a53a2f447c9dd1262b1862b03a46104bc1d2";
    std::string sig_hex = r_hex + s_hex;
    //
    std::string hash = safeheron::encode::hex::DecodeFromHex(hash_hex);
    std::string sig = safeheron::encode::hex::DecodeFromHex(sig_hex);
    memset(digest, 0, 32);
    memcpy(digest + 32 - hash.length(), (const uint8_t*)hash.c_str(), hash.length());
    printf("hash = "); print_hex(digest, 32);
    printf("sign = "); print_hex((uint8_t*)sig.c_str(), sig.length());
    bool pass = safeheron::curve::ecdsa::Verify(CurveType::STARK, pubkey, digest, (const uint8_t*)sig.c_str());
    EXPECT_TRUE(pass);

    // test signature case 2
    hash_hex = "123456";
    r_hex = "0673530c734c7f7bba8f4db260a7f2eb27ca6605300de48c6720853292cf9d04";
    s_hex = "04872267a2ef6acf721430dee7f1dc80bce883088fbf55c3fdd952d55b1c0a4f";
    sig_hex = r_hex + s_hex;
    //
    hash = safeheron::encode::hex::DecodeFromHex(hash_hex);
    sig = safeheron::encode::hex::DecodeFromHex(sig_hex);
    memset(digest, 0, 32);
    memcpy(digest + 32 - hash.length(), (const uint8_t*)hash.c_str(), hash.length());
    printf("hash = "); print_hex(digest, 32);
    printf("sign = "); print_hex((uint8_t*)sig.c_str(), sig.length());
    pass = safeheron::curve::ecdsa::Verify(CurveType::STARK, pubkey, digest, (const uint8_t*)sig.c_str());
    EXPECT_TRUE(pass);

    // test signature case 3
    hash_hex = "ffffffffff";
    r_hex = "07e2d65b7a6da7a85b62db64aa6c798dcd52182772a52e22babca32569cbe80d";
    s_hex = "0143202b69186093f3a4df7d0095e95f5c93f5e660971d94358a61b3feea533d";
    sig_hex = r_hex + s_hex;
    //
    hash = safeheron::encode::hex::DecodeFromHex(hash_hex);
    sig = safeheron::encode::hex::DecodeFromHex(sig_hex);
    memset(digest, 0, 32);
    memcpy(digest + 32 - hash.length(), (const uint8_t*)hash.c_str(), hash.length());
    printf("hash = "); print_hex(digest, 32);
    printf("sign = "); print_hex((uint8_t*)sig.c_str(), sig.length());
    pass = safeheron::curve::ecdsa::Verify(CurveType::STARK, pubkey, digest, (const uint8_t*)sig.c_str());
    EXPECT_TRUE(pass);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
