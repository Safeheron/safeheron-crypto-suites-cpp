#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-bn/bn.h"
#include "exception/located_exception.h"
#include "crypto-curve/curve.h"
#include "crypto-bip32/bip32.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/base58.h"
#include "crypto-encode/base64.h"
#include "crypto-hash/hmac_sha512.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

TEST(Bip32,CreateHDKey_Secp256k1)
{
    std::string seed ={"0102030405060708090A0B0C0D0E0F10"};
    string CHMAC_SHA512_I = "94248494c36ea2cec92b356458119658a2bfea84314a6f8461d3857fa52cd10699d9cf91a64a02110481402e10f035ad95f16f306bffd9a7d7c11c3b9801ad11";
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed);
    root_hd_key.FromSeed(CurveType::SECP256K1, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());

    string priv = CHMAC_SHA512_I.substr(0,64);
    string chain_code = CHMAC_SHA512_I.substr(64,64);
    BN priv_bn(priv.c_str(),16);
    string  chaincode = hex::DecodeFromHex(chain_code);
    const uint8_t* _chaincode = reinterpret_cast<const uint8_t*>(chaincode.c_str());
    HDKey root1_hd_key =safeheron::bip32::HDKey::CreateHDKey(CurveType::SECP256K1,priv_bn,_chaincode);
    uint8_t root1_buf32[32];
    uint8_t root_buf32[32];
    root_hd_key.GetChainCode(root_buf32);
    root1_hd_key.GetChainCode(root1_buf32);
    string root_buf = safeheron::encode::hex::EncodeToHex(root_buf32,32);
    string root_buf1 = safeheron::encode::hex::EncodeToHex(root1_buf32,32);
    EXPECT_TRUE(root_buf == root_buf1);

    uint8_t priv_buf32[32];
    uint8_t priv1_buf32[32];

    root_hd_key.GetPrivateKey(priv_buf32);
    root1_hd_key.GetPrivateKey(priv1_buf32);
    string priv_buf = safeheron::encode::hex::EncodeToHex(priv_buf32,32);
    string priv1_buf1 = safeheron::encode::hex::EncodeToHex(priv1_buf32,32);
    EXPECT_TRUE(priv_buf == priv1_buf1);
}

//SECP256K1
void testCreate(const std::string &seed, const std::string &extended_xprv, const std::string &extended_xpub) {

    std::string seed_bytes = hex::DecodeFromHex(seed);
    HDKey hd_root;
    hd_root.FromSeed(CurveType::SECP256K1, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());

    BN hd_root_priv;
    CurvePoint hd_root_pub;
    uint8_t hd_root_chaincode[32];
    hd_root.GetPrivateKey(hd_root_priv);
    hd_root.GetPublicKey(hd_root_pub);
    hd_root.GetChainCode(hd_root_chaincode);

    uint8_t m[32 + 32];
    safeheron::hash::CHMAC_SHA512 hmac((const uint8_t *)"Bitcoin seed", strlen("Bitcoin seed"));
    hmac.Write(reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());
    hmac.Finalize(m);

    const Curve *curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);

    BN priv = BN::FromBytesBE(m, 32);
    assert((priv != 0) && (priv <= curv->n));
    uint8_t chaincode[32];
    memcpy(chaincode, m+32, 32);

    HDKey hd_root1 = HDKey::CreateHDKey(CurveType::SECP256K1, priv, chaincode);
    BN hd_root1_priv;
    CurvePoint hd_root1_pub;
    uint8_t hd_root1_chaincode[32];
    hd_root1.GetPrivateKey(hd_root1_priv);
    hd_root1.GetPublicKey(hd_root1_pub);
    hd_root1.GetChainCode(hd_root1_chaincode);

    CurvePoint pub = curv->g * priv;
    HDKey hd_root2 = HDKey::CreateHDKey(CurveType::SECP256K1, pub, chaincode);

    CurvePoint hd_root2_pub;
    uint8_t hd_root2_chaincode[32];

    hd_root2.GetPublicKey(hd_root2_pub);
    hd_root2.GetChainCode(hd_root2_chaincode);

    HDKey hd_root3;
    hd_root3.FromExtendedPrivateKey(extended_xprv, CurveType::SECP256K1);
    BN hd_root3_priv;
    CurvePoint hd_root3_pub;
    uint8_t hd_root3_chaincode[32];
    hd_root3.GetPrivateKey(hd_root3_priv);
    hd_root3.GetPublicKey(hd_root3_pub);
    hd_root3.GetChainCode(hd_root3_chaincode);

    HDKey hd_root4;
    hd_root4.FromExtendedPublicKey(extended_xpub, CurveType::SECP256K1);
    CurvePoint hd_root4_pub;
    uint8_t hd_root4_chaincode[32];
    hd_root4.GetPublicKey(hd_root4_pub);
    hd_root4.GetChainCode(hd_root4_chaincode);


    //verify
    EXPECT_TRUE(hd_root_priv == priv);
    EXPECT_TRUE(hd_root_pub == pub);
    EXPECT_TRUE(strncmp((char *)hd_root_chaincode, (char *)chaincode, 32) == 0);

    EXPECT_TRUE(hd_root1_priv == priv);
    EXPECT_TRUE(hd_root1_pub == pub);
    EXPECT_TRUE(strncmp((char *)hd_root1_chaincode, (char *)chaincode, 32) == 0);

    EXPECT_TRUE(hd_root2_pub == pub);
    EXPECT_TRUE(strncmp((char *)hd_root2_chaincode, (char *)chaincode, 32) == 0);

    EXPECT_TRUE(hd_root3_priv == priv);
    EXPECT_TRUE(hd_root3_pub == pub);
    EXPECT_TRUE(strncmp((char *)hd_root3_chaincode, (char *)chaincode, 32) == 0);

    EXPECT_TRUE(hd_root4_pub == pub);
    EXPECT_TRUE(strncmp((char *)hd_root4_chaincode, (char *)chaincode, 32) == 0);

}
const static std::vector<std::vector<std::string>> test_vector = {
        {
            "000102030405060708090a0b0c0d0e0f",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        },
        {
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        },
        {
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        }
};
TEST(Bip32, CreateHDKey) {
    for(size_t i = 0; i < test_vector.size(); ++i) {
        std::string seed = test_vector[i][0];
        std::string xprv = test_vector[i][2];
        std::string xpub = test_vector[i][1];
        testCreate(seed, xprv, xpub);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
