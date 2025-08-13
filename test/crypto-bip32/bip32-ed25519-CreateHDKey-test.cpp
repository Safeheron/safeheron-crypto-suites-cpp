#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/exception/located_exception.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bip32/bip32.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-encode/base58.h"
#include "crypto-suites/crypto-encode/base64.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

TEST(Bip32,CreateHDKey_Ed25519)
{
    std::string seed ={"0102030405060708090A0B0C0D0E0F10"};
    string CHMAC_SHA512_I = "94248494c36ea2cec92b356458119658a2bfea84314a6f8461d3857fa52cd10699d9cf91a64a02110481402e10f035ad95f16f306bffd9a7d7c11c3b9801ad11";
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed);
    root_hd_key.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());

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

TEST(Bip32,CreateHDKey_Ed25519_with_false_ret)
{
    std::string seed ={"0102030405060708090A0B0C0D0E0F10"};
    string CHMAC_SHA512_I = "94248494c36ea2cec92b356458119658a2bfea84314a6f8461d3857fa52cd10699d9cf91a64a02110481402e10f035ad95f16f306bffd9a7d7c11c3b9801ad11";
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed);
    root_hd_key.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());

    string priv = CHMAC_SHA512_I.substr(0,64);
    string chain_code = CHMAC_SHA512_I.substr(64,64);
    BN priv_bn(priv.c_str(),16);
    string  chaincode = hex::DecodeFromHex(chain_code);
    const uint8_t* _chaincode = reinterpret_cast<const uint8_t*>(chaincode.c_str());
    HDKey root1_hd_key;
    bool ok = safeheron::bip32::HDKey::CreateHDKey(root1_hd_key, CurveType::SECP256K1,priv_bn,_chaincode);
    EXPECT_TRUE(ok);
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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
