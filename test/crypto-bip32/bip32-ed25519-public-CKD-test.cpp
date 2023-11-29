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

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

std::vector<string> case_data_seeds_ed25519 = {"0102030405060708090A0B0C0D0E0F10"};
std::vector<std::vector<std::vector<std::string>>> case_data_child_key_ed25519 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m",
                        "eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c",
                        "epub8YjJEGN2T9xLdin8GVPo4JD8jS9FWrCtvP4j48pZUA7zjuFWN7igGdB4F39s7umSx7CoiLF13yzPL8sUJWL14sPkVMdY9VHQjZVeVQSjWPZ",
                },
                {
                        "m/44/60/0",
                        "eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm",
                        "epub8fRQ8yUwFP8cyL4S6pkNgEnhovARJJ4fGiA7AK18bghTwdaL8WmVNtey5uWHTYN8V63YFCD8L1xW9YCoKd6vwd7jtzLnBfeGqJ4De4Fe9wB"
                },
                {
                        "m/44/60/1",
                        "eprv48jMzZSh71Sx9f2jQAshscVct4EEMS4dkcPHvWmNM6g5uZrqtLFJ9574cUzHbEX3UatTSEtcVsJVS1eYZAFy6sAK1PJpk14qFsyen9riCtv",
                        "epub8fRQ8yUwFP8d384XHpYJH29jT5kAWmFYKuz5D2ofmNUUk47cWj4tKZivnXy97eKHQY5oQUv5qTMLJng16n4PAfB4U8ap7Z7b7FXVijt2pzg"
                },
                {
                        "m/44/60/2",
                        "eprv48jMzZSh71SxAQfV9mHKJmhBP6pvzZsdZGTYCuzJb2bNnKhvsEjU2d3sfBEZZ4xfFfNCQrXMsF7fgQJs3vJoU5poivTkVhCTbjW31HxrPtU",
                        "epub8fRQ8yUwFP8d3shH3QwuiBMHx8Ls9u4Y8a4KVS2c1JPmcoxhVdZ4D7fjqEyjfxpwGsXzGDT5TW6CX5Vjk9bHRpcYW7q2KCdfNYpsoKckHGc"
                },
                {
                        "m/44/60/3",
                        "eprv48jMzZSh71SxEY29US1HTD117pa7WvqPimsEANK8zLMaHNYa4XD8gmMqLXWtNXit5uEtsCzjqLZaBdNE2aX2rPM9EgzwmyTYtzYRFWcNPgi",
                        "epub8fRQ8yUwFP8d813wN5fsrcf7gr63gG2JJ5U1StMSQc9y7roLgv2isFyhWafzi6dkndaoAVakLJ1fELVCVTXqRVdjcnhcvnQPgMRJRB2TY3d"
                },
                {
                        "m/44/60/4",
                        "eprv48jMzZSh71SxGQr3YyAizSjsdjx5MqFq9nSupn39wR4wMyprnF3xPuYdkcpBWEYBwjDCJH3z3X8ovjWTJTmx5xxwvpofDRsY9RTwWVPWpC8",
                        "epub8fRQ8yUwFP8d9ssqScqKPrPzCmU1XASjj63h7J5TMgsLCU5dQdsYaQAVvfiKyvAJSoQMsSW6AweVYWnAuEgLrmq7TwJptRCtpLqPShfCdBR"
                },
        },
};

void testSeedAndCKD_Ed25519(const string &seed_hex, const string &path, const string &xprv, const string &xpub){
    bool ok;
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed_hex);
    ok = root_hd_key.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);

    //std::cout << "child_xprv: " << child_xprv << std::endl;
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    ASSERT_EQ(child_xprv, xprv);
    ASSERT_EQ(child_xpub, xpub);

    BN delta(0);
    string root_xpub;
    root_hd_key.ToExtendedPublicKey(root_xpub);
    HDKey root_hd_key_p;
    ok = root_hd_key_p.FromExtendedPublicKey(root_xpub, CurveType::ED25519);
    ASSERT_TRUE(ok);
    child_hd_key = root_hd_key_p.PublicCKDPath(path.c_str(), delta);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(child_xpub, xpub);


    const Curve *curv = safeheron::curve::GetCurveParam(CurveType::ED25519);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Ed25519)
{
    for(size_t i = 0; i < case_data_child_key_ed25519.size(); i++ ){
        for(size_t j = 0; j < case_data_child_key_ed25519[i].size(); j++){
            const string & seed = case_data_seeds_ed25519[i];
            const string & path = case_data_child_key_ed25519[i][j][0];
            const string & xprv = case_data_child_key_ed25519[i][j][1];
            const string & xpub = case_data_child_key_ed25519[i][j][2];
            testSeedAndCKD_Ed25519(seed, path, xprv, xpub);
        }
    }
}

void testSeedAndCKD_Ed25519_with_false_ret(const string &seed_hex, const string &path, const string &xprv, const string &xpub){
    bool ok;
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed_hex);
    ok = root_hd_key.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    HDKey child_hd_key;
    ok = root_hd_key.PrivateCKDPath(child_hd_key, path.c_str());
    ASSERT_TRUE(ok);
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);

    //std::cout << "child_xprv: " << child_xprv << std::endl;
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    //std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    //std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    ASSERT_EQ(child_xprv, xprv);
    ASSERT_EQ(child_xpub, xpub);

    BN delta(0);
    string root_xpub;
    root_hd_key.ToExtendedPublicKey(root_xpub);
    HDKey root_hd_key_p;
    ok = root_hd_key_p.FromExtendedPublicKey(root_xpub, CurveType::ED25519);
    ASSERT_TRUE(ok);
    ok = root_hd_key_p.PublicCKDPath(child_hd_key,path.c_str(), delta);
    ASSERT_TRUE(ok);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(child_xpub, xpub);


    const Curve *curv = safeheron::curve::GetCurveParam(CurveType::ED25519);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Ed25519_with_false_ret)
{
    for(size_t i = 0; i < case_data_child_key_ed25519.size(); i++ ){
        for(size_t j = 0; j < case_data_child_key_ed25519[i].size(); j++){
            const string & seed = case_data_seeds_ed25519[i];
            const string & path = case_data_child_key_ed25519[i][j][0];
            const string & xprv = case_data_child_key_ed25519[i][j][1];
            const string & xpub = case_data_child_key_ed25519[i][j][2];
            testSeedAndCKD_Ed25519_with_false_ret(seed, path, xprv, xpub);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
