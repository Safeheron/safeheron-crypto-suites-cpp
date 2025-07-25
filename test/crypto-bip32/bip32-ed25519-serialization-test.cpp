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


std::vector<std::vector<string>> case_data_serialize_hdkey_ed25519 = {
        {
                "eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c",
                "epub8YjJEGN2T9xLdin8GVPo4JD8jS9FWrCtvP4j48pZUA7zjuFWN7igGdB4F39s7umSx7CoiLF13yzPL8sUJWL14sPkVMdY9VHQjZVeVQSjWPZ",
        },
        {
                "eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm",
                "epub8fRQ8yUwFP8cyL4S6pkNgEnhovARJJ4fGiA7AK18bghTwdaL8WmVNtey5uWHTYN8V63YFCD8L1xW9YCoKd6vwd7jtzLnBfeGqJ4De4Fe9wB"
        },
        {
                "eprv48jMzZSh71Sx9f2jQAshscVct4EEMS4dkcPHvWmNM6g5uZrqtLFJ9574cUzHbEX3UatTSEtcVsJVS1eYZAFy6sAK1PJpk14qFsyen9riCtv",
                "epub8fRQ8yUwFP8d384XHpYJH29jT5kAWmFYKuz5D2ofmNUUk47cWj4tKZivnXy97eKHQY5oQUv5qTMLJng16n4PAfB4U8ap7Z7b7FXVijt2pzg"
        },
};

void testSerializeHDKey_Ed25519(const std::string &xprv, const std::string &xpub){
    HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::ED25519));

    std::string t_xpriv;
    hdKey.ToExtendedPrivateKey(t_xpriv);
    //std::cout << "t_xpriv:        " << t_xpriv << std::endl;
    //std::cout << "xprv: " << xprv << std::endl;
    EXPECT_TRUE(t_xpriv == xprv);

    HDKey hdKey2;
    EXPECT_TRUE(hdKey2.FromExtendedPublicKey(xpub, CurveType::ED25519));
    std::string t_xpub;
    hdKey2.ToExtendedPublicKey(t_xpub);
    //std::cout << "t_xpub:        " << t_xpub << std::endl;
    //std::cout << "xpub: " << xpub << std::endl;
    EXPECT_TRUE(t_xpub == xpub);
}

TEST(Bip32, SerializeHDKey_Ed25519)
{
    for(const auto &hd_key_pair: case_data_serialize_hdkey_ed25519){
        const string &xprv = hd_key_pair[0];
        const string &xpub = hd_key_pair[1];
        testSerializeHDKey_Ed25519(xprv, xpub);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
