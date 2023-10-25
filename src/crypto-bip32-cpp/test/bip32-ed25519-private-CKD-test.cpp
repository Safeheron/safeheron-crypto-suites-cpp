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

std::vector<string> case_data_root_xprv_Ed25519 = {"eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c"};
std::vector<std::vector<std::vector<std::string>>> case_data_private_ckd_child_key_Ed25519 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m",
                        "eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c"
                },
                {
                        "m/44/60/0",
                        "eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm"
                },
                {
                        "m/44/60/1",
                        "eprv48jMzZSh71Sx9f2jQAshscVct4EEMS4dkcPHvWmNM6g5uZrqtLFJ9574cUzHbEX3UatTSEtcVsJVS1eYZAFy6sAK1PJpk14qFsyen9riCtv"
                },
                {
                        "m/44/60/2",
                        "eprv48jMzZSh71SxAQfV9mHKJmhBP6pvzZsdZGTYCuzJb2bNnKhvsEjU2d3sfBEZZ4xfFfNCQrXMsF7fgQJs3vJoU5poivTkVhCTbjW31HxrPtU"
                },
                {
                        "m/44/60/3",
                        "eprv48jMzZSh71SxEY29US1HTD117pa7WvqPimsEANK8zLMaHNYa4XD8gmMqLXWtNXit5uEtsCzjqLZaBdNE2aX2rPM9EgzwmyTYtzYRFWcNPgi"
                },
                {
                        "m/44/60/4",
                        "eprv48jMzZSh71SxGQr3YyAizSjsdjx5MqFq9nSupn39wR4wMyprnF3xPuYdkcpBWEYBwjDCJH3z3X8ovjWTJTmx5xxwvpofDRsY9RTwWVPWpC8"
                },
        },
};

void testprivateCKD_Ed25519(const string &xprv, const string &path, const string &child_xprv) {
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPrivateKey(xprv, CurveType::ED25519);
    ASSERT_TRUE(ok);
    std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string t_child_xprv;
    child_hd_key.ToExtendedPrivateKey(t_child_xprv);
    std::cout << "child_xprv: " << child_xprv << std::endl;
    ASSERT_EQ(t_child_xprv, child_xprv);
}

TEST(Bip32, PrivateCKDTestCase_Ed25519) {
    for (size_t i = 0; i < case_data_root_xprv_Ed25519.size(); i++) {
        for (size_t j = 0; j < case_data_private_ckd_child_key_Ed25519[i].size(); j++) {
            const string &xprv = case_data_root_xprv_Ed25519[i];
            const string &path = case_data_private_ckd_child_key_Ed25519[i][j][0];
            const string &child_xprv = case_data_private_ckd_child_key_Ed25519[i][j][1];
            testprivateCKD_Ed25519(xprv, path, child_xprv);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
