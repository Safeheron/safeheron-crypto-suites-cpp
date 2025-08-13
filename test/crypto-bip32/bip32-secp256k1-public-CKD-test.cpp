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

const static std::vector<std::vector<std::string>> test_vector {

        {
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                "m/0",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        }
};
void test_PubCKD(const std::string &root_xpub, const std::string &path, const std::string &child_xpub) {
    HDKey hd_root;
    hd_root.FromExtendedPublicKey(root_xpub, CurveType::SECP256K1);
    HDKey child_key = hd_root.PublicCKDPath(path);
    std::string child_xpub_gen;
    child_key.ToExtendedPublicKey(child_xpub_gen);
    EXPECT_TRUE(child_xpub == child_xpub_gen);
}
TEST(bip32, PubCKD) {
    for (size_t i = 0; i < test_vector.size(); ++i) {
        std::string root_xpub = test_vector[i][0];
        size_t j = 1;
        while (j < test_vector[i].size()) {
            std::string path = test_vector[i][j];
            ++j;
            std::string child_xpub = test_vector[i][j];
            ++j;
            test_PubCKD(root_xpub, path, child_xpub);
        }

    }
}


std::vector<std::vector<string>> case_data_public_cdk_secp256k1 = {
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/0",
                "xpub6FhYNQEVoQX8hDWvvuagZu7w2oBhgwWLJcQKeUpqeMbD4F5mYcHe3cWdzcLkuWVgXQbCoYDcWo1GT9gjDJxfR1a3UiL8YdEccCtduJZSYm8",
                "68ccb77ec22767916e6364c4f514021169a14bec0e40fd817b5d08ee04345349"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/1",
                "xpub6FhYNQEVoQX8kAAWmYh966iMnE1sQ8ThaYK1UYeihUPEdM3oEWMaWgmTWSxm8nUnAHe2VAWEJmYfNqLfcRT8c8aBwuRQ1VEsYEue6bryKnH",
                "572d022fd0c1fdd9e90bf0f85a6b6d9492469df4b3beec5350b5a634f940d97"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/2",
                "xpub6FhYNQEVoQX8nZKHbeokzeuJLgSPruJmgjHVeSDiWETiWJ4hZGEPEpQNzXsYXtZ14xt8pUA4yPh9yCSB1ysHstNAeWo7hd4sNV1CcztdfZW",
                "4c48648d91bd8ab02872a5631930783e59b42f9aa16339e2703ac9293ccafe43"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/3",
                "xpub6FhYNQEVoQX8poKL4mpc9754yphsqSJqVtJUEVVn846GyR9ReXR4bhkFmSDac3ui479KTvTDsQAR1yHcL3XFG6om8D7oRCEGxrMiYNRbG6G",
                "d13d3f61687bc407c23cf25ee88fa012b51f1937ddd4491179329d7734f0f788"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/4",
                "xpub6FhYNQEVoQX8thvrJ96vR3VcMo345uwvjrt2ybS5kMzGez3YR1w2MVQ6CqHmWgNDYrbqVX3SincAuX6Qa4KxsPv9X3n43edWnC3vD7xz8km",
                "f35243e947cf29d324e3266dc08bdd6486e311c7b16a68e09a2f9f6a596c5ebd"
        }
};

void testPublicCKD_Secp256k1(std::string xprv, std::string path, std::string child_xpub, std::string deltaStr){
    BN delta = BN::FromHexStr(deltaStr);
    safeheron::bip32::HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::SECP256K1));

    safeheron::bip32::HDKey childHDKey;
    BN t_delta;
    childHDKey = hdKey.PublicCKDPath(path, t_delta);
    std::string t_child_xpub;
    childHDKey.ToExtendedPublicKey(t_child_xpub);
    std::cout << "  child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    std::cout << "t_child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(t_child_xpub)) << std::endl;
    EXPECT_TRUE(child_xpub == t_child_xpub);
    EXPECT_TRUE(delta == t_delta);


    std::string t_delta_str;
    t_delta.ToHexStr(t_delta_str);
    //std::cout << "delta: " << t_delta_str << std::endl;
}

TEST(Bip32, PublicCDK_Secp256k1)
{
    for(const auto &item: case_data_public_cdk_secp256k1){
        const string &xprv = item[0];
        const string &path = item[1];
        const string &child_xpub = item[2];
        const string &delta = item[3];
        testPublicCKD_Secp256k1(xprv, path, child_xpub, delta);
    }
}

void testPublicCKD_Secp256k1_with_false_ret(std::string xprv, std::string path, std::string child_xpub, std::string deltaStr){
    BN delta = BN::FromHexStr(deltaStr);
    safeheron::bip32::HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::SECP256K1));

    safeheron::bip32::HDKey childHDKey;
    BN t_delta;
    bool ok = hdKey.PublicCKDPath(childHDKey, path, t_delta);
    EXPECT_TRUE(ok);
    std::string t_child_xpub;
    childHDKey.ToExtendedPublicKey(t_child_xpub);
    //std::cout << "  child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    //std::cout << "t_child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(t_child_xpub)) << std::endl;
    EXPECT_TRUE(child_xpub == t_child_xpub);
    EXPECT_TRUE(delta == t_delta);


    std::string t_delta_str;
    t_delta.ToHexStr(t_delta_str);
    //std::cout << "delta: " << t_delta_str << std::endl;
}

TEST(Bip32, PublicCDK_Secp256k1_with_false_ret)
{
    for(const auto &item: case_data_public_cdk_secp256k1){
        const string &xprv = item[0];
        const string &path = item[1];
        const string &child_xpub = item[2];
        const string &delta = item[3];
        testPublicCKD_Secp256k1_with_false_ret(xprv, path, child_xpub, delta);
    }
}


std::vector<string> case_data_root_xpub_secp256k1 = {"xpub661MyMwAqRbcGQmVCzudmLbsCwDVcyZPHEumbwahrVxrBwS3QkGDEbVtTBwvUP4HruZn2cssHsywMREQh9R3XgUbe7hjfK2Z5sxJrJQEnNh"};
std::vector<std::vector<std::vector<std::string>>> case_data_public_ckd_child_key_secp256k1 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m/44/60/0/0/0",
                        "xpub6FhYNQEVoQX8hDWvvuagZu7w2oBhgwWLJcQKeUpqeMbD4F5mYcHe3cWdzcLkuWVgXQbCoYDcWo1GT9gjDJxfR1a3UiL8YdEccCtduJZSYm8",
                },
                {
                        "m/44/60/0/0/1",
                        "xpub6FhYNQEVoQX8kAAWmYh966iMnE1sQ8ThaYK1UYeihUPEdM3oEWMaWgmTWSxm8nUnAHe2VAWEJmYfNqLfcRT8c8aBwuRQ1VEsYEue6bryKnH"
                },
                {
                        "m/44/60/0/0/2",
                        "xpub6FhYNQEVoQX8nZKHbeokzeuJLgSPruJmgjHVeSDiWETiWJ4hZGEPEpQNzXsYXtZ14xt8pUA4yPh9yCSB1ysHstNAeWo7hd4sNV1CcztdfZW"
                },
                {
                        "m/44/60/0/0/3",
                        "xpub6FhYNQEVoQX8poKL4mpc9754yphsqSJqVtJUEVVn846GyR9ReXR4bhkFmSDac3ui479KTvTDsQAR1yHcL3XFG6om8D7oRCEGxrMiYNRbG6G"
                },
                {
                        "m/44/60/0/0/4",
                        "xpub6FhYNQEVoQX8thvrJ96vR3VcMo345uwvjrt2ybS5kMzGez3YR1w2MVQ6CqHmWgNDYrbqVX3SincAuX6Qa4KxsPv9X3n43edWnC3vD7xz8km"
                },
        },
};

void testPublicCKD_Secp256k1(const string &xpub, const string &path, const string &child_xpub){
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPublicKey(xpub, CurveType::SECP256K1);
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    BN delta;
    HDKey child_hd_key = root_hd_key.PublicCKDPath(path.c_str(), delta);
    string t_child_xpub;
    child_hd_key.ToExtendedPublicKey(t_child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(t_child_xpub, child_xpub);

    const Curve *curv = GetCurveParam(CurveType::SECP256K1);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Secp256k1)
{
    for(size_t i = 0; i < case_data_root_xpub_secp256k1.size(); i++ ){
        for(size_t j = 0; j < case_data_public_ckd_child_key_secp256k1[i].size(); j++){
            const string & xpub = case_data_root_xpub_secp256k1[i];
            const string & path = case_data_public_ckd_child_key_secp256k1[i][j][0];
            const string & child_xpub = case_data_public_ckd_child_key_secp256k1[i][j][1];
            testPublicCKD_Secp256k1(xpub, path, child_xpub);
        }
    }
}

void testPublicCKD_Secp256k1_with_false_ret(const string &xpub, const string &path, const string &child_xpub){
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPublicKey(xpub, CurveType::SECP256K1);
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    BN delta;
    HDKey child_hd_key;
    ok = root_hd_key.PublicCKDPath(child_hd_key, path.c_str(), delta);
    ASSERT_TRUE(ok);
    string t_child_xpub;
    child_hd_key.ToExtendedPublicKey(t_child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(t_child_xpub, child_xpub);

    const Curve *curv = GetCurveParam(CurveType::SECP256K1);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Secp256k1_with_false_ret)
{
    for(size_t i = 0; i < case_data_root_xpub_secp256k1.size(); i++ ){
        for(size_t j = 0; j < case_data_public_ckd_child_key_secp256k1[i].size(); j++){
            const string & xpub = case_data_root_xpub_secp256k1[i];
            const string & path = case_data_public_ckd_child_key_secp256k1[i][j][0];
            const string & child_xpub = case_data_public_ckd_child_key_secp256k1[i][j][1];
            testPublicCKD_Secp256k1_with_false_ret(xpub, path, child_xpub);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
