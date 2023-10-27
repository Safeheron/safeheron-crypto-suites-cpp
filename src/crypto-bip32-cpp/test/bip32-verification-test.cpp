#include <google/protobuf/stubs/common.h>
#include <fstream>
#include <vector>
#include "gtest/gtest.h"
#include "crypto-bip32/bip32.h"
#include "crypto-curve/curve.h"
#include "crypto-encode/hex.h"
using safeheron::bip32::HDKey;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using namespace safeheron::encode;

void validate_priv_derivation(const std::string &file_path) {
    std::ifstream infile;
    infile.open(file_path);
    std::string seed_hex;
    getline(infile, seed_hex);
    std::cout << "seed_hex: " << seed_hex << std::endl;

    HDKey hd_root;
    std::string seed_bytes = hex::DecodeFromHex(seed_hex);
    hd_root.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());
    std::string root_xprv;
    std::string root_xpub;
    hd_root.ToExtendedPrivateKey(root_xprv);
    hd_root.ToExtendedPublicKey(root_xpub);
    std::string expected_root_xprv;
    std::string expected_root_xpub;
    std::string m;
    getline(infile, m);
    std::cout << "root_path: " << m <<std::endl;
    getline(infile, expected_root_xprv);
    getline(infile, expected_root_xpub);
    EXPECT_TRUE(root_xprv == expected_root_xprv);
    EXPECT_TRUE(root_xpub == expected_root_xpub);
    std::cout << "root_xprv: " << root_xprv << std::endl;
    std::cout << "root_xpub: " << root_xpub << std::endl;

    std::string child_path;
    while (getline(infile, child_path)) {
        HDKey child = hd_root.PrivateCKDPath(child_path);
        std::string child_xprv;
        std::string child_xpub;
        child.ToExtendedPrivateKey(child_xprv);
        child.ToExtendedPublicKey(child_xpub);
        std::string child_xprv_expected;
        std::string child_xpub_expected;
        getline(infile, child_xprv_expected);
        getline(infile, child_xpub_expected);
        EXPECT_TRUE(child_xprv == child_xprv_expected);
        EXPECT_TRUE(child_xpub == child_xpub_expected);
//        std::cout << "child_xprv: " << child_xprv << std::endl;
//        std::cout << "child_xpub: " << child_xpub << std::endl;
    }
    infile.close();
}

void validate_pub_derivation(const std::string &file_path) {
    std::ifstream infile;
    infile.open(file_path);
    std::string seed_hex;
    getline(infile, seed_hex);
    std::cout << "seed_hex: " << seed_hex << std::endl;

    HDKey hd_root;
    std::string seed_bytes = hex::DecodeFromHex(seed_hex);
    hd_root.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());
    std::string root_xpub;
    hd_root.ToExtendedPublicKey(root_xpub);
    std::string expected_root_xpub;
    std::string m;
    getline(infile, m);
    std::cout << "root_path: " << m <<std::endl;
    getline(infile, expected_root_xpub);
    EXPECT_TRUE(root_xpub == expected_root_xpub);
    std::cout << "root_xpub: " << root_xpub << std::endl;
    std::string child_path;
    while (getline(infile, child_path)) {
        HDKey child = hd_root.PublicCKDPath(child_path);
        std::string child_xpub;
        child.ToExtendedPublicKey(child_xpub);
        std::string child_xpub_expected;
        getline(infile, child_xpub_expected);
        EXPECT_TRUE(child_xpub == child_xpub_expected);
        //    std::cout << "child_xpub: " << child_xpub << std::endl;
    }
    infile.close();
}

//copy priv_derivation_js.txt to runtime directory
TEST(bip32, validate_js_priv) {
    validate_priv_derivation("./priv_derivation_js.txt");
}

//copy pub_derivation_js.txt to runtime directory
TEST(bip32, validate_js_pub) {
    validate_pub_derivation("./pub_derivation_js.txt");
}

//copy priv_derivation_java.txt to runtime directory
TEST(bip32, validate_java_priv) {
    validate_priv_derivation("./priv_derivation_java.txt");
}

//copy pub_derivation_java.txt to runtime directory
TEST(bip32, validate_java_pub) {
    validate_pub_derivation("./pub_derivation_java.txt");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
