#include <google/protobuf/stubs/common.h>
#include <fstream>
#include <vector>
#include "gtest/gtest.h"
#include "crypto-bip32/bip32.h"
#include "crypto-curve/curve.h"
#include "crypto-encode/hex.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
using safeheron::bip32::HDKey;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using namespace safeheron::encode;

TEST(bip32, generate_data_priv_sep) {
    std::ofstream outfile;
    outfile.open("./priv_derivation.txt");

    safeheron::bignum::BN seed = safeheron::rand::RandomBNStrict(256);
    std::string seed_str = seed.Inspect();
    std::cout << "seed_str: " << seed_str << std::endl;
    std::string seed_bytes = hex::DecodeFromHex(seed_str);

    outfile << seed_str << std::endl;

    HDKey hd_root;
    hd_root.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());

    outfile << "m" << std::endl;

    std::string root_xprv;
    bool encoded = hd_root.ToExtendedPrivateKey(root_xprv);
    EXPECT_TRUE(encoded);
    std::cout << "root_xprv: " << root_xprv << std::endl;
    outfile << root_xprv << std::endl;

    std::string root_xpub;
    encoded = hd_root.ToExtendedPublicKey(root_xpub);
    EXPECT_TRUE(encoded);
    std::cout << "root_xpub: " << root_xpub << std::endl;
    outfile << root_xpub << std::endl;

    std::vector<std::vector<std::string>> path;
    path.resize(5);

    safeheron::bignum::BN max("80000000", 16);

    for (int i = 0; i < 1000; ++i) {
        safeheron::bignum::BN r = safeheron::rand::RandomBNLt(max);
        std::string path_str = "m/" + r.Inspect(10);
        safeheron::bignum::BN hardened = safeheron::rand::RandomBN(32);
        if (hardened >= max) {
            path_str += '\'';
        }
    //    std::cout << "path_str: " << path_str << std::endl;
        outfile << path_str << std::endl;

        HDKey child = hd_root.PrivateCKDPath(path_str);

        std::string child_xprv;
        encoded = child.ToExtendedPrivateKey(child_xprv);
        EXPECT_TRUE(encoded);
        //std::cout << "child_xprv: " << child_xprv << std::endl;
        outfile << child_xprv << std::endl;

        std::string child_xpub;
        encoded = child.ToExtendedPublicKey(child_xpub);
        EXPECT_TRUE(encoded);
      //  std::cout << "child_xpub: " << child_xpub << std::endl;
        outfile << child_xpub << std::endl;

        path[0].push_back(path_str);
    }
    for (int j = 1; j < 5; j++) {
        for (int i = 0; i < 1000; ++i) {
            safeheron::bignum::BN r = safeheron::rand::RandomBNLt(max);
            std::string path_str = path[j - 1][i] + '/' + r.Inspect(10);
            safeheron::bignum::BN hardened = safeheron::rand::RandomBN(32);
            if (hardened >= max) {
                path_str += '\'';
            }
        //    std::cout << "path_str: " << path_str << std::endl;
            outfile << path_str << std::endl;

            HDKey child = hd_root.PrivateCKDPath(path_str);

            std::string child_xprv;
            encoded = child.ToExtendedPrivateKey(child_xprv);
            EXPECT_TRUE(encoded);
            //std::cout << "child_xprv: " << child_xprv << std::endl;
            outfile << child_xprv << std::endl;

            std::string child_xpub;
            encoded = child.ToExtendedPublicKey(child_xpub);
            EXPECT_TRUE(encoded);
          //  std::cout << "child_xpub: " << child_xpub << std::endl;
            outfile << child_xpub << std::endl;

            path[j].push_back(path_str);
        }
    }
    outfile.close();
}

TEST(bip32, generate_data_pub_sep) {
    std::ofstream outfile;
    outfile.open("./pub_derivation.txt");

    safeheron::bignum::BN seed = safeheron::rand::RandomBNStrict(256);
    std::string seed_str = seed.Inspect();
    std::cout << "seed_str: " << seed_str << std::endl;
    std::string seed_bytes = hex::DecodeFromHex(seed_str);

    outfile << seed_str << std::endl;
    HDKey hd_root;
    hd_root.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());
    outfile << "m" << std::endl;

    std::string root_xpub;
    bool encoded = hd_root.ToExtendedPublicKey(root_xpub);
    EXPECT_TRUE(encoded);
    std::cout << "root_xpub: " << root_xpub << std::endl;
    outfile << root_xpub << std::endl;
    std::vector<std::vector<std::string>> path;
    path.resize(5);

    safeheron::bignum::BN max("80000000", 16);
    for (int i = 0; i < 1000; ++i) {
        safeheron::bignum::BN r = safeheron::rand::RandomBNLt(max);
        std::string path_str = "m/" + r.Inspect(10);

    //    std::cout << "path_str: " << path_str << std::endl;
        outfile << path_str << std::endl;
        HDKey child = hd_root.PublicCKDPath(path_str);

        std::string child_xpub;
        encoded = child.ToExtendedPublicKey(child_xpub);
        EXPECT_TRUE(encoded);
    //    std::cout << "child_xpub: " << child_xpub << std::endl;
        outfile << child_xpub << std::endl;
        path[0].push_back(path_str);

    }
    for (int j = 1; j < 5; j++) {
        for (int i = 0; i < 1000; ++i) {
            safeheron::bignum::BN r = safeheron::rand::RandomBNLt(max);
            std::string path_str = path[j - 1][i] + '/' + r.Inspect(10);

        //    std::cout << "path_str: " << path_str << std::endl;
            outfile << path_str << std::endl;
            HDKey child = hd_root.PublicCKDPath(path_str);

            std::string child_xpub;
            encoded = child.ToExtendedPublicKey(child_xpub);
            EXPECT_TRUE(encoded);
        //    std::cout << "child_xpub: " << child_xpub << std::endl;
            outfile << child_xpub << std::endl;
            path[j].push_back(path_str);
        }
    }
    outfile.close();
}


TEST(bip32, validate_self_priv) {
    std::ifstream infile;
    infile.open("./priv_derivation.txt");
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


TEST(bip32, validate_self_pub) {
    std::ifstream infile;
    infile.open("./pub_derivation.txt");
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
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}

