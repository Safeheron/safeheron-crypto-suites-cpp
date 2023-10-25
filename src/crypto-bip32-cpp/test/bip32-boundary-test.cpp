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
using safeheron::bignum::BN;
using namespace safeheron::encode;
TEST(bip32, IllegalPath) {
    std::string item = "12345678";
    std::string replacement = "////";
    item = replacement.substr(0, replacement.find('/'));
    EXPECT_TRUE(item == "");
    std::cout << "item: " << item << std::endl;
    if (item.find_first_not_of("0123456789") != std::string::npos) {
        std::cout << "In if" << std::endl;
    }
    if (item.compare("m")!= 0 || item.compare("M") != 0)
    {
        std::cout << "In compare if" << std::endl;
    }
    char *ptr = nullptr;
    uint32_t number = strtoul(item.c_str(), &ptr, 10);
    std::cout << "number: " << number << std::endl;
}

TEST(bip32, InvalidPath) {
    std::string seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    std::string seedBytes = safeheron::encode::hex::DecodeFromHex(seed);
    HDKey hd_root;
    hd_root.FromSeed(safeheron::curve::CurveType::SECP256K1, (uint8_t *)seed.c_str(), seedBytes.length());
    std::string hd_root_xprv;
    hd_root.ToExtendedPrivateKey(hd_root_xprv);
    std::cout << "hdKey xprv: " << hd_root_xprv << std::endl;

    std::string illegal_path1 = "////";
    std::string illegal_path2 = " / / / / ";
    std::string illegal_path3 = "223 / 336 / mqr";

    HDKey hdchild1 = hd_root.PrivateCKDPath(illegal_path1);
    HDKey hdchild2 = hd_root.PrivateCKDPath(illegal_path2);
    HDKey hdchild3 = hd_root.PrivateCKDPath(illegal_path3);
    std::string hdchild1_xprv;
    hdchild1.ToExtendedPrivateKey(hdchild1_xprv);
    std::cout << "hdchild1 xprv: " << hdchild1_xprv << std::endl;

    std::string hdchild2_xprv;
    hdchild2.ToExtendedPrivateKey(hdchild2_xprv);
    std::cout << "hdchild2 xprv: " << hdchild2_xprv << std::endl;

    std::string hdchild3_xprv;
    hdchild3.ToExtendedPrivateKey(hdchild3_xprv);
    std::cout << "hdchild3 xprv: " << hdchild3_xprv << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
