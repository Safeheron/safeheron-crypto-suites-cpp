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
#include "crypto-suites/crypto-hash/hmac_sha512.h"
using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

std::vector<std::vector<string>> case_data_serialize_hdkey_secp256k1 = {
        {
                "xprvA1CnPMjbTkNNtEVrTvG8SHrLPp7tc6xXDkpY59NGSy6fyHmLzTrFdcHWq5cqsiwK758pGuBaX9XJY1kR6PacgG3sJbAmcQCsarTgh8EJvY2",
                "xpub6EC8nsGVJ7vg6iaKZwo8oRo4wqxP1ZgNayk8sXmt1Jder66VY1AWBQbzgKz2X9fhvyJDtAZ425KwFm9bKLYD9cUUjddMevsRD2Qdrnk9a1m"
        },
        {
                "xprv9yUAqePdq9JYrAnxHWns8ooPknGjWSLkCYtKNB1EEqFKoqrX4DV91bP7YAefJzQU8CRHpsioXdVTMGHu8BhmGhPYSnXRoe8Sy31aoQGnQco",
                "xpub6CTXF9vXfWrr4esRPYKsVwk8Jp7Duu4bZmovAZQqoAnJgeBfbkoPZPhbPTvgcm2HRM7TmyYuLKS6MNh4eHvGV2nZAjtYXg7hbNWz2vZ7rMv"
        }
};

void testSerializeHDKey_Secp256k1(const std::string &xprv, const std::string &xpub){
    safeheron::bip32::HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::SECP256K1));

    std::string t_xpriv;
    hdKey.ToExtendedPrivateKey(t_xpriv);
    //std::cout << "t_xpriv:        " << t_xpriv << std::endl;
    //std::cout << "xprv: " << xprv << std::endl;
    std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(t_xpriv)) << std::endl;
    std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    EXPECT_TRUE(t_xpriv == xprv);

    safeheron::bip32::HDKey hdKey2;
    EXPECT_TRUE(hdKey2.FromExtendedPublicKey(xpub, CurveType::SECP256K1));
    std::string t_xpub;
    hdKey2.ToExtendedPublicKey(t_xpub);
    //std::cout << "t_xpub:        " << t_xpub << std::endl;
    //std::cout << "xpub: " << xpub << std::endl;
    EXPECT_TRUE(t_xpub == xpub);
}
const static std::vector<std::vector<std::string>> test_vector {
        {
                "000102030405060708090a0b0c0d0e0f",
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        },
        {
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        },
        {
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "m/0'",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        },
        {
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m/0'",
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
                "m/0'/1'",
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
        }
};

void test_Serialize(const std::string &xprv, const std::string &xpub, const std::string &seed, const std::string &path) {
    HDKey hd_root;
    std::string seed_bytes = hex::DecodeFromHex(seed);
    hd_root.FromSeed(CurveType::SECP256K1, (uint8_t*)seed_bytes.c_str(), seed_bytes.length());

    HDKey child_key = hd_root.PrivateCKDPath(path);
    BN priv;
    CurvePoint pub;
    uint8_t chaincode[32];

    child_key.GetPrivateKey(priv);
    child_key.GetPublicKey(pub);
    child_key.GetChainCode(chaincode);

    HDKey xprv_key;
    HDKey xpub_key;
    xprv_key.FromExtendedPrivateKey(xprv, CurveType::SECP256K1);
    xpub_key.FromExtendedPublicKey(xpub, CurveType::SECP256K1);

    BN priv_gen;
    CurvePoint pub_gen_1, pub_gen_2;
    uint8_t chaincode_gen_1[32], chaincode_gen_2[32];
    xprv_key.GetPrivateKey(priv_gen);
    xprv_key.GetPublicKey(pub_gen_1);
    xprv_key.GetChainCode(chaincode_gen_1);
    xpub_key.GetPublicKey(pub_gen_2);
    xpub_key.GetChainCode(chaincode_gen_2);
    EXPECT_TRUE(priv_gen == priv);
    EXPECT_TRUE(pub_gen_1 == pub);
    EXPECT_TRUE(pub_gen_2 == pub);
    EXPECT_TRUE(strncmp((char *)chaincode, (char *)chaincode_gen_1, 32) == 0);
    EXPECT_TRUE(strncmp((char *)chaincode, (char *)chaincode_gen_2, 32) == 0);
    std::string xprv_gen, xpub_gen, xpub_gen1;
    xprv_key.ToExtendedPrivateKey(xprv_gen);
    EXPECT_TRUE(xprv_gen == xprv);
    xprv_key.ToExtendedPublicKey(xpub_gen1);
    xpub_key.ToExtendedPublicKey(xpub_gen);
    EXPECT_TRUE(xpub == xpub_gen);
    EXPECT_TRUE(xpub == xpub_gen1);
}
TEST(bip32, Serialize) {
    for(size_t i = 0; i < test_vector.size(); ++i) {
        const std::string seed = test_vector[i][0];
        size_t j = 1;
        std::string path;
        std::string child_xprv;
        std::string child_xpub;
        while (j < test_vector[i].size()) {
            path = test_vector[i][j];
            j++;
            child_xprv = test_vector[i][j];
            j++;
            child_xpub = test_vector[i][j];
            j++;
            test_Serialize(child_xprv, child_xpub, seed, path);
        }
    }
}
TEST(Bip32, SerializeHDKey_Secp256k1)
{
    for(const auto &hd_key_pair: case_data_serialize_hdkey_secp256k1){
        const string &xprv = hd_key_pair[0];
        const string &xpub = hd_key_pair[1];
        testSerializeHDKey_Secp256k1(xprv, xpub);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
