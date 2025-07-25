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

std::vector<string> case_data_root_xprv_secp256k1 = {"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"};
std::vector<std::vector<std::vector<std::string>>> case_data_private_ckd_child_key_secp256k1 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m/0'",
                        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
                },
                {
                        "m/0'/1",
                        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
                },
                {
                        "m/0'/1/2'",
                        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
                },
                {
                        "m/0'/1/2'/2",
                        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
                },
                {
                        "m/0'/1/2'/2/1000000000",
                        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
                },
        },
};
void testprivateCKD_Secp256k1(const string &xprv, const string &path, const string &child_xprv) {
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPrivateKey(xprv, CurveType::SECP256K1);
    ASSERT_TRUE(ok);
    std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string t_child_xprv;
    child_hd_key.ToExtendedPrivateKey(t_child_xprv);
    std::cout << "child_xprv: " << child_xprv << std::endl;
    ASSERT_EQ(t_child_xprv, child_xprv);
}

TEST(Bip32, PrivateCKDTestCase_Secp256k1) {
    for (size_t i = 0; i < case_data_root_xprv_secp256k1.size(); i++) {
        for (size_t j = 0; j < case_data_private_ckd_child_key_secp256k1[i].size(); j++) {
            const string &xprv = case_data_root_xprv_secp256k1[i];
            const string &path = case_data_private_ckd_child_key_secp256k1[i][j][0];
            const string &child_xprv = case_data_private_ckd_child_key_secp256k1[i][j][1];
            testprivateCKD_Secp256k1(xprv, path, child_xprv);
        }
    }
}


const static std::vector<std::vector<std::string>> test_vector {
        {
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
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
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
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
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
            "m/0'",
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        },
        {
            "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
            "m/0'",
            "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
            "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            "m/0'/1'",
            "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
            "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
        }
};
void test_PrivCKD(const std::string &root_xprv, const std::string &path, const std::string &child_xprv, const std::string &child_xpub) {
    HDKey hd_root;
    hd_root.FromExtendedPrivateKey(root_xprv, CurveType::SECP256K1);
    HDKey child_key = hd_root.PrivateCKDPath(path);
    std::string child_xprv_gen;
    std::string child_xpub_gen;
    child_key.ToExtendedPrivateKey(child_xprv_gen);
    child_key.ToExtendedPublicKey(child_xpub_gen);
    EXPECT_TRUE(child_xpub == child_xpub_gen);
    EXPECT_TRUE(child_xprv == child_xprv_gen);
}
TEST(Bip32, PrivCKD) {
    for(size_t i = 0; i < test_vector.size(); ++i) {
        const std::string root_xprv = test_vector[i][0];
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
            test_PrivCKD(root_xprv, path, child_xprv, child_xpub);
        }
    }
}

void test_PrivCKD_with_false_ret(const std::string &root_xprv, const std::string &path, const std::string &child_xprv, const std::string &child_xpub) {
    HDKey hd_root;
    hd_root.FromExtendedPrivateKey(root_xprv, CurveType::SECP256K1);
    HDKey child_key;
    bool ok = hd_root.PrivateCKDPath(child_key, path);
    EXPECT_TRUE(ok);
    //HDKey child_key = hd_root.PrivateCKDPath(path);
    std::string child_xprv_gen;
    std::string child_xpub_gen;
    child_key.ToExtendedPrivateKey(child_xprv_gen);
    child_key.ToExtendedPublicKey(child_xpub_gen);
    EXPECT_TRUE(child_xpub == child_xpub_gen);
    EXPECT_TRUE(child_xprv == child_xprv_gen);
}

TEST(Bip32, PrivCKD_with_false_ret) {
    for(size_t i = 0; i < test_vector.size(); ++i) {
        const std::string root_xprv = test_vector[i][0];
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
            test_PrivCKD_with_false_ret(root_xprv, path, child_xprv, child_xpub);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
