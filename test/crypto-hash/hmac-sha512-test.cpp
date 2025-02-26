#include "gtest/gtest.h"
#include "crypto-hash/hmac_sha512.h"
#include "util-test.h"

using safeheron::hash::CHMAC_SHA512;

typedef struct {
    std::string key;
    std::string data;
    std::string result;
} test_case_t;

std::vector<test_case_t> test_case_for_hmac_sha512 = {
        /* Test for empty message, The expected value is from sodium and crypto-js */
        {
                "",
                "",
                "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
        },
        /* "Test Case 1" from RFC 4231 */
        /* RFC 4231: https://datatracker.ietf.org/doc/html/draft-nystrom-smime-hmac-sha-02 */
        {
                std::string(20, '\x0b'),
                "Hi There",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        },
        /* "Test Case 2" from RFC 4231 */
        {
                "Jefe",
                "what do ya want for nothing?",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        },
        /* "Test Case 6" from RFC 4231 */
        {
                std::string(131, '\xaa'),
                "Test Using Larger Than Block-Size Key - Hash Key First",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        },
        /* "Test Case 7" from RFC 4231 */
        {
                std::string(131, '\xaa'),
                "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        }
};

void run_case(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, const char * expected_digest_hex){
    uint8_t digest[CHMAC_SHA512::OUTPUT_SIZE];

    CHMAC_SHA512 hmac_sha512(key, key_len);
    hmac_sha512.Write(data, data_len);
    hmac_sha512.Finalize(digest);

    std::string digest_hex = bytes2hex(digest, CHMAC_SHA512::OUTPUT_SIZE);

    EXPECT_TRUE(strcmp(expected_digest_hex, digest_hex.c_str()) == 0);
}

TEST(HASH, SHA256)
{
    for(const auto& test_case : test_case_for_hmac_sha512) {
        const uint8_t* key = reinterpret_cast<const uint8_t *>(test_case.key.c_str());
        size_t key_len = test_case.key.length();
        const uint8_t* data = reinterpret_cast<const uint8_t *>(test_case.data.c_str());
        size_t data_len = test_case.data.length();
        const char* expected_digest_hex = test_case.result.c_str();
        run_case(key, key_len, data, data_len, expected_digest_hex);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

    return ret;
}
