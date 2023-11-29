#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-bn/bn.h"
#include "exception/located_exception.h"
#include "crypto-curve/curve.h"
#include "crypto-bip32/hd_path.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/base58.h"
#include "crypto-encode/base64.h"

using std::string;
using safeheron::bip32::HDPath;

void test_case(std::string keypath_str, std::vector<uint32_t> keypath){
    std::string t_keypath_str;
    std::vector<uint32_t> t_keypath;
    HDPath::ParseHDPath(keypath_str, t_keypath);
    t_keypath_str = HDPath::WriteHDPath(keypath);
    std::cout << t_keypath_str <<std::endl;
    EXPECT_TRUE(t_keypath_str == keypath_str);
    EXPECT_TRUE(t_keypath.size() == keypath.size());
    if(t_keypath.size() == keypath.size()){
        for(size_t i = 0; i < keypath.size(); i++){
            EXPECT_TRUE(t_keypath[i] == keypath[i]);
        }
    }
}

std::vector<std::string> keypath_str_arr = {
        "m/7/0'/2000",
        "m/2034'/2'/2000",
        "m/20/2/2000'",
        "m/20'/2'/2000'",
};

std::vector<std::vector<uint32_t>> keypath_arr = {
        {7, 0x80000000, 2000},
        {2034 + 0x80000000, 2 + 0x80000000, 2000},
        {20, 2, 2000 + 0x80000000},
        {20 + 0x80000000, 2 + 0x80000000, 2000 + 0x80000000},
};

TEST(Bip32, HDPath)
{
    for (int i = 0; i < 4; ++i) {
        test_case(keypath_str_arr[i], keypath_arr[i]);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
