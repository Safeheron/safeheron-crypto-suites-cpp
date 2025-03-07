#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "crypto-curve/curve.h"
#include <random>

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

struct TestData {
    int index;
    std::string secret_key;
    std::string public_key;
    std::string aux_rand;
    std::string message;
    std::string signature;
    bool verification_result;
    std::string comment;
};

// BIP340 Test data from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
TestData testCase_BIP340[19] = {
        {0, "0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", true, ""},
        {1, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "0000000000000000000000000000000000000000000000000000000000000001", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", true, ""},
        {2, "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", true, ""},
        {3, "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", true, "test fails if msg is reduced modulo p or n"},
        {4, "", "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true, ""},
        {5, "", "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "public key not on the curve"},
        {6, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false, "has_even_y(R) is false"},
        {7, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false, "negated message"},
        {8, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false, "negated s value"},
        {9, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false, "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0"},
        {10, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false, "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1"},
        {11, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "sig[0:32] is not an X coordinate on the curve"},
        {12, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "sig[0:32] is equal to field size"},
        {13, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false, "sig[32:64] is equal to curve order"},
        {14, "", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "public key is not a valid X coordinate because it exceeds the field size"},
        {15, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", true, "message of size 0 (added 2022-12)"},
        {16, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", true, "message of size 1 (added 2022-12)"},
        {17, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", true, "message of size 17 (added 2022-12)"},
        {18, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", true, "message of size 100 (added 2022-12)"}
};

int test_random_sign(CurveType type, int times)
{
    int count = 0;
    const Curve *curv = GetCurveParam(type);

    std::random_device rd;
    std::mt19937 gen(rd());
    int lower_bound = 10;
    int upper_bound = 1000;
    std::uniform_int_distribution<> dis(lower_bound, upper_bound); // 生成 lower_bound 到 upper_bound 之间的整数

    do {
        int message_len = dis(gen);
        BN privkey = safeheron::rand::RandomBNLt(curv->n);

        CurvePoint pubkey = curv->g * privkey;

        char *message = new char[message_len];
        safeheron::rand::RandomBytes(reinterpret_cast<unsigned char *>(message), message_len);

        try {
           std::string sig = safeheron::curve::schnorr::Sign(type, privkey, (const uint8_t *)message, message_len, "aux",
                                                             safeheron::curve::schnorr::SchnorrPattern::BIP340);

           bool pass = safeheron::curve::schnorr::Verify(type, pubkey, (const uint8_t*)sig.c_str(), (const uint8_t *)message, message_len,
                                                         safeheron::curve::schnorr::SchnorrPattern::BIP340);
           EXPECT_TRUE(pass == true);
        }catch (const std::exception &e){
            printf("%s", e.what());
        }
        delete[] message;
    }while (++count < times);
    return 0;
}

TEST(SECP256K1, test_random_sign)
{
    printf("/*******************SECP256K1 Random Sign/Verify Begin (BIP340) *********************/\n");
    test_random_sign(CurveType::SECP256K1,  100);
    printf("/*******************SECP256K1 Random Sign/Verify End (BIP340) *********************/\n");
    printf("\n\n");
}

void sign_and_verify_once(int i){
    std::string secret_key_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].secret_key);
    std::string public_key_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].public_key);
    std::string aux_rand_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].aux_rand);
    std::string message_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].message);
    std::string signature_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].signature);

    // public_key = lift(x)
    CurvePoint public_key(CurveType::SECP256K1);
    BN x = BN::FromBytesBE(public_key_bytes);
    bool flag = false;
    // Implicitly choosing the Y coordinate that is even[6].
    if(public_key.PointFromX(x, false, CurveType::SECP256K1)){
        flag = true;
    }
    if(!flag){
        printf("Failed: invalid public key: %s \n", testCase_BIP340[i].public_key.c_str());
        return;
    }

    // secret key
    BN secret_key = BN::FromBytesBE(secret_key_bytes);

    // sig
    std::string sig = safeheron::curve::schnorr::Sign(CurveType::SECP256K1, secret_key, (uint8_t *)message_bytes.c_str(), message_bytes.length(), aux_rand_bytes,
                                                      safeheron::curve::schnorr::SchnorrPattern::BIP340);

    bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, public_key, (const uint8_t*)signature_bytes.c_str(), (const uint8_t*)message_bytes.c_str(), message_bytes.length(),
                                                  safeheron::curve::schnorr::SchnorrPattern::BIP340);
    EXPECT_TRUE(pass);
    EXPECT_TRUE(strcasecmp(safeheron::encode::hex::EncodeToHex(sig).c_str(), testCase_BIP340[i].signature.c_str()) == 0);
}

TEST(SECP256K1, sign_and_verify_once)
{
    printf("/*******************SECP256K1 Sign/Verify (BIP340 Official test cases) begin *********************/\n");
    sign_and_verify_once(0);
    sign_and_verify_once(1);
    sign_and_verify_once(2);
    sign_and_verify_once(3);
    sign_and_verify_once(15);
    sign_and_verify_once(16);
    sign_and_verify_once(17);
    sign_and_verify_once(18);
    printf("/*******************SECP256K1 Sign/Verify (BIP340 Official test cases) end *********************/\n");
    printf("\n\n");
}

void verify_once(int i){
    std::string public_key_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].public_key);
    std::string message_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].message);
    std::string signature_bytes = safeheron::encode::hex::DecodeFromHex(testCase_BIP340[i].signature);

    // public_key = lift(x)
    CurvePoint public_key(CurveType::SECP256K1);
    BN x = BN::FromBytesBE(public_key_bytes);
    bool flag = false;
    // Implicitly choosing the Y coordinate that is even[6].
    if(public_key.PointFromX(x, false, CurveType::SECP256K1)){
        flag = true;
    }
    if(!flag){
        printf("Failed: invalid public key: %s \n", testCase_BIP340[i].public_key.c_str());
        return;
    }

    bool pass = safeheron::curve::schnorr::Verify(CurveType::SECP256K1, public_key, (const uint8_t*)signature_bytes.c_str(), (const uint8_t*)message_bytes.c_str(), message_bytes.length(),safeheron::curve::schnorr::SchnorrPattern::BIP340);
    EXPECT_TRUE(pass == testCase_BIP340[i].verification_result);
}

TEST(SECP256K1, verify_once)
{
    printf("/*******************SECP256K1 Verify (BIP340 Official test cases) begin *********************/\n");
    verify_once(4);
    verify_once(5);
    verify_once(6);
    verify_once(7);
    verify_once(8);
    verify_once(9);
    verify_once(10);
    verify_once(11);
    verify_once(12);
    verify_once(13);
    verify_once(14);
    printf("/*******************SECP256K1 Verify (BIP340 Official test cases) end *********************/\n");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
