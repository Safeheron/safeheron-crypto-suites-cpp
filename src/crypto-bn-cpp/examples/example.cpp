//
// Created by 何剑虹 on 2020/10/22.
//
#include "gtest/gtest.h"
#include <crypto-bn/bn.h>
#include <crypto-bn/rand.h>

using safeheron::bignum::BN;

TEST(BN, Constructor)
{
    BN n0;
    BN n1(0);
    BN n2("0", 10);
    BN n3("0", 16);
    EXPECT_TRUE(n0 == BN::ZERO);
    EXPECT_TRUE(n1 == BN::ZERO);
    EXPECT_TRUE(n2 == BN::ZERO);
    EXPECT_TRUE(n3 == BN::ZERO);

    BN n4("111", 16);
    EXPECT_TRUE(n4 == 0x111);
    std::string str;
    n4.ToHexStr(str);
    std::cout << str << std::endl;
    BN n5("1234", 10);
    BN n5_neg("-1234", 10);
    EXPECT_TRUE(n5.Neg() == n5_neg);
    BN n6(10);
    BN n7(-20);
    EXPECT_TRUE(n6.Neg() == -10);
    EXPECT_TRUE(n7.Neg() == 20);
}

TEST(BN, Const)
{
    BN n0(0);
    BN n1("1", 10);
    BN n2("2", 10);
    BN n3("3", 10);
    BN n4("4", 10);
    BN n5("5", 10);
    EXPECT_TRUE( BN::ZERO == n0);
    EXPECT_TRUE( BN::ONE == n1);
    EXPECT_TRUE( BN::TWO == n2);
    EXPECT_TRUE( BN::THREE == n3);
    EXPECT_TRUE( BN::FOUR == n4);
    EXPECT_TRUE( BN::FIVE == n5);
    BN n6("-50", 10);
    BN n7 = n6 / -10;
    std::string s;
    n7.ToHexStr(s);
    std::cout<< s << std::endl;
}


TEST(BN, Add) {
    BN n1(100);
    BN n2("ffff", 16);
    BN n3("1234", 10);
    BN n4;
    std::string s4;
    for(int i = 0; i < 5; i ++){
        n4 = n1 + n2 + n3;
    }
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("66869") == 0);

    n4 += n1;
    n4 += n2;
    n4 += n3;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("133738") == 0);

    n4 = n4 + 5;
    n4 += 5;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("133748") == 0);
}

TEST(BN, Sub) {
    BN n1(100);
    BN n2("ffff", 16);
    BN n3("1234", 10);
    BN n4;
    std::string s4;
    for(int i = 0; i < 5; i ++){
        n4 = n1 - n2 - n3;
    }
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("-66669") == 0);

    n4 -= n1;
    n4 -= n2;
    n4 -= n3;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("-133538") == 0);

    n4 = n4 - 5;
    n4 -= 5;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("-133548") == 0);
}


TEST(BN, Mul) {
    BN n1(100);
    BN n2("ffff", 16);
    BN n3("1234", 10);
    BN n4;
    std::string s4;
    for(int i = 0; i < 5; i ++){
        n4 = n1 * n2 * n3;
    }
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("8087019000") == 0);

    n4 *= n1;
    n4 *= n2;
    n4 *= n3;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("65399876306361000000") == 0);

    n4 = n4 * 5;
    n4 *= 2;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("653998763063610000000") == 0);
}

TEST(BN, Div) {
    BN n1(100);
    BN n2("ffff", 16);
    BN n3("1234", 10);
    BN n4("65399876306361000101", 10);
    std::string s4;
    n4 = n4 / n1;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("653998763063610001") == 0);

    n4 /= n1;
    n4 /= n2;
    n4 /= n3;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("80870190") == 0);

    n4 = n4 / 5;
    n4 /= 2;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("8087019") == 0);

    n4 = n4 / 5;
    n4 /= 2;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("808701") == 0);
}

TEST(BN, Modular) {
    BN n1("65399876306361000101", 10);
    BN n2("5", 10);
    BN n3("10", 10);
    BN n4;
    std::string s4;
    n4 = n1 % n2;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("1") == 0);
    EXPECT_TRUE(n4 == 1);

    n4 = n1 % 5;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("1") == 0);
    EXPECT_TRUE(n4 == 1);

    n4 = n1 % n3;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("1") == 0);
    EXPECT_TRUE(n4 == 1);

    n4 = n1 % 10;
    n4.ToDecStr(s4);
    EXPECT_TRUE(s4.compare("1") == 0);
    EXPECT_TRUE(n4 == 1);
}

TEST(BN, NumberTheory) {
    BN n1(3);
    BN n2(2);
    BN m(7);
    EXPECT_EQ(n1.InvM(m), 5);
    EXPECT_EQ(n2.InvM(m), 4);

    n1 = BN(20);
    n2 = BN(30);
    EXPECT_EQ(n1.Gcd(n2), 10);
    EXPECT_EQ(n1.Lcm(n2), 60);

    //n2 = q*n1 + r
    BN q,r;
    n2.Div(n1, q, r);
    EXPECT_EQ(q, 1);
    EXPECT_EQ(r, 10);

    EXPECT_TRUE(BN(7).IsProbablyPrime());
    EXPECT_TRUE(BN(2147483647).IsProbablyPrime());

    BN n3 = BN::FromDecStr("3512361716805789371972727939883643101583447981968520328116222065795410830354167025485897169128481068329654077646734548662444384264600983851903304370332254379348431475618118443515097594013924630541082872673167087534602645691179668711694033983775097204256071148542458122815112287827804817008054571967569811098943958115474043611129903319499487179312753156982390604797594672110109279968116426946681439986817149082450603667765550663321273293047160509353032867927345920496246922999786486549211202276522272367449078522109089788557317028595008274191747489285773979775102541035592329871004023280977348435038643994502879226281");
    BN n4 = BN::FromDecStr("531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127");
    EXPECT_FALSE(n3.IsProbablyPrime());
    EXPECT_TRUE(n4.IsProbablyPrime());
}

TEST(BN, Shift) {
    BN n1("1011", 2);
    EXPECT_EQ(n1 << 4, 176);
    n1 <<= 4;
    EXPECT_EQ(n1, 176);

    EXPECT_EQ(n1 >> 5, 5);
    n1 >>= 5;
    EXPECT_EQ(n1, 5);
}


TEST(BN, Comparison) {
    BN n1("1234", 10);
    BN n2("1234", 10);
    BN n3("1235", 10);
    BN n4("1236", 10);
    BN n5("1237", 10);
    EXPECT_TRUE(n1 == n2);
    EXPECT_TRUE(n2 != n3);
    EXPECT_TRUE(n3 > n2);
    EXPECT_TRUE(n3 >= n2);
    EXPECT_TRUE(n2 < n3);
    EXPECT_TRUE(n2 <= n3);

    EXPECT_FALSE(n1 != n2);
    EXPECT_FALSE(n2 == n3);
    EXPECT_FALSE(n3 < n2);
    EXPECT_FALSE(n3 <= n2);
    EXPECT_FALSE(n2 > n3);
    EXPECT_FALSE(n2 >= n3);

    EXPECT_TRUE(n1 == 1234);
    EXPECT_TRUE(n1 != 0);
    EXPECT_TRUE(n1 > 1200);
    EXPECT_TRUE(n1 >= 1234);
    EXPECT_TRUE(n1 < 2000);
    EXPECT_TRUE(n1 <= 2000);

    n1 = BN("-1234", 10);
    EXPECT_TRUE(n1 == -1234);
    EXPECT_FALSE(n1 > 0);
    EXPECT_TRUE(n1 < 0);
    EXPECT_TRUE(n1 >= -2234);
    EXPECT_TRUE(n1 <= 1234);
}

TEST(BN, ToStringFromString) {
    BN n1 = BN::FromDecStr("24785187341154544549914104546227");
    BN n2 = BN::FromHexStr("FFFFFFFFFFFFFFFF");
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToHexStr(s2);

    EXPECT_TRUE(s1.compare("24785187341154544549914104546227") == 0);
    EXPECT_TRUE(s2.compare("FFFFFFFFFFFFFFFF") == 0);
}

TEST(BN, ToBytesFromBytes) {
    uint8_t ch[10];
    ch[0] = 0x01;
    ch[1] = 0x02;
    BN n1 = BN::FromBytesBE(ch, 2);
    BN n2 = BN::FromBytesLE(ch, 2);
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToDecStr(s2);

    EXPECT_TRUE(s1.compare("258") == 0);
    EXPECT_TRUE(s2.compare("513") == 0);

    std::string ns1, ns2;
    n1.ToBytesBE(ns1);
    n2.ToBytesBE(ns2);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
}

TEST(BN, Auxiliary) {
    BN n1 = BN::FromDecStr("1");
    EXPECT_EQ(n1.BitLength(), 1);
    EXPECT_EQ(n1.ByteLength(), 1);
    EXPECT_EQ(n1.IsZero(), false);
    EXPECT_EQ(n1.IsOdd(), true);
    EXPECT_EQ(n1.IsEven(), false);

    BN n2 = BN::FromDecStr("-258");
    EXPECT_EQ(n2.BitLength(), 9);
    EXPECT_EQ(n2.ByteLength(), 2);
    EXPECT_EQ(n2.IsZero(), false);
    EXPECT_EQ(n2.IsOdd(), false);
    EXPECT_EQ(n2.IsEven(), true);

    BN n3 = BN::FromDecStr("0");
    EXPECT_EQ(n3.BitLength(), 0);
    EXPECT_EQ(n3.ByteLength(), 0);
    EXPECT_EQ(n3.IsZero(), true);
    EXPECT_EQ(n3.IsOdd(), false);
    EXPECT_EQ(n3.IsEven(), true);

    // Be careful
    BN n4 = BN();
    EXPECT_EQ(n4.BitLength(), 0);
    EXPECT_EQ(n4.ByteLength(), 0);
    EXPECT_EQ(n4.IsZero(), true);
    EXPECT_EQ(n4.IsOdd(), false);
    EXPECT_EQ(n4.IsEven(), true);

    EXPECT_EQ(BN::Max(n1, n2), 1);
    EXPECT_EQ(BN::Max(n1, n2), n1);
    EXPECT_EQ(BN::Min(n1, n2), -258);
    EXPECT_EQ(BN::Min(n1, n2), n2);

    BN::Swap(n1, n2);
    EXPECT_EQ(n1, -258);
    EXPECT_EQ(n2, 1);

}

TEST(BN, ModPow)
{
    //BN n11 = BN::FromHexStr("3512361716805789371972727939883643101583447981968520328116222065795410830354167025485897169128481068329654077646734548662444384264600983851903304370332254379348431475618118443515097594013924630541082872673167087534602645691179668711694033983775097204256071148542458122815112287827804817008054571967569811098943958115474043611129903319499487179312753156982390604797594672110109279968116426946681439986817149082450603667765550663321273293047160509353032867927345920496246922999786486549211202276522272367449078522109089788557317028595008274191747489285773979775102541035592329871004023280977348435038643994502879226281");
    //BN pp1 = BN::FromDecStr("24785187341154544549914104546227324477849397927398564865898843147322410450159242714370313726215895344220422746105653910669926029449459443135240985638132813206618427011656415731288349869320099645008300932936995561385777390730121084071260567710340592802651082340376366434798431644732948435115566808067213452460824745589204954083798251054081876658612393182807087164285433664045394356387935544555343059651032295512441123006645668258731185928418616367925541996626300252413082259164698109375439746033443057802058077833685231311051193530557877051836264709759220533097861910127780566282488800845776390118872368439248528368887");
    //BN pp2 = BN::FromDecStr("24785187341154544549914104546227324477849397927398564865898843147322410450159242714370313726215895344220422746105653910669926029449459443135240985638132813206618427011656415731288349869320099645008300932936995561385777390730121084071260567710340592802651082340376366434798431644732948435115566808067213452460824745589204954083798251054081876658612393182807087164285433664045394356387935544555343059651032295512441123006645668258731185928418616367925541996626300252413082259164698109375439746033443057802058077833685231311051193530557877051836264709759220533097861910127780566282488800845776390118872368439248528368887");
    BN n11 = BN::FromHexStr("351");
    BN pp1 = BN::FromDecStr("247");
    BN pp2 = BN::FromDecStr("247");
    clock_t start, end;
    start = clock();
    BN ret;
    for(int j = 0; j < 5; j ++){
        ret = n11.PowM(pp1, pp2);
    }
    end = clock();
    std::cout << double(end - start)/CLOCKS_PER_SEC << std::endl;
}

TEST(BN, ToBytes32FromBytes32)
{
    uint8_t num1[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t num2[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t num3[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00};
    uint8_t num4[33] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21};
    BN n1 = BN::FromBytesBE(num1, 32);
    uint8_t buf32BE[32];
    uint8_t buf32LE[32];
    n1.ToBytes32BE(buf32BE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num1[i], buf32BE[i]);
    }

    BN n2 = BN::FromBytesBE(num2, 32);
    BN expected_n2 = BN::FromBytesBE(num2 + 1, 32 - 1);
    EXPECT_TRUE(n2 == expected_n2);
    n2.ToBytes32BE(buf32BE);
    n2.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num2[i], buf32BE[i]);
        EXPECT_EQ(num2[i], buf32LE[31 - i]);
    }

    BN n3 = BN::FromBytesLE(num3, 32);
    BN expected_n3 = BN::FromBytesLE(num3, 32 - 1);
    EXPECT_TRUE(n3 == expected_n3);
    n3.ToBytes32BE(buf32BE);
    n3.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num3[i], buf32LE[i]);
        EXPECT_EQ(num3[i], buf32BE[31 - i]);
    }

    BN n4 = BN::FromBytesBE(num4, 33);
    n4.ToBytes32BE(buf32BE);
    n4.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num4[i + 1], buf32BE[i]);
        EXPECT_EQ(num4[i + 1], buf32LE[31 - i]);
    }
}

TEST(BN, BitOperation)
{
    uint8_t num1[3] = {0x01, 0x02, 0x03};
    BN n1 = BN::FromBytesBE(num1, 3);
    EXPECT_TRUE(n1.IsBitSet(0));
    EXPECT_TRUE(n1.IsBitSet(1));
    EXPECT_TRUE(!n1.IsBitSet(2));
    EXPECT_TRUE(n1.IsBitSet(9));
    EXPECT_TRUE(n1.IsBitSet(16));
    EXPECT_TRUE(n1 == 0x010203);
    n1.SetBit(23);
    EXPECT_TRUE(n1 == 0x810203);
    n1.SetBit(7);
    EXPECT_TRUE(n1 == 0x810283);
    n1.ClearBit(9);
    EXPECT_TRUE(n1 == 0x810083);
}

bool isRootM(BN &a, BN &b, BN &m){
    return (a == b) || (a + b == m);
}

TEST(BN, SquareRootModuloP)
{
    //BN p0(5);
    //BN n0(0);
    //BN r0 = n0.SqrtM(p0);
    //EXPECT_TRUE(r0 == 0);

    //BN p1(5);
    //BN n1(2);
    //BN r1 = n1.SqrtM(p1);
    //EXPECT_TRUE(r1 == BN::MINUS_ONE);

    BN p2(5);
    BN n2(4);
    BN r2;
    r2 = n2.SqrtM(p2);
    std::cout << r2.Inspect() << std::endl;
    EXPECT_TRUE(r2 == 3);

    BN p3 = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    BN r3_0("ffffffff000000010000fffff0000000100000000000", 16);
    BN r3_1("ffffffff000000010000fffff0000000100000000001", 16);
    BN r3_2("ffffffff000000010000fffff0000000100000000002", 16);
    BN r3_3("ffffffff000000010000fffff0000000100000000003", 16);
    BN r3_4("ffffffff000000010000fffff0000000100000000004", 16);
    BN r3_5("ffffffff000000010000fffff0000000100000000005", 16);
    n2 = (r3_0 * r3_0) % p3;
    BN ret3_0 = n2.SqrtM(p3);
    n2 = (r3_1 * r3_1) % p3;
    BN ret3_1 = n2.SqrtM(p3);
    n2 = (r3_2 * r3_2) % p3;
    BN ret3_2 = n2.SqrtM(p3);
    n2 = (r3_3 * r3_3) % p3;
    BN ret3_3 = n2.SqrtM(p3);
    n2 = (r3_4 * r3_4) % p3;
    BN ret3_4 = n2.SqrtM(p3);
    n2 = (r3_5 * r3_5) % p3;
    BN ret3_5 = n2.SqrtM(p3);
    EXPECT_TRUE(isRootM(r3_0, ret3_0, p3));
    EXPECT_TRUE(isRootM(r3_1, ret3_1, p3));
    EXPECT_TRUE(isRootM(r3_2, ret3_2, p3));
    EXPECT_TRUE(isRootM(r3_3, ret3_3, p3));
    EXPECT_TRUE(isRootM(r3_4, ret3_4, p3));
    EXPECT_TRUE(isRootM(r3_5, ret3_5, p3));
    //EXPECT_TRUE(eqM(r3_0 == (ret3_0.Neg() % p3) );
    //EXPECT_TRUE(r3_1 == ret3_1);
    //EXPECT_TRUE(r3_2 == ret3_2);
    //EXPECT_TRUE(r3_3 == ret3_3);
    //EXPECT_TRUE(r3_4 == ret3_4);
    //EXPECT_TRUE(r3_5 == ret3_5);

    //BN p3 = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    //BN r3_0("ffffffff000000010000fffff0000000100000000000", 16);
    //BN r3_1("ffffffff000000010000fffff0000000100000000001", 16);
    //BN r3_2("ffffffff000000010000fffff0000000100000000002", 16);
    //BN r3_3("ffffffff000000010000fffff0000000100000000003", 16);
    //BN r3_4("ffffffff000000010000fffff0000000100000000004", 16);
    //BN r3_5("ffffffff000000010000fffff0000000100000000005", 16);
    //n2 = (r3_0 * r3_0) % p3;
    //BN ret3_0 = n2.SqrtM(p3);
    //n2 = (r3_1 * r3_1) % p3;
    //BN ret3_1 = n2.SqrtM(p3);
    //n2 = (r3_2 * r3_2) % p3;
    //BN ret3_2 = n2.SqrtM(p3);
    //n2 = (r3_3 * r3_3) % p3;
    //BN ret3_3 = n2.SqrtM(p3);
    //n2 = (r3_4 * r3_4) % p3;
    //BN ret3_4 = n2.SqrtM(p3);
    //n2 = (r3_5 * r3_5) % p3;
    //BN ret3_5 = n2.SqrtM(p3);
    //EXPECT_TRUE(r3_0 == ret3_0);
    //EXPECT_TRUE(r3_1 == ret3_1);
    //EXPECT_TRUE(r3_2 == ret3_2);
    //EXPECT_TRUE(r3_3 == ret3_3);
    //EXPECT_TRUE(r3_4 == ret3_4);
    //EXPECT_TRUE(r3_5 == ret3_5);

    //BN p4(11);
    //BN n4(7);
    //BN r4 = n2.SqrtM(p1);
    //EXPECT_TRUE(r4 == 3);
}

TEST(BN, SquareRootModuloP_More)
{
    BN p = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    for(int i = 0; i < 100; ++i){
        BN r = safeheron::rand::RandomBNLt(p);
        BN n = (r * r) % p;
        BN ret = n.SqrtM(p);
        EXPECT_TRUE(isRootM(r, ret, p));
    }
}

TEST(BN, SelfAssign)
{
    BN p = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    std::string str;
    p.ToHexStr(str);
    std::cout << "Before self-assignment: " << str << std::endl;
    p = std::move(p);
    p.ToHexStr(str);
    std::cout << "After self-assignment: " << str << std::endl;
}

TEST(BN, FromAndTo)
{
    // DON'T SUPPORT convert "" to BIGNUM!!!
    // expect a/b/c are Zero
    //BN a("", 2);
    //BN b("", 10);
    //BN c("", 16);
    //EXPECT_TRUE(a.IsZero());
    //EXPECT_TRUE(b.IsZero());
    //EXPECT_TRUE(c.IsZero());

    // expect a/b/c are Zero
    std::string str;
    uint8_t buff[256] = {0};
    BN d1 = BN::FromHexStr("0");
    BN d2 = BN::FromDecStr("0");
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(str);
    d2 = BN::FromBytesLE(str);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(buff, 0);
    d2 = BN::FromBytesLE(buff, 0);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());

    // BigNum Zero to string
    BN n;
    std::string s1,s2;
    n.ToHexStr(s1);
    n.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("0") == 0);
    EXPECT_TRUE(s2.compare("0") == 0);
    n.ToBytesBE(s1);
    n.ToBytesLE(s2);
    EXPECT_TRUE(s1.compare("") == 0);   //TODO:
    EXPECT_TRUE(s2.compare("") == 0);   //TODO:

    // BigNum Zero to buff
    uint8_t buff32[32] = {0};
    n.ToBytes32BE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);
    n.ToBytes32LE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);

    BN m(5);
    m.ToHexStr(s1);
    m.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("05") == 0);
    EXPECT_TRUE(s2.compare("5") == 0);
    m = BN::FromHexStr("5");
    m.ToHexStr(s1);
    EXPECT_TRUE(s1.compare("05") == 0);

    BN p(-2);
    p.ToHexStr(s1);
    p.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("-02") == 0);
    EXPECT_TRUE(s2.compare("-2") == 0);
    p = BN::FromDecStr("-0");
    EXPECT_TRUE(p.IsZero());
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
