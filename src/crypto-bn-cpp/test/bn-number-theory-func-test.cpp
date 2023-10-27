#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"

#ifdef ENABLE_ASSEMBLE
#include <google/protobuf/stubs/common.h>
#endif

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

TEST(BN, NumberTheory) {
    BN bn0;
    BN bn1(10);
    BN bn2(-10);
    EXPECT_TRUE(bn1.Neg() == bn2);
    EXPECT_TRUE(bn2.Neg() == bn1);
    EXPECT_TRUE(bn0.Neg() == bn0);

    BN bn3(3);
    BN bn4, bn5;
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 3) && (bn5 == 1));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -3) && (bn5 == -1));
    bn3 = BN(-3);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -3) && (bn5 == 1));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 3) && (bn5 == -1));

    bn1 = BN(20);
    bn2 = BN(-20);
    bn3 = BN(7);
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 2) && (bn5 == 6));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -2) && (bn5 == -6));
    bn3 = BN(-7);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -2) && (bn5 == 6));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 2) && (bn5 == -6));

    bn1 = BN(30);
    bn2 = BN(-30);
    bn3 = BN(6);
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 5) && (bn5 == 0));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -5) && (bn5 == 0));
    bn3 = BN(-6);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -5) && (bn5 == 0));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 5) && (bn5 == 0));

    BN bn6(7);
    BN bn7(2);
    BN bn8(3);
    EXPECT_EQ(bn7.InvM(bn6), 4);
    EXPECT_EQ(bn8.InvM(bn6), 5);
    bn6 = BN(11);
    EXPECT_EQ(bn7.InvM(bn6), 6);
    EXPECT_EQ(bn8.InvM(bn6), 4);

    bn6 = BN(7);
    EXPECT_EQ(bn7.PowM(bn8,bn6), 1);
    EXPECT_EQ(bn7.PowM(bn7,bn6), 4);
    EXPECT_EQ(bn8.PowM(bn7,bn6), 2);
    EXPECT_EQ(bn8.PowM(bn8,bn6), 6);

    bn6 = BN(23);
    EXPECT_TRUE(bn7.ExistSqrtM(bn6));
    EXPECT_TRUE(bn7.SqrtM(bn6) == 5 || bn7.SqrtM(bn6) == 18);
    bn6 = BN(13);
    EXPECT_TRUE(bn8.ExistSqrtM(bn6));
    EXPECT_TRUE(bn8.SqrtM(bn6) == 4 ||bn8.SqrtM(bn6) == 9);
    bn6 = BN(11);
    EXPECT_FALSE(bn7.ExistSqrtM(bn6));

    bn6 = BN(7);
    EXPECT_TRUE(bn6.IsProbablyPrime());
    bn6 = BN(2147483647);
    EXPECT_TRUE(bn6.IsProbablyPrime());
    bn6 =  BN::FromDecStr("3512361716805789371972727939883643101583447981968520"
                          "328116222065795410830354167025485897169128481068329654077646734548662444"
                          "384264600983851903304370332254379348431475618118443515097594013924630541"
                          "0828726731670875346026456911796687116940339837750972042560711485424581228"
                          "15112287827804817008054571967569811098943958115474043611129903319499487179"
                          "31275315698239060479759467211010927996811642694668143998681714908245060366"
                          "776555066332127329304716050935303286792734592049624692299978648654921120227"
                          "652227236744907852210908978855731702859500827419174748928577397977510254103"
                          "5592329871004023280977348435038643994502879226281");
    EXPECT_FALSE(bn6.IsProbablyPrime());
    bn6 = BN::FromDecStr("531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127");
    EXPECT_TRUE(bn6.IsProbablyPrime());

    BN bn9(45);
    BN bn10(63);
    EXPECT_TRUE(bn9.Gcd(bn10) == 9);
    EXPECT_TRUE(bn9.Lcm(bn10) == 315);
    bn9 = BN(7);
    bn10 = BN(70);
    EXPECT_TRUE(bn9.Gcd(bn10) == 7);
    EXPECT_TRUE(bn9.Lcm(bn10) == 70);
    bn9 = BN(1);
    bn10 = BN(4);
    EXPECT_TRUE(bn9.Gcd(bn10) == 1);
    EXPECT_TRUE(bn9.Lcm(bn10) == 4);
}

bool isRootM(BN &a, BN &b, BN &m){
    return (a == b) || (a + b == m);
}

TEST(BN, SquareRootModuloP)
{
    BN p0(5);
    BN n0(0);
    BN r0 = n0.SqrtM(p0);
    EXPECT_TRUE(r0 == 0);

    BN p1(5);
    BN n1(2);
    EXPECT_FALSE( n1.ExistSqrtM(p1) );
    try {
        BN r1 = n1.SqrtM(p1);
    }catch (const LocatedException &e) {
        std::cout << e.what() << std::endl;
    }

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

TEST(BN, ModPow2)
{
    BN b2(2);
    BN b3(3);
    BN b7(7);
    // 3^2 mod 7 = 2
    EXPECT_TRUE(b3.PowM(b2, b7) == 2);
    // 3^(-2) mod 7 = (3^2)^-1 mod 7 = 2^-1 mod 7 = 4
    EXPECT_TRUE(b3.PowM(b2.Neg(), b7) == 4);
    // 3^3 mod 7 = 6
    EXPECT_TRUE(b3.PowM(b3, b7) == 6);
}

TEST(BN, ExtendedEuclidean)
{
    // Given a, b, compute x, y, d, st. ax + by = d
    BN a(6);
    BN b(8);
    BN x, y, d;
    BN::ExtendedEuclidean(a, b, x, y, d);
    EXPECT_TRUE(d == 2);
    std::cout<< "d: " << d.Inspect() << std::endl;
    EXPECT_TRUE(x == -1);
    std::cout<< "x: " << x.Inspect() << std::endl;
    EXPECT_TRUE(y == 1);
    std::cout<< "y: " << y.Inspect() << std::endl;

    // Given a, b, compute x, y, d, st. ax + by = d
    a = BN(3);
    b = BN(4);
    BN::ExtendedEuclidean(a, b, x, y, d);
    EXPECT_TRUE(d == 1);
    EXPECT_TRUE(x == -1);
    EXPECT_TRUE(y == 1);

    // Given a, b, compute x, y, d, st. ax + by = d
    a = BN(4);
    b = BN(3);
    BN::ExtendedEuclidean(a, b, x, y, d);
    EXPECT_TRUE(d == 1);
    EXPECT_TRUE(x == 1);
    EXPECT_TRUE(y == -1);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

#ifdef ENABLE_ASSEMBLE
    google::protobuf::ShutdownProtobufLibrary();
#endif

    return ret;
}
