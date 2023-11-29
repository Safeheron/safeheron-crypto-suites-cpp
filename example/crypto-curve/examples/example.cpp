#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

int main(int argc, char **argv) {
    // p0 = g^10
    CurvePoint p0;
    if(!p0.PointFromXY(BN("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f", 16),
                      BN("878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773", 16),
                      CurveType::P256)){
        return 0;
    }

    // p1 = g^100
    CurvePoint p1;
    if(!p1.PointFromXY(BN("490a19531f168d5c3a5ae6100839bb2d1d920d78e6aeac3f7da81966c0f72170", 16),
                       BN("bbcd2f21db581bd5150313a57cfa2d9debe20d9f460117b588fcf9b0f4377794", 16),
                       CurveType::P256)){
        return 0;
    }

    // p2 = g^1000
    CurvePoint p2;
    if(!p2.PointFromXY(BN("b8fa1a4acbd900b788ff1f8524ccfff1dd2a3d6c917e4009af604fbd406db702", 16),
                       BN("9a5cc32d14fc837266844527481f7f06cb4fb34733b24ca92e861f72cc7cae37", 16),
                       CurveType::P256)){
        return 0;
    }

    std::cout << (p0 * 10 == p1) << std::endl;
    std::cout << (p1 * 10 == p2) << std::endl;

    CurvePoint p3(CurveType::P256);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    std::cout << (p3 == p1) << std::endl;

    CurvePoint p4(CurveType::P256);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    std::cout << (p4 == p2) << std::endl;

    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::P256);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    std::cout << (p5 == p1) << std::endl;

    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::P256);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    std::cout << (p6 == p0) << std::endl;


    CurvePoint p7;
    std::cout << (p7.PointFromXY(p1.x(), p1.y(), p1.GetCurveType())) << std::endl;
    std::cout << (p7.PointFromXY(p2.x(), p2.y(), p2.GetCurveType())) << std::endl;
    std::cout << (p7.PointFromXY(p3.x(), p3.y(), p3.GetCurveType())) << std::endl;
    return 0;
}
