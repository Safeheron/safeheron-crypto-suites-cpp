#include <google/protobuf/stubs/common.h>
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-commitment/commitment.h"
#include "crypto-bn/rand.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::commitment::KgdCurvePoint;
using safeheron::commitment::KgdNumber;

int main(int argc, char **argv) {
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;

    std::string str;
    BN com_point = safeheron::commitment::CreateComWithBlind(point, blind_factor);
    com_point.ToHexStr(str);
    std::cout << "commitment(point) :" << str << std::endl;
    return 0;
}
