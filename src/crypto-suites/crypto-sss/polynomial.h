#ifndef SAFEHERON_CRYPTO_POLYNOMIAL_H
#define SAFEHERON_CRYPTO_POLYNOMIAL_H

#include <vector>
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/bn.h"

namespace safeheron{
namespace sss{

struct Point{
   safeheron::bignum::BN x;
   safeheron::bignum::BN y;
   Point(const safeheron::bignum::BN &xx, const safeheron::bignum::BN &yy){ x = xx; y = yy; }
};

class Polynomial {
private:
    safeheron::bignum::BN _prime;
    std::vector<safeheron::bignum::BN> _vecCoe;

public:
    Polynomial(const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime);
    Polynomial(const safeheron::bignum::BN &secret, const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime);
    static Polynomial CreateRandomPolynomial(const safeheron::bignum::BN &secret, int threshold, const safeheron::bignum::BN &prime);

    void GetY(safeheron::bignum::BN &y, const safeheron::bignum::BN &x);
    void GetYArray(std::vector<safeheron::bignum::BN> &yArr, const std::vector<safeheron::bignum::BN> &xArr);
    void GetPoints(std::vector<Point> &vecPoint, const std::vector<safeheron::bignum::BN> &xArr);
    void GetCommits(std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::curve::CurvePoint &g);

    static bool VerifyCommits(const std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, const safeheron::curve::CurvePoint &g, const safeheron::bignum::BN &prime);
    static void LagrangeInterpolate(safeheron::bignum::BN &y, const safeheron::bignum::BN &x, const std::vector<Point> &vecPoint, const safeheron::bignum::BN &prime );
    static void GetLArray(std::vector<safeheron::bignum::BN> &lArr, const safeheron::bignum::BN &x, const std::vector<safeheron::bignum::BN> &xArr, const safeheron::bignum::BN &prime );
};

}
}
#endif //SAFEHERON_CRYPTO_POLYNOMIAL_H
