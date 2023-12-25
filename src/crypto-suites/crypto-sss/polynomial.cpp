#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-sss/polynomial.h"
#include "crypto-suites/common/custom_assert.h"

using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;

namespace safeheron{
namespace sss{

Polynomial::Polynomial(const vector<BN> &coeArr, const BN &prime) {
    _prime = prime;
    _vecCoe.insert(_vecCoe.begin(), coeArr.begin(), coeArr.end());
}

Polynomial::Polynomial(const BN &secret, const vector<BN> &coeArr, const BN &prime) {
    _prime = prime;
    _vecCoe.insert(_vecCoe.begin(), secret);
    _vecCoe.insert(_vecCoe.begin() + 1, coeArr.begin(), coeArr.end());
}

Polynomial Polynomial::CreateRandomPolynomial(const BN &secret, int threshold, const BN &prime) {
    ASSERT_THROW(threshold > 1);
    vector<BN> vecCoe;
    for(int i = 1; i < threshold; ++i){
        BN coe = safeheron::rand::RandomBNLt(prime);
        vecCoe.push_back(coe);
    }
    return Polynomial(secret, vecCoe, prime);
}

/**
 * Get point at 'x'
 *
 * User Honer's rule
 * f(x) = a0 + a1x + a2x^2 + ... + anx^n
 * This can, also, be written as:
 * f(x) = a0 + x(a1 + x(a2 + x(a3 + ... + x(an-1 + anx)....)
 * f(x) = a0 + x(a1 + x(a2 + x(a3 + ... + x(an-1 + x(an + x*0))....)
 *
 * @param x
 * @returns {[x, y]}
 */
void Polynomial::GetY(BN &y, const BN &x) {
    BN r(0);
    for(int i = _vecCoe.size() - 1; i >= 0; --i){
        r = (_vecCoe[i] + x * r) % _prime;
    }
    y = r;
}

void Polynomial::GetYArray(vector<BN> &yArr, const vector<BN> &xArr) {
    BN y;

    yArr.clear();
    for (size_t i = 0; i < xArr.size(); ++i) {
        GetY(y, xArr[i]);
        yArr.push_back(y);
    }
}

void Polynomial::GetPoints(vector<Point> &vecPoint, const vector<BN> &xArr) {
    vector<BN> yArr;
    GetYArray(yArr, xArr);
    ASSERT_THROW(xArr.size() == yArr.size());
    for(size_t i = 0; i < xArr.size(); ++i){
        vecPoint.push_back(Point(xArr[i], yArr[i]));
    }
}


/**
 * Get Commits of the polynomial according to Feldman's scheme
 *
 * f(x) = a0 + a1x + a2x^2 + ... + anx^n
 *
 * c0 = g^a0
 * c1 = g^a1
 * ...
 * ct = g^at
 *
 *
 * @param x*
 * @param curve
 * @returns {[c0, c1, ... , ct]}
 */
void Polynomial::GetCommits(vector<CurvePoint> &commits, const CurvePoint &g) {
    for (size_t i = 0; i < _vecCoe.size(); ++i) {
        commits.push_back(g * _vecCoe[i]);
    }
}

/**
 * Verify Commits of the polynomial according to Feldman's scheme
 *
 * f(x) = a0 + a1x + a2x^2 + ... + anx^n
 *
 * Verify g^y === c0 c1^{x} c2^{x^2} c3^{x^3}.... cn^{x^n}
 *
 *
 * @param commits:  [c0, c1, ... , ct]
 * @param x
 * @param y
 * @param curve
 * @returns {boolean}
 */
bool Polynomial::VerifyCommits(const vector<CurvePoint> &commits, const BN &x, const BN &y, const CurvePoint &g, const BN &prime) {
    CurvePoint expected_gy = g * y;
    CurvePoint gy(g.GetCurveType());
    BN x_pow_n(1);
    for (size_t i = 0; i < commits.size(); ++i) {
        gy += commits[i] * x_pow_n;
        x_pow_n = (x_pow_n * x) % prime;
    }
    return expected_gy == gy;
}

/**
 * Polynomial Interpolation
 *
 * Interpolation polynomial in the Lagrange form
 * Given a set of k + 1 data points:
 *     (x0, x1), ... , (xj,yj), ... , (xk,yk)
 * L(x) = \Sigma_{j=0}^k{yj lj(x)}
 * lj(x) = \Pi_{0<=m<=k, m!=j}{(x-xm)/(xj-xm)}
 *
 * @param x
 * @param threshold
 * @param points
 * @param prime
 * @returns {L(x)}
 */
void Polynomial::LagrangeInterpolate(BN &y, const BN &x, const vector<Point> &vecPoint, const BN &prime) {
    y = BN::ZERO;
    int threshold = vecPoint.size();
    for(int j = 0; j < threshold; ++j){
        BN xj = vecPoint[j].x;
        BN yj = vecPoint[j].y;
        BN num(1), den(1);
        for(int m = 0; m < threshold; ++m){
            if(m != j){
                BN xm = vecPoint[m].x;
                num *= (x - xm) % prime;
                den *= (xj - xm) % prime;
            }
        }
        BN lj = ( num * den.InvM(prime) ) % prime;
        y = (y + yj * lj) % prime;
    }
}


/**
 * GetLArray
 *
 * Interpolation polynomial in the Lagrange form
 * Given a array of k + 1 data points:
 *     (x0, ..., xj, ...., yk)
 * For points:
 *     (x0, y1), ... , (xj,yj), ... , (xk,yk)
 *
 * lj(x) = \Pi_{0<=m<=k, m!=j}{(x-xm)/(xj-xm)}
 *
 * @param x
 * @param xArray
 * @param prime
 * @returns {l0(x), ..., lj(x), ..., lk(x)}
 */
void Polynomial::GetLArray(vector<BN> &lArr, const BN &x, const vector<BN> &xArr, const BN &prime) {
    lArr.clear();
    for(size_t j = 0; j < xArr.size(); ++j){
        BN xj = xArr[j];
        BN num(1), den(1);
        for(size_t m = 0; m < xArr.size(); ++m){
            if(m != j){
                BN xm = xArr[m];
                num *= (x - xm) % prime;
                den *= (xj - xm) % prime;
            }
        }
        BN lj = ( num * den.InvM(prime) ) % prime;
        lArr.push_back(lj);
    }
}

}
}
