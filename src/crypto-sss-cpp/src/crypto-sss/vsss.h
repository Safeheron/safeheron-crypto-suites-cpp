#ifndef SAFEHERON_CRYPTO_VSSS_H
#define SAFEHERON_CRYPTO_VSSS_H

#include "polynomial.h"

namespace safeheron{
namespace sss {
namespace vsss{

/**
 * Make shares of 'secret'
 *
 * @param secret
 * @param threshold
 * @param shareIndexs
 *
 *        [new safeheron::bignum::BN('1',10),
 *         new safeheron::bignum::BN('2',10),
 *         new safeheron::bignum::BN('3',10),
 *         new safeheron::bignum::BN('4',10)]
 *
 * @param n
 * @param prime
 * @returns {Promise<[[shareIndex1, share1], [shareIndex2, share2],[shareIndex3, share3],]>}
 */
void
MakeShares(std::vector<Point> &shares, const safeheron::bignum::BN &secret, int threshold, const std::vector<safeheron::bignum::BN> &shareIndexs, const safeheron::bignum::BN &prime);

/**
 * Make shares of 'secret'
 *
 * @param secret
 * @param threshold
 * @param shareIndexs
 *
 *        [new safeheron::bignum::BN('1',10),
 *         new safeheron::bignum::BN('2',10),
 *         new safeheron::bignum::BN('3',10),
 *         new safeheron::bignum::BN('4',10)]
 *
 * @param secret
 * @param threshold
 * @param shareIndexs
 * @param n
 * @param prime
 * @param curve
 * @returns {Promise<[[shareIndex1, share1], [shareIndex2, share2],[shareIndex3, share3],[c0,c1,ct]]>}
 */
void
MakeSharesWithCommits(std::vector<Point> &shares, std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &secret, int threshold,
                      const std::vector<safeheron::bignum::BN> &shareIndexs, const safeheron::bignum::BN &prime, const safeheron::curve::CurvePoint &g);

/**
 * Make shares of 'secret'
 *
 * @param secret
 * @param threshold
 * @param shareIndexs
 *
 *        [new safeheron::bignum::BN('1',10),
 *         new safeheron::bignum::BN('2',10),
 *         new safeheron::bignum::BN('3',10),
 *         new safeheron::bignum::BN('4',10)]
 *
 * @param secret
 * @param threshold
 * @param shareIndexs
 * @param n
 * @param prime
 * @param curve
 * @returns {Promise<[[shareIndex1, share1], [shareIndex2, share2],[shareIndex3, share3],[c0,c1,ct]]>}
 */
void
MakeSharesWithCommitsAndCoes(std::vector<Point> &shares, std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &secret, int threshold,
                      const std::vector<safeheron::bignum::BN> &shareIndexs, const std::vector<safeheron::bignum::BN> &coeArray, const safeheron::bignum::BN &prime, const safeheron::curve::CurvePoint &g);

/**
 * Verify share in Feldman's scheme
 *
 * @param commits
 * @param shareIndex
 * @param share
 * @param curve
 * @returns {boolean}
 */
bool
VerifyShare(const std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &shareIndex, const safeheron::bignum::BN &share, const safeheron::curve::CurvePoint &g, const safeheron::bignum::BN &prime);

/**
 * Recover secret
 *
 * @param threshold
 * @param shares
 * @param prime
 * @returns {secret}
 */
void
RecoverSecret(safeheron::bignum::BN &secret, const std::vector<Point> &shares, const safeheron::bignum::BN &prime);



}
}
}
#endif //SAFEHERON_CRYPTO_VSSS_H
