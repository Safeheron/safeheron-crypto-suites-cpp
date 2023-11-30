#ifndef CPP_MPC_COMMITMENT_H
#define CPP_MPC_COMMITMENT_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-commitment/kgd_number.h"
#include "crypto-suites/crypto-commitment/kgd_curve_point.h"
#include "crypto-suites/crypto-commitment/com256.h"
#include "crypto-suites/crypto-commitment/com512.h"

namespace safeheron{
namespace commitment {

/**
 * Commitment with a blind factor
 * @param num
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(const safeheron::bignum::BN &num, const safeheron::bignum::BN &blind_factor);

/**
 * Commitment with a blind factor
 * @param num_arr
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(const std::vector<safeheron::bignum::BN> &num, const safeheron::bignum::BN &blind_factor);

/**
 * Commitment with a blind factor
 * @param point
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(const curve::CurvePoint &point, const safeheron::bignum::BN &blind_factor);

/**
 * Commitment with a blind factor
 * @param points
 * @param blind_factor
 * @return commitment
 */
safeheron::bignum::BN CreateComWithBlind(const std::vector<curve::CurvePoint> &points, const safeheron::bignum::BN &blind_factor);

}
}


#endif //CPP_MPC_COMMITMENT_H
