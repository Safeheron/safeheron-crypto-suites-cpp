#ifndef SAFEHERON_CURVE_H
#define SAFEHERON_CURVE_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-curve/ecdsa.h"
#include "crypto-suites/crypto-curve/eddsa.h"

namespace safeheron{
namespace curve {

/**
 * A Curve class
 */
class Curve {
public:
    const safeheron::bignum::BN p; /**< A prime which indicates the finite fields. */
    const safeheron::bignum::BN a; /**< A parameter to define the curve. */
    const safeheron::bignum::BN b; /**< A parameter to define the curve. */
    const safeheron::bignum::BN c; /**< A parameter to define the curve. */
    const safeheron::bignum::BN d; /**< A parameter to define the curve. */
    const safeheron::bignum::BN n; /**< Order of the group on the curve */
    const CurvePoint g; /**< Base point of the group on the curve */
    const ec_group_st* grp; /**< A pointer to the struct indicating the group on the curve */

    /**
     * Constructor.
     *
     * @param _p A prime which indicates the finite fields.
     * @param _a A parameter to define the curve.
     * @param _b A parameter to define the curve.
     * @param _c A parameter to define the curve.
     * @param _d A parameter to define the curve.
     * @param _n Order of the group on the curve
     * @param _g Base point of the group on the curve
     */
    Curve(safeheron::bignum::BN _p,
          safeheron::bignum::BN _a,
          safeheron::bignum::BN _b,
          safeheron::bignum::BN _c,
          safeheron::bignum::BN _d,
          safeheron::bignum::BN _n,
          CurvePoint _g);

    /**
     * Destructor.
     */
    ~Curve();
};

/**
 * Return a pointer to the group information.
 * @param[in] c_type
 * @return A pointer to a struct ec_group_st.
 */
const ec_group_st *GetCurveGroup(CurveType c_type);

/**
 * Get a Curve with the specified type.
 * @param[in] c_type
 * @return A pointer to the Curve.
 */
const Curve *GetCurveParam(CurveType c_type);

}
}

#endif //SAFEHERON_CURVE_H
