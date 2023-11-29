#ifndef SAFEHERON_RANDOM_H
#define SAFEHERON_RANDOM_H

#include "bn.h"

namespace safeheron {
namespace rand {

/**
 * Sample random bytes.
 * @param buf
 * @param size
 */
void RandomBytes(unsigned char * buf, size_t size);

/**
 * Sample random BN.
 * @param bits
 * @return a random BN.
 */
safeheron::bignum::BN RandomBN(size_t bits);

/**
 * Sample random BN whose highest bit is 1.
 * @param bits
 * @return a random BN.
 */
safeheron::bignum::BN RandomBNStrict(size_t bits);

/**
 * Sample random prime.
 * @param bits.
 * @return a random BN.
 */
safeheron::bignum::BN RandomPrime(size_t bits);

/**
 * Sample random prime whose highest bit is 1.
 * @param bits.
 * @return a random prime.
 */
safeheron::bignum::BN RandomPrimeStrict(size_t bits);

/**
 * Sample random safe prime.
 * @param bits.
 * @return a random safe prime.
 */
safeheron::bignum::BN RandomSafePrime(size_t bits);

/**
 * Sample random safe prime whose highest bit is 1.
 * @param bits.
 * @return a random safe prime.
 */
safeheron::bignum::BN RandomSafePrimeStrict(size_t bits);

/**
 * Sample random BN which is less than "max".
 * @param max
 * @return a random BN.
 */
safeheron::bignum::BN RandomBNLt(const safeheron::bignum::BN &max);

/**
 * Sample random BN which is less than and co-prime to "max"
 * @deprecated Use "RandomBNLtCoPrime" instead.
 * @param max
 * @return a random BN
 */
safeheron::bignum::BN RandomBNLtGcd(const safeheron::bignum::BN &max);

/**
 * Sample random BN which is less than and co-prime to "max"
 * @param max
 * @return a random BN
 */
safeheron::bignum::BN RandomBNLtCoPrime(const safeheron::bignum::BN &max);

 /**
  * Sample random BN in range [min, max)
  * @param min
  * @param max
  * @return
  */
safeheron::bignum::BN RandomBNInRange(const safeheron::bignum::BN &min, const safeheron::bignum::BN &max);

/**
 * Sample random BN.in range (-limit, limit)
 * @param limit
 * @return a random BN
 */
safeheron::bignum::BN RandomNegBNInSymInterval(const safeheron::bignum::BN &limit);

/**
 * Sample random BN in range (-2^bits, +2^bits)
 * @param bits
 * @return a random BN
 */
safeheron::bignum::BN RandomNegBNInSymInterval(size_t bits);

};
};


#endif //SAFEHERON_RANDOM_H