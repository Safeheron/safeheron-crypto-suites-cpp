#ifndef SAFEHERON_CRYPTO_PAIL_PUBKEY_H
#define SAFEHERON_CRYPTO_PAIL_PUBKEY_H

#include <string>
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/proto_gen/paillier.pb.switch.h"

namespace safeheron{
namespace pail {

class PailPrivKey;

class PailPubKey {
    friend void CreateKeyPair(PailPrivKey &priv, PailPubKey &pub, int key_bits);

public:
    PailPubKey();

    /**
     * Constructor of PailPubKey
     * @param n = pq
     * @param g = n + 1
     * @constructor
     */
    PailPubKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &g);

    std::string Inspect() const;

    /**
     * Encrypt:
     *     c = g^m * r^n mod n^2
     *       = (1 + m*n) * r^n mod n^2
     *
     * @param {safeheron::bignum::BN} m: number to be encrypted
     * @param {safeheron::bignum::BN} r : random number
     */
    safeheron::bignum::BN EncryptWithR(const safeheron::bignum::BN &m, const safeheron::bignum::BN &r) const;

    safeheron::bignum::BN EncryptWithR_v0(const safeheron::bignum::BN &m, const safeheron::bignum::BN &r) const;

    /**
     * Encrypt:
     *     c = g^m * r^n mod n^2
     *       = (1 + m*n) * r^n mod n^2
     *
     * @param {safeheron::bignum::BN} m: number to be encrypted
     */
    safeheron::bignum::BN Encrypt(const safeheron::bignum::BN &m) const;

    /**
     * Check the plain message is valid. It means that m is in range [-(n-1)/2, m <= (n-1)/2]
     * @param m
     * @return
     */
    bool IsValidPlainMsg(const safeheron::bignum::BN &m) const;

    /**
     * Encrypt m, where m is in [-(n-1)/2, m <= (n-1)/2]
     * @param m
     * @param r
     * @return
     * @remark The message decrypted with "PailPrivKey.DecryptNeg" should be encrypted with "PailPubKey.EncryptNeg" or with "PailPubKey.EncryptNegWithR".
     */
    safeheron::bignum::BN EncryptNegWithR(const safeheron::bignum::BN &m, const safeheron::bignum::BN &r) const;

    /**
     * Encrypt m, where m is in [-(n-1)/2, m <= (n-1)/2]
     * @param m
     * @return
     * @remark The message decrypted with "PailPrivKey.DecryptNeg" should be encrypted with "PailPubKey.EncryptNeg" or with "PailPubKey.EncryptNegWithR".
     */
    safeheron::bignum::BN EncryptNeg(const safeheron::bignum::BN &m) const;

    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * E(b) mod n^2
     * @param {safeheron::bignum::BN} e_a: encrypted num a
     * @param {safeheron::bignum::BN} e_b: encrypted num b
     */
    safeheron::bignum::BN HomomorphicAdd(const safeheron::bignum::BN &e_a, const safeheron::bignum::BN &e_b) const;

    /**
     * Homomorphic add plain:
     *     E(a+b) = E(a) * g^b mod n^2
     *            = E(a) * (1 + b*n) mod n^2
     * @param {safeheron::bignum::BN} e_a: encrypted num a
     * @param {safeheron::bignum::BN} b: plain num b
     */
    safeheron::bignum::BN HomomorphicAddPlain(const safeheron::bignum::BN &e_a, const safeheron::bignum::BN &b) const;

    /**
     * Homomorphic add plain:
     *     E(a+b) = E(a) * g^b * r^n mod n^2
     *            = E(a) * (1 + b*n) * r^n mod n^2
     * @param {safeheron::bignum::BN} e_a: encrypted num a
     * @param {safeheron::bignum::BN} b: plain num b
     * @param {safeheron::bignum::BN} r: plain num r
     */
    safeheron::bignum::BN HomomorphicAddPlainWithR(const safeheron::bignum::BN &e_a, const safeheron::bignum::BN &b, const safeheron::bignum::BN &r) const;

    /**
     * Homomorphic multiple:
     *     E(ka) = E(a) ^ k mod n^2
     * @param {safeheron::bignum::BN} e_a: encrypted num a
     * @param {safeheron::bignum::BN} k: plain num to multiple
     */
    safeheron::bignum::BN HomomorphicMulPlain(const safeheron::bignum::BN &e_a, const safeheron::bignum::BN &k) const;

    const safeheron::bignum::BN& n() const { return n_; }

    const safeheron::bignum::BN& g() const { return g_; }

    const safeheron::bignum::BN& n_sqr() const { return n_sqr_; }

    bool ToProtoObject(safeheron::proto::PailPub &pail_pub) const;

    bool FromProtoObject(const safeheron::proto::PailPub &pail_pub);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);

private:
    safeheron::bignum::BN n_;   // n = pq
    safeheron::bignum::BN g_;   // g = n + 1
    safeheron::bignum::BN n_sqr_;

};

};
};


#endif //SAFEHERON_CRYPTO_PAIL_PUBKEY_H
