#include "pail.h"
#include <cassert>
#include "../crypto-bn/rand.h"

using safeheron::bignum::BN;

namespace safeheron{
namespace pail {


 /**
 * Create a Paillier Key Pair with key length == "key_bits"
 *
 * @param key_bits
 */
void CreateKeyPair(PailPrivKey &priv, PailPubKey &pub, int key_bits) {
    assert(key_bits == 1024 || key_bits == 2048 || key_bits == 3072 || key_bits == 4096);
    BN p = safeheron::rand::RandomSafePrimeStrict(key_bits / 2);
    BN q;
    // make sure: p != q
    do {
        q = safeheron::rand::RandomSafePrimeStrict(key_bits / 2);
    } while (p == q);

    // make sure: p > q
    if (p < q) {
        BN::Swap(p, q);
    }

    BN n = p * q;
    BN g = n + 1;
    BN lambda = (p - 1) * (q - 1);
    BN mu = lambda.InvM(n);
    BN n_sqr = n * n;

    BN p_sqr = p * p;    // p_sqr = p^2
    BN q_sqr = q * q;    // q_sqr = q^2
    BN p_minus_1 = p - 1; // p_minus_1 = p-1
    BN q_minus_1 = q - 1; // q_minus_1 = q-1

    BN x = g.PowM(p - 1, p_sqr);
    BN lpx = (x - 1) / p;
    BN hp = lpx.InvM(p);      // hp = Lp[g^(p-1) mod p^2]^(-1) mod p

    x = g.PowM(q - 1, q_sqr);
    BN lqx = (x - 1) / q;
    BN hq = lqx.InvM(q);      // hq = Lq[g^(q-1) mod q^2]^(-1) mod q

    BN q_inv_p = q.InvM(p);   // q_inv_p = q^(-1) mod p
    BN p_inv_q = p.InvM(q);;   // p_inv_q = p^(-1) mod q

    // Set Private Key
    priv.p_ = p;
    priv.q_ = q;
    priv.n_ = n;
    priv.mu_ = mu;
    priv.lambda_ = lambda;
    priv.n_sqr_ = n_sqr;

    // For fast decryption
    priv.p_sqr_ = p_sqr;
    priv.q_sqr_ = q_sqr;
    priv.p_minus_1_ = p_minus_1;
    priv.q_minus_1_ = q_minus_1;
    priv.hp_ = hp;
    priv.hq_ = hq;
    priv.q_inv_p_ = q_inv_p;
    priv.p_inv_q_ = p_inv_q;

    // Set Public Key
    pub.n_ = n;
    pub.g_ = g;
    pub.n_sqr_ = n_sqr;
}

/**
 * Create a Paillier Key Pair (key size == 1024 bit)
 *
 * @param key_bits
 */
void CreateKeyPair1024(PailPrivKey &priv, PailPubKey &pub) {
    pail::CreateKeyPair(priv, pub, 1024);
}

/**
 * Create a Paillier Key Pair (key size == 1024 bit)
 *
 * @param key_bits
 */
void CreateKeyPair2048(PailPrivKey &priv, PailPubKey &pub) {
    pail::CreateKeyPair(priv, pub, 2048);
}

/**
 * Create a Paillier Key Pair (key size == 1024 bit)
 *
 * @param key_bits
 */
void CreateKeyPair3072(PailPrivKey &priv, PailPubKey &pub) {
    pail::CreateKeyPair(priv, pub, 3072);
}

/**
 * Create a Paillier Key Pair (key size == 1024 bit)
 *
 * @param key_bits
 */
void CreateKeyPair4096(PailPrivKey &priv, PailPubKey &pub) {
    pail::CreateKeyPair(priv, pub, 4096);
}

PailPrivKey CreatePailPrivKey(const std::string& lambda_hex, const std::string& mu_hex, const std::string& n_hex, const std::string& n_sqr_hex,
                              const std::string& p_hex, const std::string& q_hex,
                              const std::string& p_sqr_hex, const std::string& q_sqr_hex,
                              const std::string& p_minus_1_hex, const std::string& q_minus_1_hex,
                              const std::string& hp_hex, const std::string& hq_hex,
                              const std::string& q_inv_p_hex, const std::string& p_inv_q_hex) {
    BN lambda = BN::FromHexStr(lambda_hex);
    BN mu = BN::FromHexStr(mu_hex);
    BN n = BN::FromHexStr(n_hex);
    BN n_sqr = BN::FromHexStr(n_sqr_hex);
    BN p = BN::FromHexStr(p_hex);
    BN q = BN::FromHexStr(q_hex);
    BN p_sqr = BN::FromHexStr(p_sqr_hex);
    BN q_sqr = BN::FromHexStr(q_sqr_hex);
    BN p_minus_1 = BN::FromHexStr(p_minus_1_hex);
    BN q_minus_1 = BN::FromHexStr(q_minus_1_hex);
    BN hp = BN::FromHexStr(hp_hex);
    BN hq = BN::FromHexStr(hq_hex);
    BN q_inv_p = BN::FromHexStr(q_inv_p_hex);
    BN p_inv_q = BN::FromHexStr(p_inv_q_hex);
    return PailPrivKey(lambda, mu, n, n_sqr,
                       p, q,
                       p_sqr, q_sqr,
                       p_minus_1, q_minus_1,
                       hp, hq,
                       q_inv_p, p_inv_q);
}

PailPrivKey CreatePailPrivKey(const std::string& lambda_hex, const std::string& mu_hex, const std::string& n_hex) {
    BN lambda = BN::FromHexStr(lambda_hex);
    BN mu = BN::FromHexStr(mu_hex);
    BN n = BN::FromHexStr(n_hex);
    return PailPrivKey(lambda, mu, n);
}

PailPubKey CreatePailPubKey(const std::string& n_hex, const std::string& g_hex) {
    BN n = BN::FromHexStr(n_hex);
    BN g = BN::FromHexStr(g_hex);
    return PailPubKey(n, g);
}

};
};
