#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-paillier/pail_privkey.h"


using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron{
namespace pail {

/**
 * Construct of PailPrivKey
 * @param lambda = (p-1)(q-1)
 * @param mu = lambda^-1 mod n
 * @param n = pq
 * @constructor
 */
PailPrivKey::PailPrivKey(const BN &lambda, const BN &mu, const BN &n) {
    lambda_ = lambda;
    mu_ = mu;
    n_ = n;
    n_sqr_ = n * n;
}

/**
 * Construct of PailPrivKey
 * @param lambda = (p-1)(q-1)
 * @param mu = lambda^-1 mod n
 * @param n = pq
 * @param p
 * @param q
 * @param p_sqr = p * p
 * @param q_sqr = q * q
 * @param p_minus_1 = p - 1
 * @param q_minus_1 = q - 1
 * @param hp = Lp[g^(p-1) mod p^2]^(-1) mod p
 * @param hq = Lq[g^(q-1) mod q^2]^(-1) mod q
 * @param q_inv_p = q^(-1) mod p
 * @param p_inv_q = p^(-1) mod q
 * @constructor
 */
PailPrivKey::PailPrivKey(const BN &lambda, const BN &mu, const BN &n, const BN &n_sqr, const BN &p, const BN &q,
                         const BN &p_sqr, const BN &q_sqr, const BN &p_minus_1,
                         const BN &q_minus_1, const BN &hp, const BN &hq, const BN &q_inv_p, const BN &p_inv_q) {
    lambda_ = lambda;
    mu_ = mu;
    n_ = n;
    n_sqr_ = n_sqr;
    p_ = p;
    q_ = q;
    p_sqr_ = p_sqr;
    q_sqr_ = q_sqr;
    p_minus_1_ = p_minus_1;
    q_minus_1_ = q_minus_1;
    hp_ = hp;
    hq_ = hq;
    q_inv_p_ = q_inv_p;
    p_inv_q_ = p_inv_q;
}

PailPrivKey::PailPrivKey() {
    lambda_ = BN();
    mu_ = BN();
    n_ = BN();
    n_sqr_ = BN();
}

std::string PailPrivKey::Inspect() const {
    std::string str;
    this->ToJsonString(str);
    return str;
}


/**
 * Decrypt:
 *     c = L(c^lambda mod n^2) * mu mod n
 *
 * @param {BN} c: encrypted number
 */
BN PailPrivKey::Decrypt(const BN &c) const {
    bool use_slow = ((p_ == 0)
                     || (q_ == 0)
                     || (p_sqr_ == 0)
                     || (q_sqr_ == 0)
                     || (p_minus_1_ == 0)
                     || (q_minus_1_ == 0)
                     || (hp_ == 0)
                     || (hq_ == 0)
                     || (q_inv_p_ == 0)
                     || (p_inv_q_ == 0)
    );

    if (use_slow) {
        return DecryptSlowly(c);
    } else {
        return DecryptFast(c);
    }
}

BN PailPrivKey::DecryptNeg(const BN &c) const {
    BN half_n = n_ >> 1;
    BN m = Decrypt(c);
    if(m > half_n) {
        return m - n_;
    }
    else {
        return m;
    }
}


BN PailPrivKey::DecryptFast(const BN &c) const {
    BN x = c.PowM(p_minus_1_, p_sqr_);
    BN lpx = (x - 1) / p_;
    BN mp = (lpx * hp_) % p_;

    x = c.PowM(q_minus_1_, q_sqr_);
    BN lqx = (x - 1) / q_;
    BN mq = (lqx * hq_) % q_;

    // a1 = mp, t1 = q_inv_p, M1 = q, m1 = p
    // a2 = mq, t2 = p_inv_q, M2 = p, m2 = q
    // m = CRT(a1, t1, M1, m1, a2, t2, M2, m2)
    //   = (a1*t1*M1 + a2*t2*M2) mod (m1*m2)
    BN item1 = (mp * q_inv_p_ * q_) % n_;
    BN item2 = (mq * p_inv_q_ * p_) % n_;
    return (item1 + item2) % n_;
}

BN PailPrivKey::DecryptSlowly(const BN &c) const {
    BN x = c.PowM(lambda_, n_sqr_);
    BN l = (x - 1) / n_;
    return (l * mu_) % n_;
}


bool PailPrivKey::ToProtoObject(safeheron::proto::PailPriv &pail_priv) const {
    bool ok = true;
    string str;

    // lambda
    ok = (lambda_ != 0);
    if (!ok) return false;
    lambda_.ToHexStr(str);
    pail_priv.set_lambda(str);

    ok = (mu_ != 0);
    if (!ok) return false;
    mu_.ToHexStr(str);
    pail_priv.set_mu(str);

    ok = (n_ != 0);
    if (!ok) return false;
    n_.ToHexStr(str);
    pail_priv.set_n(str);

    ok = (p_ != 0);
    if (!ok) return false;
    p_.ToHexStr(str);
    pail_priv.set_p(str);

    ok = (q_ != 0);
    if (!ok) return false;
    q_.ToHexStr(str);
    pail_priv.set_q(str);

    ok = (p_sqr_ != 0);
    if (!ok) return false;
    p_sqr_.ToHexStr(str);
    pail_priv.set_psqr(str);

    ok = (q_sqr_ != 0);
    if (!ok) return false;
    q_sqr_.ToHexStr(str);
    pail_priv.set_qsqr(str);

    ok = (p_minus_1_ != 0);
    if (!ok) return false;
    p_minus_1_.ToHexStr(str);
    pail_priv.set_pminus1(str);

    ok = (q_minus_1_ != 0);
    if (!ok) return false;
    q_minus_1_.ToHexStr(str);
    pail_priv.set_qminus1(str);

    ok = (hp_ != 0);
    if (!ok) return false;
    hp_.ToHexStr(str);
    pail_priv.set_hp(str);

    ok = (hq_ != 0);
    if (!ok) return false;
    hq_.ToHexStr(str);
    pail_priv.set_hq(str);

    ok = (q_inv_p_ != 0);
    if (!ok) return false;
    q_inv_p_.ToHexStr(str);
    pail_priv.set_qinvp(str);

    ok = (p_inv_q_ != 0);
    if (!ok) return false;
    p_inv_q_.ToHexStr(str);
    pail_priv.set_pinvq(str);

    return true;
}

bool PailPrivKey::FromProtoObject(const safeheron::proto::PailPriv &pail_priv) {
    bool ok = true;
    lambda_ = BN::FromHexStr(pail_priv.lambda());
    ok = (lambda_ != 0);
    if (!ok) return false;

    mu_ = BN::FromHexStr(pail_priv.mu());
    ok = (mu_ != 0);
    if (!ok) return false;

    n_ = BN::FromHexStr(pail_priv.n());
    ok = (n_ != 0);
    if (!ok) return false;

    p_ = BN::FromHexStr(pail_priv.p());
    ok = (p_ != 0);
    if (!ok) return false;

    q_ = BN::FromHexStr(pail_priv.q());
    ok = (q_ != 0);
    if (!ok) return false;

    p_minus_1_ = BN::FromHexStr(pail_priv.pminus1());
    ok = (p_minus_1_ != 0);
    if (!ok) return false;

    q_minus_1_ = BN::FromHexStr(pail_priv.qminus1());
    ok = (q_minus_1_ != 0);
    if (!ok) return false;

    hp_ = BN::FromHexStr(pail_priv.hp());
    ok = (hp_ != 0);
    if (!ok) return false;

    hq_ = BN::FromHexStr(pail_priv.hq());
    ok = (hq_ != 0);
    if (!ok) return false;

    q_inv_p_ = BN::FromHexStr(pail_priv.qinvp());
    ok = (q_inv_p_ != 0);
    if (!ok) return false;

    p_inv_q_ = BN::FromHexStr(pail_priv.pinvq());
    ok = (p_inv_q_ != 0);
    if (!ok) return false;

    n_sqr_ = n_ * n_;
    q_sqr_ = q_ * q_;
    p_sqr_ = p_ * p_;
    return true;
}

bool PailPrivKey::ToBase64(string &base64) const {
    bool ok = true;
    base64.clear();

    safeheron::proto::PailPriv proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    base64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailPrivKey::FromBase64(const string &base64) {
    bool ok = true;

    string data = safeheron::encode::base64::DecodeFromBase64(base64);

    safeheron::proto::PailPriv proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailPrivKey::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailPriv proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailPrivKey::FromJsonString(const string &json_str) {
    safeheron::proto::PailPriv proto_object;
    JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

};
};
