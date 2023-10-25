#include "no_small_factor_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha512.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::hash::CSHA512;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace no_small_factor_proof {

void NoSmallFactorProof::Prove(const NoSmallFactorSetUp &setup, const NoSmallFactorStatement &statement, const NoSmallFactorWitness &witness) {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    uint32_t l = statement.l_;
    uint32_t varepsilon = statement.varepsilon_;

    const BN &p = witness.p_;
    const BN &q = witness.q_;

    const BN sqrt_N0 = N0.Sqrt();
    const BN limit_alpha_beta = (BN::ONE << (l + varepsilon)) * sqrt_N0;
    // 2^l * N_tilde
    const BN limit_mu_nu = (BN::ONE << l) * N_tilde;
    // 2^l * N0 * N_tilde
    const BN limit_sigma = limit_mu_nu * N0;
    // 2^(l + varepsilon) * N0 * N_tilde
    const BN limit_r = limit_sigma << varepsilon;
    // 2^(l + varepsilon) * N_tilde
    const BN limit_x_y = limit_mu_nu << varepsilon;

    const BN alpha = RandomNegBNInSymInterval(limit_alpha_beta);
    const BN beta = RandomNegBNInSymInterval(limit_alpha_beta);
    const BN mu = RandomNegBNInSymInterval(limit_mu_nu);
    const BN nu = RandomNegBNInSymInterval(limit_mu_nu);
    sigma_ = RandomNegBNInSymInterval(limit_sigma);
    const BN r = RandomNegBNInSymInterval(limit_r);
    const BN x = RandomNegBNInSymInterval(limit_x_y);
    const BN y = RandomNegBNInSymInterval(limit_x_y);

    // P = s^p * t^mu  mod N_tilde
    P_ = (s.PowM(p, N_tilde) * t.PowM(mu, N_tilde)) % N_tilde;
    // Q = s^q * t^nu  mod N_tilde
    Q_ = (s.PowM(q, N_tilde) * t.PowM(nu, N_tilde)) % N_tilde;
    // A = s^alpha * t^x  mod N_tilde
    A_ = (s.PowM(alpha, N_tilde) * t.PowM(x, N_tilde)) % N_tilde;
    // B = s^beta * t^y  mod N_tilde
    B_ = (s.PowM(beta, N_tilde) * t.PowM(y, N_tilde)) % N_tilde;
    // T = Q^alpha * t^r  mod N_tilde
    T_ = (Q_.PowM(alpha, N_tilde) * t.PowM(r, N_tilde)) % N_tilde;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    P_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Q_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    sigma_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    int byte_len = l / 8;
    BN e = BN::FromBytesBE(sha512_digest, byte_len);
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    BN sigma_tilde = sigma_ - nu * p;
    z1_ = alpha + e * p;
    z2_ = beta + e * q;
    w1_ = x + e * mu;
    w2_ = y + e * nu;
    v_ = r + e * sigma_tilde;
}

bool NoSmallFactorProof::Verify(const NoSmallFactorSetUp &setup, const NoSmallFactorStatement &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    uint32_t l = statement.l_;
    uint32_t varepsilon = statement.varepsilon_;

    const BN sqrt_N0 = N0.Sqrt();
    const BN limit_alpha_beta = (BN::ONE << (l + varepsilon)) * sqrt_N0;
    if(z1_ > limit_alpha_beta || z1_ < BN::ZERO - limit_alpha_beta)return false;
    if(z2_ > limit_alpha_beta || z2_ < BN::ZERO - limit_alpha_beta)return false;

    if(N_tilde.BitLength() < 2046)return false;

    if(P_ % N_tilde == 0) return false;
    if(Q_ % N_tilde == 0) return false;
    if(A_ % N_tilde == 0) return false;
    if(B_ % N_tilde == 0) return false;
    if(T_ % N_tilde == 0) return false;

    if(P_.Gcd(N_tilde) != 1) return false;
    if(Q_.Gcd(N_tilde) != 1) return false;
    if(A_.Gcd(N_tilde) != 1) return false;
    if(B_.Gcd(N_tilde) != 1) return false;
    if(T_.Gcd(N_tilde) != 1) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    P_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Q_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    sigma_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    int byte_len = l / 8;
    BN e = BN::FromBytesBE(sha512_digest, byte_len);
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    BN R = (s.PowM(N0, N_tilde) * t.PowM(sigma_, N_tilde)) % N_tilde;

    bool ok = true;
    BN left_num;
    BN right_num;

    // s^z1 * t^w1 = A * P^e  mod N_tilde
    left_num = (s.PowM(z1_, N_tilde) * t.PowM(w1_, N_tilde)) % N_tilde;
    right_num = ( A_ * P_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    // s^z2 * t^w2 = B * Q^e  mod N_tilde
    left_num = (s.PowM(z2_, N_tilde) * t.PowM(w2_, N_tilde)) % N_tilde;
    right_num = ( B_ * Q_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    // Q^z1 * t^v = T * R^e  mod N_tilde
    left_num = (Q_.PowM(z1_, N_tilde) * t.PowM(v_, N_tilde)) % N_tilde;
    right_num = ( T_ * R.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool NoSmallFactorProof::ToProtoObject(safeheron::proto::NoSmallFactorProof &proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    std::string str;

    // P
    P_.ToHexStr(str);
    proof.set_p(str);

    // Q
    Q_.ToHexStr(str);
    proof.set_q(str);

    // A
    A_.ToHexStr(str);
    proof.set_a(str);

    // B
    B_.ToHexStr(str);
    proof.set_b(str);

    // T
    T_.ToHexStr(str);
    proof.set_t(str);

    // sigma
    sigma_.ToHexStr(str);
    proof.set_sigma(str);

    // z1
    z1_.ToHexStr(str);
    proof.set_z1(str);

    // z2
    z2_.ToHexStr(str);
    proof.set_z2(str);

    // w1
    w1_.ToHexStr(str);
    proof.set_w1(str);

    // w2
    w2_.ToHexStr(str);
    proof.set_w2(str);

    // v
    v_.ToHexStr(str);
    proof.set_v(str);

    return true;
}

bool NoSmallFactorProof::FromProtoObject(const safeheron::proto::NoSmallFactorProof &proof) {
    bool ok = true;

    // P
    P_ = BN::FromHexStr(proof.p());
    ok = (P_ != 0);
    if (!ok) return false;

    // Q
    Q_ = BN::FromHexStr(proof.q());
    ok = (Q_ != 0);
    if (!ok) return false;

    // A
    A_ = BN::FromHexStr(proof.a());
    ok = (A_ != 0);
    if (!ok) return false;

    // B
    B_ = BN::FromHexStr(proof.b());
    ok = (B_ != 0);
    if (!ok) return false;

    // T
    T_ = BN::FromHexStr(proof.t());
    ok = (T_ != 0);
    if (!ok) return false;

    // sigma
    sigma_ = BN::FromHexStr(proof.sigma());
    ok = (sigma_ != 0);
    if (!ok) return false;

    // z1
    z1_ = BN::FromHexStr(proof.z1());
    ok = (z1_ != 0);
    if (!ok) return false;

    // z2
    z2_ = BN::FromHexStr(proof.z2());
    ok = (z2_ != 0);
    if (!ok) return false;

    // w1
    w1_ = BN::FromHexStr(proof.w1());
    ok = (w1_ != 0);
    if (!ok) return false;

    // w2
    w2_ = BN::FromHexStr(proof.w2());
    ok = (w2_ != 0);
    if (!ok) return false;

    // v
    v_ = BN::FromHexStr(proof.v());
    ok = (v_ != 0);
    if (!ok) return false;

    return true;
}

bool NoSmallFactorProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::NoSmallFactorProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool NoSmallFactorProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::NoSmallFactorProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool NoSmallFactorProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::NoSmallFactorProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool NoSmallFactorProof::FromJsonString(const string &json_str) {
    safeheron::proto::NoSmallFactorProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
