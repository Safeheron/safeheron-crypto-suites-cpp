#include "pail_aff_group_ele_range_proof_v1.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA256;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace pail {

void PailAffGroupEleRangeProof_V1::Prove(const PailAffGroupEleRangeSetUp_V1 &setup, const PailAffGroupEleRangeStatement_V1 &statement, const PailAffGroupEleRangeWitness_V1 &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &h1 = setup.h1_;
    const BN &h2 = setup.h2_;

    const BN &c1 = statement.c1_;
    const BN &c2 = statement.c2_;
    const safeheron::pail::PailPubKey &pail_pub = statement.pail_pub_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const BN &q = statement.q_;

    const BN &x = witness.x_;
    const BN &y = witness.y_;
    const BN &r = witness.r_;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());

    BN q2 = q * q;
    BN q3 = q * q2;
    BN q7 = q * q3 * q3;
    BN q_N_tilde = q * N_tilde;
    BN q2_N_tilde = q * q_N_tilde;
    BN q3_N_tilde = q * q2_N_tilde;

    // random
    BN alpha = RandomBNLt(q3);
    BN rho = RandomBNLt(q_N_tilde);
    BN rho_prime = RandomBNLt(q3_N_tilde);
    BN sigma = RandomBNLt(q_N_tilde);
    BN beta = RandomBNLtCoPrime(pail_pub.n());
    BN gamma = RandomBNLt(q7);
    BN tau = RandomBNLt(q3_N_tilde);

    // u = g^alpha
    u_ = curv->g * alpha;
    // z = h1^x * h2^rho mod N_tilde
    z_ = ( h1.PowM(x, N_tilde) * h2.PowM(rho, N_tilde) ) % N_tilde;
    // z' = h1^alpha * h2^rho_prime mod N_tilde
    z_prime_ = ( h1.PowM(alpha, N_tilde) * h2.PowM(rho_prime, N_tilde) ) % N_tilde;
    // t = h1^y * h2^sigma mod N_tilde
    t_ = ( h1.PowM(y, N_tilde) * h2.PowM(sigma, N_tilde) ) % N_tilde;
    // v = c1^alpha * Gamma^gamma * beta^N mod N^2
    v_ = ( c1.PowM(alpha, pail_pub.n_sqr()) * pail_pub.g().PowM(gamma, pail_pub.n_sqr()) * beta.PowM(pail_pub.n(), pail_pub.n_sqr()) ) % pail_pub.n_sqr();
    // w = h1^gamma * h2^tau mod N_tilde
    w_ = ( h1.PowM(gamma, N_tilde) * h2.PowM(tau, N_tilde) ) % N_tilde;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    pail_pub.n().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_prime_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    t_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    v_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    w_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    // s = r^e * beta mod N
    s_ = ( r.PowM(e, pail_pub.n()) * beta ) % pail_pub.n();
    // s1 = e * x + alpha
    s1_ = e * x + alpha;
    // s2 = e * rho + rho_prime mod N
    s2_ = e * rho + rho_prime;
    // t1 = e * y + gamma
    t1_ = e * y + gamma;
    // t2 = e * sigma + tau;
    t2_ = e * sigma + tau;
}

bool PailAffGroupEleRangeProof_V1::Verify(const PailAffGroupEleRangeSetUp_V1 &setup, const PailAffGroupEleRangeStatement_V1 &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &h1 = setup.h1_;
    const BN &h2 = setup.h2_;

    const BN &c1 = statement.c1_;
    const BN &c2 = statement.c2_;
    const safeheron::pail::PailPubKey &pail_pub = statement.pail_pub_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const BN &q = statement.q_;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());

    BN q2 = q * q;
    BN q3 = q * q2;
    BN q7 = q * q3 * q3;

    if(N_tilde.BitLength() < 2047) return false;

    if(z_.Gcd(N_tilde) != BN::ONE)return false;
    if(z_prime_.Gcd(N_tilde) != BN::ONE)return false;
    if(t_.Gcd(N_tilde) != BN::ONE)return false;
    if(v_.Gcd(pail_pub.n()) != BN::ONE)return false;
    if(w_.Gcd(N_tilde) != BN::ONE)return false;
    if(s_.Gcd(pail_pub.n()) != BN::ONE)return false;

    if(s1_ > q3 || s1_ < BN::ZERO - q3)return false;
    if(t1_ > q7 || t1_ < BN::ZERO - q7)return false;

    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    pail_pub.n().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.x().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    u_.y().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    z_prime_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    t_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    v_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    w_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);
    BN e = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));
    e = e % q;

    bool ok = true;
    CurvePoint left_point;
    CurvePoint right_point;
    BN left_num;
    BN right_num;

    // g^s1 = e*X + u
    left_point = curv->g * s1_;
    right_point = X * e + u_;
    ok = left_point == right_point;
    if(!ok) return false;

    // h1^s1 * h2^s2 = z^e * z_prime    mod N_tilde
    left_num = ( h1.PowM(s1_, N_tilde) * h2.PowM(s2_, N_tilde) ) % N_tilde;
    right_num = ( z_.PowM(e, N_tilde) * z_prime_ ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    // h1^t1 * h2^t2 = t^e * w     mod N_tilde
    left_num = ( h1.PowM(t1_, N_tilde) * h2.PowM(t2_, N_tilde) ) % N_tilde;
    right_num = ( t_.PowM(e, N_tilde) * w_ ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    // c1^s1 * s^N * Gamma^t1 = c2^e * v    mod N^2
    left_num = ( c1.PowM(s1_, pail_pub.n_sqr()) * s_.PowM(pail_pub.n(), pail_pub.n_sqr()) * pail_pub.g().PowM(t1_, pail_pub.n_sqr()) ) % pail_pub.n_sqr();
    right_num = ( c2.PowM(e, pail_pub.n_sqr()) * v_ ) % pail_pub.n_sqr();
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V1::ToProtoObject(safeheron::proto::PailAffGroupEleRangeProof_V1 &proof) const {
    string str;

    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    ok = u_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_u()->CopyFrom(tmp);

    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    z_prime_.ToHexStr(str);
    proof.mutable_z_prime()->assign(str);

    t_.ToHexStr(str);
    proof.mutable_t()->assign(str);

    v_.ToHexStr(str);
    proof.mutable_v()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    s_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    s1_.ToHexStr(str);
    proof.mutable_s1()->assign(str);

    s2_.ToHexStr(str);
    proof.mutable_s2()->assign(str);

    t1_.ToHexStr(str);
    proof.mutable_t1()->assign(str);

    t2_.ToHexStr(str);
    proof.mutable_t2()->assign(str);
    return true;
}

bool PailAffGroupEleRangeProof_V1::FromProtoObject(const safeheron::proto::PailAffGroupEleRangeProof_V1 &proof) {
    bool ok = true;

    // public key
    ok = u_.FromProtoObject(proof.u());
    ok = ok && !u_.IsInfinity();
    if (!ok) return false;

    z_ = BN::FromHexStr(proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    z_prime_ = BN::FromHexStr(proof.z_prime());
    ok = z_prime_ != 0;
    if(!ok) return false;

    t_ = BN::FromHexStr(proof.t());
    ok = t_ != 0;
    if(!ok) return false;

    v_ = BN::FromHexStr(proof.v());
    ok = v_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    s_ = BN::FromHexStr(proof.s());
    ok = s_ != 0;
    if(!ok) return false;

    s1_ = BN::FromHexStr(proof.s1());
    ok = s1_ != 0;
    if(!ok) return false;

    s2_ = BN::FromHexStr(proof.s2());
    ok = s2_ != 0;
    if(!ok) return false;

    t1_ = BN::FromHexStr(proof.t1());
    ok = t1_ != 0;
    if(!ok) return false;

    t2_ = BN::FromHexStr(proof.t2());
    ok = t2_ != 0;
    if(!ok) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V1::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailAffGroupEleRangeProof_V1 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailAffGroupEleRangeProof_V1::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailAffGroupEleRangeProof_V1 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailAffGroupEleRangeProof_V1::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailAffGroupEleRangeProof_V1 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V1::FromJsonString(const string &json_str) {
    safeheron::proto::PailAffGroupEleRangeProof_V1 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
