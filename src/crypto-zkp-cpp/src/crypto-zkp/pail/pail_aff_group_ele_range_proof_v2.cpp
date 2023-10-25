#include "pail_aff_group_ele_range_proof_v2.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha512.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
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
namespace pail {

void PailAffGroupEleRangeProof_V2::Prove(const PailAffGroupEleRangeSetUp_V2 &setup, const PailAffGroupEleRangeStatement_V2 &statement, const PailAffGroupEleRangeWitness_V2 &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &N1 = statement.N1_;
    const BN &N1Sqr = statement.N1Sqr_;
    const BN &C = statement.C_;
    const BN &D = statement.D_;
    const BN &Y = statement.Y_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t l_prime = statement.l_prime_;
    const uint32_t varepsilon = statement.varepsilon_;

    const BN &x = witness.x_;
    const BN &y = witness.y_;
    const BN &rho = witness.rho_;
    const BN &rho_y = witness.rho_y_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^(l' + varepsilon)
    const BN limit_beta = BN::ONE << (l_prime + varepsilon);
    // 2^(l + varepsilon) * N_tilde
    const BN limit_gamma = ( BN::ONE << (l + varepsilon) ) * N_tilde;
    // 2^l * N_tilde
    const BN limit_m = (BN::ONE << l) * N_tilde;
    // 2^(l + varepsilon) * N_tilde
    const BN &limit_delta = limit_gamma;
    // 2^l * N_tilde
    const BN &limit_mu = limit_m;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());

    // random
    BN alpha = RandomNegBNInSymInterval(limit_alpha);
    BN beta = RandomNegBNInSymInterval(limit_beta);
    BN r = RandomBNLtCoPrime(N0);
    BN ry = RandomBNLtCoPrime(N1);
    BN gamma = RandomNegBNInSymInterval(limit_gamma);
    BN m = RandomNegBNInSymInterval(limit_m);
    BN delta = RandomNegBNInSymInterval(limit_delta);
    BN mu = RandomNegBNInSymInterval(limit_mu);

    // A = C^alpha * (1 + N0)^beta * r^N0  mod N0^2
    //   = C^alpha * (1 + N0 * beta) * r^N0  mod N0^2
    A_ = ( C.PowM(alpha, N0Sqr) * ( N0 * beta + 1 ) * r.PowM(N0, N0Sqr) ) % N0Sqr;
    // Bx = g^alpha
    Bx_ = curv->g * alpha;
    // By = (1 + N1)^beta * ry^N1  mod N1^2
    By_ = ( ( N1 * beta + 1 ) * ry.PowM(N1, N1Sqr) ) % N1Sqr;
    // E = s^alpha * t^gamma mod N_tilde
    E_ = ( s.PowM(alpha, N_tilde) * t.PowM(gamma, N_tilde) ) % N_tilde;
    // S = s^x * t^m mod N_tilde
    S_ = ( s.PowM(x, N_tilde) * t.PowM(m, N_tilde) ) % N_tilde;
    // F = s^beta * t^delta mod N_tilde
    F_ = ( s.PowM(beta, N_tilde) * t.PowM(delta, N_tilde) ) % N_tilde;
    // T = s^y * t^mu mod N_tilde
    T_ = ( s.PowM(y, N_tilde) * t.PowM(mu, N_tilde) ) % N_tilde;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N1.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Bx_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Bx_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    By_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    E_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    F_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    // z1 = e * x + alpha
    z1_ = e * x + alpha;
    // z2 = e * y + beta
    z2_ = e * y + beta;
    // z3 = e * m + gamma
    z3_ = e * m + gamma;
    // z4 = e * mu + delta
    z4_ = e * mu + delta;
    // w = r * rho^e   mod N0
    w_ = ( r * rho.PowM(e, N0) ) % N0;
    // wy = ry * rho_y^e   mode N1
    wy_ = ( ry * rho_y.PowM(e, N1) ) % N1;
}

bool PailAffGroupEleRangeProof_V2::Verify(const PailAffGroupEleRangeSetUp_V2 &setup, const PailAffGroupEleRangeStatement_V2 &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &N1 = statement.N1_;
    const BN &N1Sqr = statement.N1Sqr_;
    const BN &C = statement.C_;
    const BN &D = statement.D_;
    const BN &Y = statement.Y_;
    const safeheron::curve::CurvePoint &X = statement.X_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t l_prime = statement.l_prime_;
    const uint32_t varepsilon = statement.varepsilon_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^(l' + varepsilon)
    const BN limit_beta = BN::ONE << (l_prime + varepsilon);
    // 2^(l + varepsilon) * N_tilde
    const BN limit_gamma = ( BN::ONE << (l + varepsilon) ) * N_tilde;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());

    if(N_tilde.BitLength() < 2047) return false;

    if(A_.Gcd(N0) != BN::ONE) return false;
    if(By_.Gcd(N1) != BN::ONE) return false;
    if(E_ % N_tilde == BN::ZERO) return false;
    if(S_ % N_tilde == BN::ZERO) return false;
    if(F_ % N_tilde == BN::ZERO) return false;
    if(T_ % N_tilde == BN::ZERO) return false;
    if(w_.Gcd(N0) != BN::ONE) return false;
    if(wy_.Gcd(N1) != BN::ONE) return false;

    if(z1_ > limit_alpha || z1_ < BN::ZERO - limit_alpha)return false;
    if(z2_ > limit_beta || z2_ < BN::ZERO - limit_beta)return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    N1.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Bx_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Bx_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    By_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    E_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    F_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    bool ok = true;
    CurvePoint left_point;
    CurvePoint right_point;
    BN left_num;
    BN right_num;

    // C^z1 * (1 + N0)^z2 * w^N0 = A * D^e    mod N0^2
    left_num = ( C.PowM(z1_, N0Sqr) * (N0 * z2_ + 1) * w_.PowM(N0, N0Sqr) ) % N0Sqr;
    right_num = ( A_ * D.PowM(e, N0Sqr) ) % N0Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // g^z1 = Bx * X^e
    left_point = curv->g * z1_;
    right_point = Bx_ + X * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // (1 + N1)^z2 * wy^N1 = By * Y^e    mod N1^2
    left_num = ( (N1 * z2_ + 1) * wy_.PowM(N1, N1Sqr) ) % N1Sqr;
    right_num = ( By_ * Y.PowM(e, N1Sqr) ) % N1Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // s^z1 * t^z3 = E * S^e    mod N_tilde
    left_num = ( s.PowM(z1_, N_tilde) * t.PowM(z3_, N_tilde) ) % N_tilde;
    right_num = ( E_ * S_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    // s^z2 * t^z4 = F * T^e    mod N_tilde
    left_num = ( s.PowM(z2_, N_tilde) * t.PowM(z4_, N_tilde) ) % N_tilde;
    right_num = ( F_ * T_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V2::ToProtoObject(safeheron::proto::PailAffGroupEleRangeProof_V2 &proof) const {
    string str;

    S_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    T_.ToHexStr(str);
    proof.mutable_t()->assign(str);

    A_.ToHexStr(str);
    proof.mutable_a()->assign(str);

    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    ok = Bx_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_bx()->CopyFrom(tmp);

    By_.ToHexStr(str);
    proof.mutable_by()->assign(str);

    E_.ToHexStr(str);
    proof.mutable_e()->assign(str);

    F_.ToHexStr(str);
    proof.mutable_f()->assign(str);

    z1_.ToHexStr(str);
    proof.mutable_z1()->assign(str);

    z2_.ToHexStr(str);
    proof.mutable_z2()->assign(str);

    z3_.ToHexStr(str);
    proof.mutable_z3()->assign(str);

    z4_.ToHexStr(str);
    proof.mutable_z4()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    wy_.ToHexStr(str);
    proof.mutable_wy()->assign(str);

    return true;
}

bool PailAffGroupEleRangeProof_V2::FromProtoObject(const safeheron::proto::PailAffGroupEleRangeProof_V2 &proof) {
    bool ok = true;

    S_ = BN::FromHexStr(proof.s());
    ok = S_ != 0;
    if(!ok) return false;

    T_ = BN::FromHexStr(proof.t());
    ok = T_ != 0;
    if(!ok) return false;

    A_ = BN::FromHexStr(proof.a());
    ok = A_ != 0;
    if(!ok) return false;

    // public key
    ok = Bx_.FromProtoObject(proof.bx());
    ok = ok && !Bx_.IsInfinity();
    if (!ok) return false;

    By_ = BN::FromHexStr(proof.by());
    ok = By_ != 0;
    if(!ok) return false;

    E_ = BN::FromHexStr(proof.e());
    ok = E_ != 0;
    if(!ok) return false;

    F_ = BN::FromHexStr(proof.f());
    ok = F_ != 0;
    if(!ok) return false;

    z1_ = BN::FromHexStr(proof.z1());
    ok = z1_ != 0;
    if(!ok) return false;

    z2_ = BN::FromHexStr(proof.z2());
    ok = z2_ != 0;
    if(!ok) return false;

    z3_ = BN::FromHexStr(proof.z3());
    ok = z3_ != 0;
    if(!ok) return false;

    z4_ = BN::FromHexStr(proof.z4());
    ok = z4_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    wy_ = BN::FromHexStr(proof.wy());
    ok = wy_ != 0;
    if(!ok) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V2::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailAffGroupEleRangeProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailAffGroupEleRangeProof_V2::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailAffGroupEleRangeProof_V2 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailAffGroupEleRangeProof_V2::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailAffGroupEleRangeProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailAffGroupEleRangeProof_V2::FromJsonString(const string &json_str) {
    safeheron::proto::PailAffGroupEleRangeProof_V2 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
