#include "pail_mul_group_ele_range_proof.h"
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

void PailMulGroupEleRangeProof::Prove(const PailMulGroupEleRangeSetUp &setup, const PailMulGroupEleRangeStatement &statement, const PailMulGroupEleRangeWitness &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const BN &D = statement.D_;
    const CurvePoint &X = statement.X_;
    const CurvePoint &g = statement.g_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    const BN &x = witness.x_;
    const BN &rho = witness.rho_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^(l + varepsilon) * N_tilde
    const BN limit_gamma = (BN::ONE << (l + varepsilon)) * N_tilde;
    // 2^l * N_tilde
    const BN limit_m = (BN::ONE << l) * N_tilde;

    BN alpha = RandomNegBNInSymInterval(limit_alpha);
    BN r = RandomBNLtCoPrime(N0);
    BN gamma = RandomNegBNInSymInterval(limit_gamma);
    BN m = RandomNegBNInSymInterval(limit_m);

    // 公式跟论文不一样
    // A = C^alpha * r^N0  mod N0Sqr
    A_ = ( C.PowM(alpha, N0Sqr) * r.PowM(N0, N0Sqr) ) % N0Sqr;
    // B = g^alpha
    B_ = g * alpha;
    // E = s^alpha * t^gamma mod N_tilde
    E_ = ( s.PowM(alpha, N_tilde) * t.PowM(gamma, N_tilde) ) % N_tilde;
    // S = s^x * t^m mod N_tilde
    S_ = ( s.PowM(x, N_tilde) * t.PowM(m, N_tilde) ) % N_tilde;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    E_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    z1_ = alpha + e * x;
    z2_ = gamma + e * m;
    w_ = ( r * rho.PowM(e, N0) ) % N0;
}

bool PailMulGroupEleRangeProof::Verify(const PailMulGroupEleRangeSetUp &setup, const PailMulGroupEleRangeStatement &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const BN &D = statement.D_;
    const CurvePoint &X = statement.X_;
    const CurvePoint &g = statement.g_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    if(N_tilde.BitLength() < 2047) return false;
    if(N0.BitLength() < 2047) return false;

    if(A_.Gcd(N0) != BN::ONE) return false;
    if(E_ % N_tilde == BN::ZERO) return false;
    if(S_ % N_tilde == BN::ZERO) return false;
    if(w_.Gcd(N0) != BN::ONE) return false;

    const BN limit_alpha = BN::ONE << (l + varepsilon);

    if(z1_ > limit_alpha || z1_ < (BN::ZERO - limit_alpha) ) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    E_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
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

    // C^z1 * w^N0 = A * D^e  mod N0Sqr
    left_num = ( C.PowM(z1_, N0Sqr) * w_.PowM(N0, N0Sqr) ) % N0Sqr;
    right_num = ( A_ * D.PowM(e, N0Sqr) ) % N0Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // g^z1 = Bx * X^e
    left_point = g * z1_;
    right_point = B_ + X * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // s^z1 * t^z2 = E * S^e  mod N_tilde
    left_num = ( s.PowM(z1_, N_tilde) * t.PowM(z2_, N_tilde) ) % N_tilde;
    right_num = ( E_ * S_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailMulGroupEleRangeProof::ToProtoObject(safeheron::proto::PailMulGroupEleRangeProof &proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    string str;

    A_.ToHexStr(str);
    proof.mutable_a()->assign(str);

    ok = B_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_b()->CopyFrom(tmp);

    E_.ToHexStr(str);
    proof.mutable_e()->assign(str);

    S_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    z1_.ToHexStr(str);
    proof.mutable_z1()->assign(str);

    z2_.ToHexStr(str);
    proof.mutable_z2()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    return true;
}

bool PailMulGroupEleRangeProof::FromProtoObject(const safeheron::proto::PailMulGroupEleRangeProof &proof) {
    bool ok = true;

    A_ = BN::FromHexStr(proof.a());
    ok = A_ != 0;
    if(!ok) return false;

    ok = B_.FromProtoObject(proof.b());
    ok = ok && !B_.IsInfinity();
    if (!ok) return false;

    E_ = BN::FromHexStr(proof.e());
    ok = E_ != 0;
    if(!ok) return false;

    S_ = BN::FromHexStr(proof.s());
    ok = S_ != 0;
    if(!ok) return false;

    z1_ = BN::FromHexStr(proof.z1());
    ok = z1_ != 0;
    if(!ok) return false;

    z2_ = BN::FromHexStr(proof.z2());
    ok = z2_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    return true;
}

bool PailMulGroupEleRangeProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailMulGroupEleRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailMulGroupEleRangeProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailMulGroupEleRangeProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailMulGroupEleRangeProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailMulGroupEleRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailMulGroupEleRangeProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailMulGroupEleRangeProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
