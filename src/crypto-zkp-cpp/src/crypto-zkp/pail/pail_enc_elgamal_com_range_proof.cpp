#include "pail_enc_elgamal_com_range_proof.h"
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

void PailEncElGamalComRangeProof::Prove(const PailEncElGamalComRangeSetUp &setup, const PailEncElGamalComRangeStatement &statement, const PailEncElGamalComRangeWitness &witness){
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());
    assert(curv);

    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const CurvePoint &A = statement.A_;
    const CurvePoint &B = statement.B_;
    const CurvePoint &X = statement.X_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    const BN &x = witness.x_;
    const BN &rho = witness.rho_;
    const BN &a = witness.a_;
    const BN &b = witness.b_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^l * N_tilde
    const BN limit_mu = (BN::ONE << l) * N_tilde;
    // 2^(l + varepsilon) * N_tilde
    const BN limit_gamma = limit_alpha * N_tilde;

    BN alpha = RandomNegBNInSymInterval(limit_alpha);
    BN mu = RandomNegBNInSymInterval(limit_mu);
    BN r = RandomBNLtCoPrime(N0);
    BN beta = RandomBNLt(q);
    BN gamma = RandomNegBNInSymInterval(limit_gamma);

    // S = s^x * t^mu mod N_tilde
    S_ = ( s.PowM(x, N_tilde) * t.PowM(mu, N_tilde) ) % N_tilde;
    // D = (1 + N0)^alpha * r^N0  mod N0Sqr
    //   = (1 + N0 * alpha) * r^N0 mod N0Sqr
    D_ = ( (N0 * alpha + 1) * r.PowM(N0, N0Sqr) ) % N0Sqr;
    // Y = A^beta * g^alpha
    Y_ = A * beta + curv->g * alpha;
    // Z = g^beta
    Z_ = curv->g * beta;
    // T = s^alpha * t^gamma mod N_tilde
    T_ = ( s.PowM(alpha, N_tilde) * t.PowM(gamma, N_tilde) ) % N_tilde;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    D_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Z_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Z_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    z1_ = e * x + alpha;
    w_ = e * b + beta;
    z2_ = ( r * rho.PowM(e, N0) ) % N0;
    z3_ = e * mu + gamma;
}

bool PailEncElGamalComRangeProof::Verify(const PailEncElGamalComRangeSetUp &setup, const PailEncElGamalComRangeStatement &statement) const {
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(statement.X_.GetCurveType());
    if(!curv) return false;

    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;


    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &C = statement.C_;
    const CurvePoint &A = statement.A_;
    const CurvePoint &B = statement.B_;
    const CurvePoint &X = statement.X_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    if(N_tilde.BitLength() < 2047) return false;
    if(N0.BitLength() < 2047) return false;
    if(N0Sqr.BitLength() < 4094) return false;

    if(S_ % N_tilde == 0) return false;
    if(D_.Gcd(N0) != BN::ONE) return false;
    if(T_ % N_tilde == 0) return false;
    if(z2_.Gcd(N0) != BN::ONE) return false;

    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);

    if(z1_ > limit_alpha || z1_ < BN::ZERO - limit_alpha) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    T_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    D_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y_.y().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Z_.x().ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Z_.y().ToBytesBE(str);
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

    // (1 + N0)^z1 * z2^N0 = D * C^e  mod N0Sqr
    left_num = ( ( N0 * z1_ + 1 ) * z2_.PowM(N0, N0Sqr) ) % N0Sqr;
    right_num = ( D_ * C.PowM(e, N0Sqr) ) % N0Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // A^w * g^z1 = Y * X^e
    left_point = A * w_ + curv->g * z1_;
    right_point = Y_ + X * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // g^w = Z * B^e
    left_point = curv->g * w_;
    right_point = Z_ + B * e;
    ok = left_point == right_point;
    if(!ok) return false;

    // s^z1 * t^z3 = T * S^e  mod N_tilde
    left_num = ( s.PowM(z1_, N_tilde) * t.PowM(z3_, N_tilde) ) % N_tilde;
    right_num = ( T_ * S_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailEncElGamalComRangeProof::ToProtoObject(safeheron::proto::PailEncElGamalComRangeProof &proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;
    string str;

    S_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    D_.ToHexStr(str);
    proof.mutable_d()->assign(str);

    ok = Y_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_y()->CopyFrom(tmp);

    ok = Z_.ToProtoObject(tmp);
    if (!ok) return false;
    proof.mutable_z()->CopyFrom(tmp);

    T_.ToHexStr(str);
    proof.mutable_t()->assign(str);

    z1_.ToHexStr(str);
    proof.mutable_z1()->assign(str);

    w_.ToHexStr(str);
    proof.mutable_w()->assign(str);

    z2_.ToHexStr(str);
    proof.mutable_z2()->assign(str);

    z3_.ToHexStr(str);
    proof.mutable_z3()->assign(str);

    return true;
}

bool PailEncElGamalComRangeProof::FromProtoObject(const safeheron::proto::PailEncElGamalComRangeProof &proof) {
    bool ok = true;

    S_ = BN::FromHexStr(proof.s());
    ok = S_ != 0;
    if(!ok) return false;

    D_ = BN::FromHexStr(proof.d());
    ok = D_ != 0;
    if(!ok) return false;

    ok = Y_.FromProtoObject(proof.y());
    ok = ok && !Y_.IsInfinity();
    if (!ok) return false;

    ok = Z_.FromProtoObject(proof.z());
    ok = ok && !Z_.IsInfinity();
    if (!ok) return false;

    T_ = BN::FromHexStr(proof.t());
    ok = T_ != 0;
    if(!ok) return false;

    z1_ = BN::FromHexStr(proof.z1());
    ok = z1_ != 0;
    if(!ok) return false;

    w_ = BN::FromHexStr(proof.w());
    ok = w_ != 0;
    if(!ok) return false;

    z2_ = BN::FromHexStr(proof.z2());
    ok = z2_ != 0;
    if(!ok) return false;

    z3_ = BN::FromHexStr(proof.z3());
    ok = z3_ != 0;
    if(!ok) return false;

    return true;
}

bool PailEncElGamalComRangeProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailEncElGamalComRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailEncElGamalComRangeProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailEncElGamalComRangeProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailEncElGamalComRangeProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailEncElGamalComRangeProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailEncElGamalComRangeProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailEncElGamalComRangeProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
