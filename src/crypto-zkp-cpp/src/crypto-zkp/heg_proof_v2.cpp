#include "heg_proof_v2.h"
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
namespace heg {

void HEGProof_V2::Prove(const HEGStatement_V2 &statement, const HEGWitness_V2 &witness) {
    BN a = RandomBNLt(statement.ord_);
    BN b = RandomBNLt(statement.ord_);
    ProveWithR(statement, witness, a, b);
}

void HEGProof_V2::ProveWithR(const HEGStatement_V2 &statement, const HEGWitness_V2 &witness, const BN &a, const BN &b) {
    const curve::CurvePoint &G = statement.G_;
    const curve::CurvePoint &V = statement.V_;
    const curve::CurvePoint &R = statement.R_;
    const curve::CurvePoint &A = statement.A_;
    const curve::CurvePoint &B = statement.B_;
    const safeheron::bignum::BN &ord = statement.ord_;

    const safeheron::bignum::BN &s = witness.s_;
    const safeheron::bignum::BN &l = witness.l_;

    // Alpha = R^a + G^b
    // Beta = A^b
    CurvePoint Alpha = R * a + G * b;
    CurvePoint Beta = A * b;

    // e = H(V || A || B || Alpha || Beta)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    V.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    V.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Beta.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Beta.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);

    BN c = BN::FromBytesBE(sha256_digest, 32);
    c = c % ord;

    // t = a + c * s  mod q
    BN t = (a + c * s) % ord;

    // u = b + c * l  mod q
    BN u = (b + c * l) % ord;

    Alpha_ = Alpha;
    Beta_ = Beta;
    t_ = t;
    u_ = u;
}

bool HEGProof_V2::Verify(const HEGStatement_V2 &statement) const {
    const curve::CurvePoint &G = statement.G_;
    const curve::CurvePoint &V = statement.V_;
    const curve::CurvePoint &R = statement.R_;
    const curve::CurvePoint &A = statement.A_;
    const curve::CurvePoint &B = statement.B_;
    const safeheron::bignum::BN &ord = statement.ord_;

    // e = H(V || A || B || Alpha || Beta)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    V.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    V.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    A.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    B.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha_.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Beta_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Beta_.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);

    BN c = BN::FromBytesBE(sha256_digest, 32);
    c = c % ord;

    bool ok = true;
    CurvePoint left_point;
    CurvePoint right_point;

    // R^t * G^u = Alpha * V^c
    left_point = R * t_ + G * u_;
    right_point = V * c + Alpha_;
    ok = left_point == right_point;
    if(!ok) return false;

    // A^u = Beta * B^c
    left_point = A * u_;
    right_point = Beta_ + B * c;
    ok = left_point == right_point;
    if(!ok) return false;

    return true;
}

bool HEGProof_V2::ToProtoObject(safeheron::proto::HEGProof_V2 &HEGProof_V2) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;

    // Alpha
    ok = Alpha_.ToProtoObject(tmp);
    if (!ok) return false;
    HEGProof_V2.mutable_alpha()->CopyFrom(tmp);

    // Beta
    ok = Beta_.ToProtoObject(tmp);
    if (!ok) return false;
    HEGProof_V2.mutable_beta()->CopyFrom(tmp);

    // t
    std::string str;
    t_.ToHexStr(str);
    HEGProof_V2.set_t(str);

    // res
    u_.ToHexStr(str);
    HEGProof_V2.set_u(str);

    return true;
}

bool HEGProof_V2::FromProtoObject(const safeheron::proto::HEGProof_V2 &HEGProof_V2) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // Alpha
    point = HEGProof_V2.alpha();
    ok = Alpha_.FromProtoObject(point);
    ok = ok && !Alpha_.IsInfinity();
    if (!ok) return false;

    // Beta
    point = HEGProof_V2.beta();
    ok = Beta_.FromProtoObject(point);
    ok = ok && !Beta_.IsInfinity();
    if (!ok) return false;

    // t
    t_ = BN::FromHexStr(HEGProof_V2.t());
    ok = (t_ != 0);
    if (!ok) return false;

    // u
    u_ = BN::FromHexStr(HEGProof_V2.u());
    ok = (u_ != 0);
    if (!ok) return false;

    return true;
}

bool HEGProof_V2::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::HEGProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool HEGProof_V2::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::HEGProof_V2 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool HEGProof_V2::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::HEGProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool HEGProof_V2::FromJsonString(const string &json_str) {
    safeheron::proto::HEGProof_V2 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
