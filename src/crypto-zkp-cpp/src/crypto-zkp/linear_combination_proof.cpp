#include "linear_combination_proof.h"
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
namespace linear_combination {

void LinearCombinationProof::Prove(const LinearCombinationStatement &statement, const LinearCombinationWitness &witness) {
    BN a = RandomBNLt(statement.ord_);
    BN b = RandomBNLt(statement.ord_);
    ProveWithR(statement, witness, a, b);
}

void LinearCombinationProof::ProveWithR(const LinearCombinationStatement &statement, const LinearCombinationWitness &witness, const BN &a, const BN &b) {
    const curve::CurvePoint &V = statement.V_;
    const curve::CurvePoint &R = statement.R_;
    const curve::CurvePoint &G = statement.G_;
    const safeheron::bignum::BN &ord = statement.ord_;

    const safeheron::bignum::BN &s = witness.s_;
    const safeheron::bignum::BN &l = witness.l_;

    // Alpha = R^a + G^b
    CurvePoint Alpha = R * a + G * b;

    // c = H(V || R || G || Alpha)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    V.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    V.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    R.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    R.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha.y().ToBytes32BE(str);
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
    t_ = t;
    u_ = u;
}

bool LinearCombinationProof::Verify(const LinearCombinationStatement &statement) const {
    const curve::CurvePoint &V = statement.V_;
    const curve::CurvePoint &R = statement.R_;
    const curve::CurvePoint &G = statement.G_;
    const safeheron::bignum::BN &ord = statement.ord_;

    // c = H(V || R || G || Alpha)
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    V.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    V.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    R.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    R.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    G.y().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha_.x().ToBytes32BE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    Alpha_.y().ToBytes32BE(str);
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

    return true;
}

bool LinearCombinationProof::ToProtoObject(safeheron::proto::LinearCombinationProof &LinearCombinationProof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;

    // Alpha
    ok = Alpha_.ToProtoObject(tmp);
    if (!ok) return false;
    LinearCombinationProof.mutable_alpha()->CopyFrom(tmp);

    // t
    std::string str;
    t_.ToHexStr(str);
    LinearCombinationProof.set_t(str);

    // res
    u_.ToHexStr(str);
    LinearCombinationProof.set_u(str);

    return true;
}

bool LinearCombinationProof::FromProtoObject(const safeheron::proto::LinearCombinationProof &LinearCombinationProof) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // Alpha
    point = LinearCombinationProof.alpha();
    ok = Alpha_.FromProtoObject(point);
    ok = ok && !Alpha_.IsInfinity();
    if (!ok) return false;

    // t
    t_ = BN::FromHexStr(LinearCombinationProof.t());
    ok = (t_ != 0);
    if (!ok) return false;

    // u
    u_ = BN::FromHexStr(LinearCombinationProof.u());
    ok = (u_ != 0);
    if (!ok) return false;

    return true;
}

bool LinearCombinationProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::LinearCombinationProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool LinearCombinationProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::LinearCombinationProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool LinearCombinationProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::LinearCombinationProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool LinearCombinationProof::FromJsonString(const string &json_str) {
    safeheron::proto::LinearCombinationProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
