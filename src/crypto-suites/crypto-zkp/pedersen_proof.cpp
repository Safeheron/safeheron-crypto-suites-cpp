#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/exception/located_exception.h"
#include "crypto-suites/crypto-zkp/pedersen_proof.h"
#include "crypto-suites/common/custom_assert.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::hash::CSafeHash256;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using namespace safeheron::encode;
using namespace safeheron::rand;

namespace safeheron{
namespace zkp {
namespace pedersen_proof {

void PedersenProof::Prove(const PedersenStatement &statement, const PedersenWitness &witness) {
    const safeheron::curve::Curve * curv = curve::GetCurveParam(statement.G_.GetCurveType());
    ASSERT_THROW(curv);
    BN a = safeheron::rand::RandomBNLt(curv->n);
    BN b = safeheron::rand::RandomBNLt(curv->n);
    ProveWithR(statement, witness, a, b);
}

void PedersenProof::ProveWithR(const PedersenStatement &statement,
                               const PedersenWitness &witness,
                               const safeheron::bignum::BN &a_lt_curveN,
                               const safeheron::bignum::BN &b_lt_curveN) {
    const safeheron::curve::Curve * curv = curve::GetCurveParam(statement.G_.GetCurveType());
    ASSERT_THROW(curv);

    // Alpha = a*G + b*H
    curve::CurvePoint A1 = statement.G_ * a_lt_curveN;
    curve::CurvePoint A2 = statement.H_ * b_lt_curveN;
    curve::CurvePoint Alpha = A1 + A2;

    // c = H( Salt || Alpha || T || G || H)
    CSafeHash256 sha256;
    uint8_t sha256_digest[CSafeHash256::OUTPUT_SIZE];
    string str;
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    // Alpha
    Alpha.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // T
    statement.T_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // G
    statement.G_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // H
    statement.H_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    sha256.Finalize(sha256_digest);

    BN c = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));

    // t = a + c * sigma mod q
    ASSERT_THROW(witness.sigma_ != 0);
    BN t = (a_lt_curveN + c * witness.sigma_) % curv->n;

    // u = b + c * l mod q
    ASSERT_THROW(witness.l_ != 0);
    BN u = (b_lt_curveN + c * witness.l_) % curv->n;

    Alpha_ = Alpha;
    t_ = t;
    u_ = u;
}

bool PedersenProof::Verify(const PedersenStatement &statement) const {
    // T = sigma*G + l*H
    // Alpha = a*G + b*H
    // t = (a + c * sigma) % q
    // u = (b + c * l) % q

    // c = H( Salt || Alpha || T || G || H)
    CSafeHash256 sha256;
    uint8_t sha256_digest[CSafeHash256::OUTPUT_SIZE];
    string str;
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    // Alpha
    Alpha_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // T
    statement.T_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // G
    statement.G_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    // H
    statement.H_.EncodeFull(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    sha256.Finalize(sha256_digest);

    BN c = BN::FromBytesBE(sha256_digest, sizeof(sha256_digest));

    // left = t*G + u*H
    curve::CurvePoint left = statement.G_ * t_ + statement.H_ * u_;
    // right = Alpha + c * T
    curve::CurvePoint right = Alpha_ + statement.T_ * c;
    return left == right;
}

bool PedersenProof::ToProtoObject(safeheron::proto::PedersenProof &pedersen_proof) const {
    bool ok = true;
    safeheron::proto::CurvePoint tmp;

    // Alpha
    ok = Alpha_.ToProtoObject(tmp);
    if (!ok) return false;
    pedersen_proof.mutable_alpha()->CopyFrom(tmp);

    // t
    std::string str;
    t_.ToHexStr(str);
    pedersen_proof.set_t(str);

    // res
    u_.ToHexStr(str);
    pedersen_proof.set_u(str);

    return true;
}

bool PedersenProof::FromProtoObject(const safeheron::proto::PedersenProof &pedersen_proof) {
    bool ok = true;
    safeheron::proto::CurvePoint point;
    // Alpha
    point = pedersen_proof.alpha();
    ok = Alpha_.FromProtoObject(point);
    ok = ok && !Alpha_.IsInfinity();
    if (!ok) return false;

    // t
    t_ = BN::FromHexStr(pedersen_proof.t());
    ok = (t_ != 0);
    if (!ok) return false;

    // u
    u_ = BN::FromHexStr(pedersen_proof.u());
    ok = (u_ != 0);
    if (!ok) return false;

    return true;
}

bool PedersenProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PedersenProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PedersenProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PedersenProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PedersenProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PedersenProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PedersenProof::FromJsonString(const string &json_str) {
    safeheron::proto::PedersenProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
