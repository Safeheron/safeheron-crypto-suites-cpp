#include "two_dln_proof.h"
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
namespace dln_proof {

const int ITERATIONS = 128;

void GenerateN_tilde(safeheron::bignum::BN &N_tilde, safeheron::bignum::BN &h1, safeheron::bignum::BN &h2, safeheron::bignum::BN &p, safeheron::bignum::BN &q, safeheron::bignum::BN &alpha, safeheron::bignum::BN &beta){
    const uint32_t PRIME_BITS = 1024;
    BN P = safeheron::rand::RandomSafePrime(PRIME_BITS);
    BN Q = safeheron::rand::RandomSafePrime(PRIME_BITS);
    N_tilde = P * Q;

    p = (P-1)/2;
    q = (Q-1)/2;
    BN pq = p * q;
    BN f = safeheron::rand::RandomBNLtGcd(N_tilde);
    alpha = safeheron::rand::RandomBNLtGcd(N_tilde);
    beta = alpha.InvM(pq);

    h1 = ( f * f ) % N_tilde;
    h2 = h1.PowM(alpha, N_tilde);
}


void TwoDLNProof::Prove(const BN &N, const BN &h1, const BN &h2, const BN &p, const BN &q, const BN &alpha, const BN &beta) {
    dln_proof_1_.SetSalt(salt_);
    dln_proof_1_.Prove(N, h1, h2, p, q, alpha);
    dln_proof_2_.SetSalt(salt_);
    dln_proof_2_.Prove(N, h2, h1, p, q, beta);
}

bool TwoDLNProof::Verify(const BN &N, const BN &h1, const BN &h2) const {
    return dln_proof_1_.Verify(N, h1, h2) && dln_proof_2_.Verify(N, h2, h1);
}

bool TwoDLNProof::ToProtoObject(safeheron::proto::TwoDLNProof &two_dln_proof) const {
    bool ok = true;

    safeheron::proto::DLNProof dln_proof;
    ok = dln_proof_1_.ToProtoObject(dln_proof);
    if (!ok) return false;
    two_dln_proof.mutable_dln_proof_1()->CopyFrom(dln_proof);

    ok = dln_proof_2_.ToProtoObject(dln_proof);
    if (!ok) return false;
    two_dln_proof.mutable_dln_proof_2()->CopyFrom(dln_proof);

    return true;
}

bool TwoDLNProof::FromProtoObject(const safeheron::proto::TwoDLNProof &two_dln_proof) {
    bool ok = true;

    ok = dln_proof_1_.FromProtoObject(two_dln_proof.dln_proof_1());
    if (!ok) return false;

    ok = dln_proof_2_.FromProtoObject(two_dln_proof.dln_proof_2());
    if (!ok) return false;

    return true;
}

bool TwoDLNProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::TwoDLNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TwoDLNProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::TwoDLNProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TwoDLNProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::TwoDLNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool TwoDLNProof::FromJsonString(const string &json_str) {
    safeheron::proto::TwoDLNProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
