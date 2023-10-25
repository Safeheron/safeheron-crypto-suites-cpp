#include "dln_proof.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/safe_hash256.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
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
namespace dln_proof {

const int ITERATIONS = 128;

void DLNProof::Prove(const BN &N, const BN &h1, const BN &h2, const BN &p, const BN &q, const BN &x) {
    BN pq = p * q;
    std::vector<BN> r_arr;

    for(int i = 0; i < ITERATIONS; ++i){
        BN r = RandomBNLtGcd(pq);
        // alpha = h1^r mod N
        BN alpha = h1.PowM(r, N);
        r_arr.push_back(r);
        alpha_arr_.push_back(alpha);
    }

    // Hash( N || h1 || h2 || alpha_arr_)
    CSafeHash256 sha256;
    uint8_t sha256_digest[CSafeHash256::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h1.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h2.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    for(int i = 0; i < ITERATIONS; ++i) {
        alpha_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
    }
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);

    for(int i = 0; i < ITERATIONS; ++i) {
        bool flag = ((sha256_digest[i/8] >> (i%8)) & 0x01) != 0;
        BN t = ( r_arr[i] + (flag ? x : BN::ZERO) ) % pq;
        t_arr_.push_back(t);
    }
}

bool DLNProof::Verify(const BN &N, const BN &h1, const BN &h2) const {
    if( (alpha_arr_.size() < ITERATIONS) || (t_arr_.size() < ITERATIONS) ) return false;

    if(N <= 1) return false;
    if(h1 <= 1 || h1 >= N) return false;
    if(h2 <= 1 || h2 >= N) return false;
    if(h1 == h2) return false;
    for(int i = 0; i < ITERATIONS; ++i) {
        if(t_arr_[i] <= 1 || t_arr_[i] >= N) return false;
        if(alpha_arr_[i] <= 1 || alpha_arr_[i] >= N) return false;
    }
    if(N.BitLength() < 2046)return false;

    // Hash( N || h1 || h2 || alpha_arr_)
    CSafeHash256 sha256;
    uint8_t sha256_digest[CSafeHash256::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h1.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    h2.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    for(int i = 0; i < ITERATIONS; ++i) {
        alpha_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
    }
    if(salt_.length() > 0) {
        sha256.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha256.Finalize(sha256_digest);

    for(int i = 0; i < ITERATIONS; ++i) {
        bool flag = ((sha256_digest[i/8] >> (i%8)) & 0x01) != 0;
        // left = h1^t_i mod N
        BN left = h1.PowM(t_arr_[i], N);
        // right = alpha_i * (flag ? h2 : 1)
        BN right = (alpha_arr_[i] * ( flag ? h2 : BN::ONE)) % N;
        if(left != right) return false;
    }
    return true;
}

bool DLNProof::ToProtoObject(safeheron::proto::DLNProof &dln_proof) const {
    dln_proof.clear_alpha_arr();
    for(size_t i = 0; i < alpha_arr_.size(); ++i){
        string str;
        alpha_arr_[i].ToHexStr(str);
        dln_proof.add_alpha_arr(str);
    }

    dln_proof.clear_t_arr();
    for(size_t i = 0; i < t_arr_.size(); ++i){
        string str;
        t_arr_[i].ToHexStr(str);
        dln_proof.add_t_arr(str);
    }

    return true;
}

bool DLNProof::FromProtoObject(const safeheron::proto::DLNProof &dln_proof) {
    alpha_arr_.clear();
    t_arr_.clear();

    for(int i = 0; i < dln_proof.alpha_arr_size(); ++i){
        BN alpha = BN::FromHexStr(dln_proof.alpha_arr(i));
        alpha_arr_.push_back(alpha);
    }

    for(int i = 0; i < dln_proof.t_arr_size(); ++i){
        BN t = BN::FromHexStr(dln_proof.t_arr(i));
        t_arr_.push_back(t);
    }

    return true;
}

bool DLNProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::DLNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool DLNProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::DLNProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool DLNProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::DLNProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool DLNProof::FromJsonString(const string &json_str) {
    safeheron::proto::DLNProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
