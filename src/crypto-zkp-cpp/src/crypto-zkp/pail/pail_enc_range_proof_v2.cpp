#include "pail_enc_range_proof_v2.h"
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

void PailEncRangeProof_V2::Prove(const PailEncRangeSetUp_V2 &setup, const PailEncRangeStatement_V2 &statement, const PailEncRangeWitness_V2 &witness){
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &K = statement.K_;
    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    const BN &k = witness.k_;
    const BN &rho = witness.rho_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);
    // 2^l * N_tilde
    const BN limit_mu = (BN::ONE << l) * N_tilde;
    // 2^(l + varepsilon) * N_tilde
    const BN limit_gamma = ( BN::ONE << (l + varepsilon) ) * N_tilde;

    BN alpha = RandomNegBNInSymInterval(limit_alpha);
    BN mu = RandomNegBNInSymInterval(limit_mu);
    BN r = RandomBNLtCoPrime(N0);
    BN gamma = RandomNegBNInSymInterval(limit_gamma);

    // S = s^k * t^mu mod N_tilde
    S_ = ( s.PowM(k, N_tilde) * t.PowM(mu, N_tilde) ) % N_tilde;
    // A = (1 + N0)^alpha * r^N0  mod N0Sqr
    //   = (1 + N0 * alpha) * r^N0 mod N0Sqr
    A_ = ( (N0 * alpha + 1) * r.PowM(N0, N0Sqr) ) % N0Sqr;
    // C = s^alpha * t^gamma mod N_tilde
    C_ = ( s.PowM(alpha, N_tilde) * t.PowM(gamma, N_tilde) ) % N_tilde;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    K.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    z1_ = e * k + alpha;
    z2_ = ( r * rho.PowM(e, N0) ) % N0;
    z3_ = e * mu + gamma;
}

bool PailEncRangeProof_V2::Verify(const PailEncRangeSetUp_V2 &setup, const PailEncRangeStatement_V2 &statement) const {
    const BN &N_tilde = setup.N_tilde_;
    const BN &s = setup.s_;
    const BN &t = setup.t_;

    const BN &K = statement.K_;
    const BN &N0 = statement.N0_;
    const BN &N0Sqr = statement.N0Sqr_;
    const BN &q = statement.q_;
    const uint32_t l = statement.l_;
    const uint32_t varepsilon = statement.varepsilon_;

    // limitation
    // 2^(l + varepsilon)
    const BN limit_alpha = BN::ONE << (l + varepsilon);

    if(N_tilde.BitLength() < 2047) return false;

    if( S_ % N_tilde == 0 ) return false;
    if( A_.Gcd(N0) != BN::ONE ) return false;
    if( C_ % N_tilde == 0 ) return false;
    if( z2_.Gcd(N0) != BN::ONE ) return false;

    if(z1_ > limit_alpha || z1_ < BN::ZERO - limit_alpha) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N0.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    K.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    S_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C_.ToBytesBE(str);
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
    BN left_num;
    BN right_num;

    // (1 + N0)^z1 * z2^N0 = A * K^e  mod N0Sqr
    left_num = ( ( N0 * z1_ + 1 ) * z2_.PowM(N0, N0Sqr) ) % N0Sqr;
    right_num = ( A_ * K.PowM(e, N0Sqr) ) % N0Sqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // s^z1 * t^z3 = C * S^e  mod N_tilde
    left_num = ( s.PowM(z1_, N_tilde) * t.PowM(z3_, N_tilde) ) % N_tilde;
    right_num = ( C_ * S_.PowM(e, N_tilde) ) % N_tilde;
    ok = left_num == right_num;
    if(!ok) return false;

    return true;
}

bool PailEncRangeProof_V2::ToProtoObject(safeheron::proto::PailEncRangeProof_V2 &proof) const {
    string str;
    S_.ToHexStr(str);
    proof.mutable_s()->assign(str);

    A_.ToHexStr(str);
    proof.mutable_a()->assign(str);

    C_.ToHexStr(str);
    proof.mutable_c()->assign(str);

    z1_.ToHexStr(str);
    proof.mutable_z1()->assign(str);

    z2_.ToHexStr(str);
    proof.mutable_z2()->assign(str);

    z3_.ToHexStr(str);
    proof.mutable_z3()->assign(str);

    return true;
}

bool PailEncRangeProof_V2::FromProtoObject(const safeheron::proto::PailEncRangeProof_V2 &proof) {
    bool ok = true;

    S_ = BN::FromHexStr(proof.s());
    ok = S_ != 0;
    if(!ok) return false;

    A_ = BN::FromHexStr(proof.a());
    ok = A_ != 0;
    if(!ok) return false;

    C_ = BN::FromHexStr(proof.c());
    ok = C_ != 0;
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

    return true;
}

bool PailEncRangeProof_V2::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailEncRangeProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailEncRangeProof_V2::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailEncRangeProof_V2 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailEncRangeProof_V2::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailEncRangeProof_V2 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailEncRangeProof_V2::FromJsonString(const string &json_str) {
    safeheron::proto::PailEncRangeProof_V2 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
