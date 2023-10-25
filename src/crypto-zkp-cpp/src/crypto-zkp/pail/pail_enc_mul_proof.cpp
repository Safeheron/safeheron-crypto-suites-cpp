#include "pail_enc_mul_proof.h"
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

void PailEncMulProof::Prove(const PailEncMulStatement &statement, const PailEncMulWitness &witness){
    const BN &N = statement.N_;
    const BN &NSqr = statement.NSqr_;
    const BN &X = statement.X_;
    const BN &Y = statement.Y_;
    const BN &C = statement.C_;
    const BN &q = statement.q_;

    const BN &x = witness.x_;
    const BN &rho = witness.rho_;
    const BN &rho_x = witness.rho_x_;

    // random
    BN alpha = RandomBNLtCoPrime(N);
    BN r = RandomBNLtCoPrime(N);
    BN s = RandomBNLtCoPrime(N);

    // A = Y^alpha * r^N mod NSqr;
    A_ = ( Y.PowM(alpha, NSqr) * r.PowM(N, NSqr) ) % NSqr;

    // B = ( 1 + N )^alpha * s^N mod NSqr;
    B_ = ( ( N * alpha + 1 ) * s.PowM(N, NSqr) ) % NSqr;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    // z = alpha + e * x
    z_ = e * x + alpha;
    // u = r * rho^e mod N
    u_ = ( r * rho.PowM(e, N) ) % N;
    // v = s * rho_x^e mod N
    v_ = ( s * rho_x.PowM(e, N) ) % N;
}

bool PailEncMulProof::Verify(const PailEncMulStatement &statement) const {
    const BN &N = statement.N_;
    const BN &NSqr = statement.NSqr_;
    const BN &X = statement.X_;
    const BN &Y = statement.Y_;
    const BN &C = statement.C_;
    const BN &q = statement.q_;

    if(N.BitLength() < 2047) return false;

    if(A_.Gcd(N) != BN::ONE) return false;
    if(B_.Gcd(N) != BN::ONE) return false;

    CSHA512 sha512;
    uint8_t sha512_digest[CSHA512::OUTPUT_SIZE];
    string str;
    N.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    X.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    Y.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    C.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    A_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    B_.ToBytesBE(str);
    sha512.Write((const uint8_t *)(str.c_str()), str.length());
    if(salt_.length() > 0) {
        sha512.Write((const uint8_t *)(salt_.c_str()), salt_.length());
    }
    sha512.Finalize(sha512_digest);
    BN e = BN::FromBytesBE(sha512_digest, sizeof(sha512_digest) - 1);
    e = e % q;
    if(sha512_digest[CSHA512::OUTPUT_SIZE - 1] & 0x01) e = e.Neg();

    bool ok = true;
    BN left_num;
    BN right_num;

    // Y^z * u^N = A * C^e     mod NSqr
    left_num = ( Y.PowM(z_, NSqr) * u_.PowM(N, NSqr) ) % NSqr;
    right_num = ( A_ * C.PowM(e, NSqr) ) % NSqr;
    ok = left_num == right_num;
    if(!ok) return false;

    // (1 + N)^z * c^N = B * X^e     mod NSqr
    left_num =( ( N * z_ + 1 ) * v_.PowM(N, NSqr) ) % NSqr;
    right_num = ( B_ * X.PowM(e, NSqr) ) % NSqr;
    ok = left_num == right_num;
    if(!ok) return false;

    return ( left_num == right_num );
}

bool PailEncMulProof::ToProtoObject(safeheron::proto::PailEncMulProof &proof) const {
    string str;

    A_.ToHexStr(str);
    proof.mutable_a()->assign(str);

    B_.ToHexStr(str);
    proof.mutable_b()->assign(str);

    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    u_.ToHexStr(str);
    proof.mutable_u()->assign(str);

    v_.ToHexStr(str);
    proof.mutable_v()->assign(str);

    return true;
}

bool PailEncMulProof::FromProtoObject(const safeheron::proto::PailEncMulProof &proof) {
    bool ok = true;

    A_ = BN::FromHexStr(proof.a());
    ok = A_ != 0;
    if(!ok) return false;

    B_ = BN::FromHexStr(proof.b());
    ok = B_ != 0;
    if(!ok) return false;

    z_ = BN::FromHexStr(proof.z());
    ok = z_ != 0;
    if(!ok) return false;

    u_ = BN::FromHexStr(proof.u());
    ok = u_ != 0;
    if(!ok) return false;

    v_ = BN::FromHexStr(proof.v());
    ok = v_ != 0;
    if(!ok) return false;

    return true;
}

bool PailEncMulProof::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailEncMulProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailEncMulProof::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailEncMulProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailEncMulProof::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailEncMulProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailEncMulProof::FromJsonString(const string &json_str) {
    safeheron::proto::PailEncMulProof proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
