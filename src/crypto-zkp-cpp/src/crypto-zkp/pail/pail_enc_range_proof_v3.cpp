#include "pail_enc_range_proof_v3.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-paillier/pail.h"
#include "crypto-encode/base64.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::hash::CSHA256;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
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

static BN SampleRange(const BN &min, const BN &max){
    while(true){
        BN ret = RandomBNLt(max);
        if(ret >= min) return ret;
    }
}

void PailEncRangeProof_V3::Prove(const PailEncRangeStatement_V3 &statement, const PailEncRangeWitness_V3 &witness) {
    assert(CSHA256::OUTPUT_SIZE * 8 >= SECURITY_PARAMETER);
    assert(statement.pail_pub_.n().BitLength() >= 2046);
    const BN l = statement.l_;
    const BN double_l = statement.l_ * 2;
    for (uint32_t i = 0; i < SECURITY_PARAMETER; ++i) {
        // Sample w1 in [l, 2l]
        // w2 = w1 - l
        // Sample r1, r2 in ZN*
        z_arr_.emplace_back(Z_Struct());
        z_arr_[i].w1_ = SampleRange(l, double_l);
        z_arr_[i].w2_ = z_arr_[i].w1_ - l;
        z_arr_[i].r1_ = RandomBNLtCoPrime(statement.pail_pub_.n());
        z_arr_[i].r2_ = RandomBNLtCoPrime(statement.pail_pub_.n());

        // c1 = Enc(pail_pub, w1, r1)
        c1_arr_.emplace_back(BN());
        c1_arr_[i] = statement.pail_pub_.EncryptWithR(z_arr_[i].w1_, z_arr_[i].r1_);

        // c2 = Enc(pail_pub, w2, r2)
        c2_arr_.emplace_back(BN());
        c2_arr_[i] = statement.pail_pub_.EncryptWithR(z_arr_[i].w2_, z_arr_[i].r2_);
    }

    // e = hash(c1_arr[1], c2_arr[1], c1_arr[2], c2_arr[2], ... , c1_arr[n], c2_arr[n] )
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    statement.pail_pub_.n().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    statement.c_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    for (uint32_t i = 0; i < SECURITY_PARAMETER; ++i) {
        c1_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
        c2_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
    }
    sha256.Finalize(sha256_digest);

    // for every bit in e
    for (uint32_t i = 0; i < SECURITY_PARAMETER; ++i) {
        uint8_t byte_index = i / 8;
        uint8_t filter = 1 << (i % 8);
        bool is_bit_set = (sha256_digest[byte_index] & filter) != 0x00;
        if(is_bit_set){
            // if the bit is set, output {j, masked_x, masked_r} and make sure masked_x in [l, 2l]
            // or else output {w1, w2, r1, r2}
            BN tmp = witness.x_ + z_arr_[i].w1_;
            if( l <= tmp && tmp <= double_l){
                z_arr_[i].j_ = 1;
                z_arr_[i].masked_x_ = tmp;
                z_arr_[i].masked_r_ = (witness.r_ * z_arr_[i].r1_) % statement.pail_pub_.n();
            } else{
                z_arr_[i].j_ = 2;
                z_arr_[i].masked_x_ = witness.x_ + z_arr_[i].w2_;
                z_arr_[i].masked_r_ = (witness.r_ * z_arr_[i].r2_) % statement.pail_pub_.n();
            }
        }
    }
}

bool PailEncRangeProof_V3::Verify(const PailEncRangeStatement_V3 &statement) const {
    if(statement.pail_pub_.n().BitLength() < 2046)return false;

    const BN l = statement.l_;
    const BN double_l = statement.l_ * 2;

    // e = hash(c1_arr[1], c2_arr[1], c1_arr[2], c2_arr[2], ... , c1_arr[n], c2_arr[n] )
    CSHA256 sha256;
    uint8_t sha256_digest[CSHA256::OUTPUT_SIZE];
    string str;
    statement.pail_pub_.n().ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    statement.c_.ToBytesBE(str);
    sha256.Write((const uint8_t *)(str.c_str()), str.length());
    for (uint32_t i = 0; i < SECURITY_PARAMETER; ++i) {
        c1_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
        c2_arr_[i].ToBytesBE(str);
        sha256.Write((const uint8_t *)(str.c_str()), str.length());
    }
    sha256.Finalize(sha256_digest);

    bool ok = true;
    for (uint32_t i = 0; i < SECURITY_PARAMETER; ++i) {
        uint8_t byte_index = i / 8;
        uint8_t filter = 1 << (i % 8);
        bool is_bit_set = (sha256_digest[byte_index] & filter) != 0x00;
        if(is_bit_set){
            // if the bit is set, check:
            // - j == 1 || j == 2
            // - Enc(pub, masked_x, masked_r) = HAdd(c, c1) if j = 1
            // - Enc(pub, masked_x, masked_r) = HAdd(c, c2) if j = 2
            // - masked_x in [l, 2l]
            if(z_arr_[i].j_ != 1 && z_arr_[i].j_ != 2) return false;

            if(z_arr_[i].j_ == 1){
                BN c_plus_c1 = statement.pail_pub_.HomomorphicAdd(statement.c_, c1_arr_[i]);
                ok = c_plus_c1 == statement.pail_pub_.EncryptWithR(z_arr_[i].masked_x_, z_arr_[i].masked_r_);
                if(!ok) return false;
            } else{
                BN c_plus_c2 = statement.pail_pub_.HomomorphicAdd(statement.c_, c2_arr_[i]);
                ok = c_plus_c2 == statement.pail_pub_.EncryptWithR(z_arr_[i].masked_x_, z_arr_[i].masked_r_);
                if(!ok) return false;
            }

            ok = (l <= z_arr_[i].masked_x_) && (z_arr_[i].masked_x_ <= double_l);
            if(!ok) return false;
        } else{
            // if the bit is not set, check:
            // - c1 = Enc(pub, w1, r1)
            // - c2 = Enc(pub, w2, r2)
            // - one of the case below is true:
            //   - w1 in [l, 2l] && w2 not in [l, 2l]
            //   - w1 not in [l, 2l] && w2 in [l, 2l]
            ok = c1_arr_[i] == statement.pail_pub_.EncryptWithR(z_arr_[i].w1_, z_arr_[i].r1_);
            if(!ok) return false;

            ok = c2_arr_[i] == statement.pail_pub_.EncryptWithR(z_arr_[i].w2_, z_arr_[i].r2_);
            if(!ok) return false;

            bool w1_in_range = (l <= z_arr_[i].w1_) && (z_arr_[i].w1_ <= double_l);
            bool w1_out_of_range = (l > z_arr_[i].w1_) || (z_arr_[i].w1_ > double_l);

            bool w2_in_range = (l <= z_arr_[i].w2_) && (z_arr_[i].w2_ <= double_l);
            bool w2_out_of_range = (l > z_arr_[i].w2_) || (z_arr_[i].w2_ > double_l);

            ok = (w1_in_range && w2_out_of_range) || (w1_out_of_range && w2_in_range);
            if(!ok) return false;
        }
    }
    return true;
}

bool PailEncRangeProof_V3::ToProtoObject(safeheron::proto::PailEncRangeProof_V3 &proof) const {
    if(c1_arr_.size() < SECURITY_PARAMETER) return false;
    if(c2_arr_.size() < SECURITY_PARAMETER) return false;
    if(z_arr_.size() < SECURITY_PARAMETER) return false;

    for(size_t i = 0; i < SECURITY_PARAMETER; ++i){
        string str;
        c1_arr_[i].ToHexStr(str);
        proof.add_c1_arr(str);
        c2_arr_[i].ToHexStr(str);
        proof.add_c2_arr(str);
        safeheron::proto::PailEncRangeProof_V3_Z *z = proof.add_z_arr();
        if(z_arr_[i].j_ == 0){
            z_arr_[i].w1_.ToHexStr(str);
            z->set_w1(str);
            z_arr_[i].w2_.ToHexStr(str);
            z->set_w2(str);
            z_arr_[i].r1_.ToHexStr(str);
            z->set_r1(str);
            z_arr_[i].r2_.ToHexStr(str);
            z->set_r2(str);
        } else{
            z->set_j(z_arr_[i].j_);
            z_arr_[i].masked_x_.ToHexStr(str);
            z->set_masked_x(str);
            z_arr_[i].masked_r_.ToHexStr(str);
            z->set_masked_r(str);
        }
    }

    return true;
}

bool PailEncRangeProof_V3::FromProtoObject(const safeheron::proto::PailEncRangeProof_V3 &proof) {
    if( (uint32_t)proof.c1_arr_size() < SECURITY_PARAMETER) return false;
    if( (uint32_t)proof.c2_arr_size() < SECURITY_PARAMETER) return false;
    if( (uint32_t)proof.z_arr_size() < SECURITY_PARAMETER) return false;

    safeheron::proto::CurvePoint point;

    for(int i = 0; i < proof.c1_arr_size(); ++i){
        BN c1 = BN::FromHexStr(proof.c1_arr(i));
        c1_arr_.push_back(c1);
        BN c2 = BN::FromHexStr(proof.c2_arr(i));
        c2_arr_.push_back(c2);

        z_arr_.emplace_back(Z_Struct());
        uint32_t j = proof.z_arr(i).j();
        if(j == 0){
            BN num;
            const string &w1_hex = proof.z_arr(i).w1();
            if(w1_hex.empty()) return false;
            num = BN::FromHexStr(w1_hex);
            z_arr_[i].w1_ = num;

            const string &w2_hex = proof.z_arr(i).w2();
            if(w2_hex.empty()) return false;
            num = BN::FromHexStr(w2_hex);
            z_arr_[i].w2_ = num;

            const string &r1_hex = proof.z_arr(i).r1();
            if(r1_hex.empty()) return false;
            num = BN::FromHexStr(r1_hex);
            z_arr_[i].r1_ = num;

            const string &r2_hex = proof.z_arr(i).r2();
            if(r2_hex.empty()) return false;
            num = BN::FromHexStr(r2_hex);
            z_arr_[i].r2_ = num;
        }else{
            z_arr_[i].j_ = j;
            BN num;
            const string &masked_x_hex = proof.z_arr(i).masked_x();
            if(masked_x_hex.empty()) return false;
            num = BN::FromHexStr(masked_x_hex);
            z_arr_[i].masked_x_ = num;

            const string &masked_r_hex = proof.z_arr(i).masked_r();
            if(masked_r_hex.empty()) return false;
            num = BN::FromHexStr(masked_r_hex);
            z_arr_[i].masked_r_ = num;
        }
    }

    return true;
}

bool PailEncRangeProof_V3::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::PailEncRangeProof_V3 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool PailEncRangeProof_V3::FromBase64(const string &b64) {
    bool ok = true;

    string data = base64::DecodeFromBase64(b64);

    safeheron::proto::PailEncRangeProof_V3 proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool PailEncRangeProof_V3::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::PailEncRangeProof_V3 proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool PailEncRangeProof_V3::FromJsonString(const string &json_str) {
    safeheron::proto::PailEncRangeProof_V3 proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
