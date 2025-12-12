#include "crypto-suites/crypto-commitment/com256.h"
#include "crypto-suites/common/bytes_comparison.h"
using safeheron::common::BytesEqual;
namespace safeheron {
namespace commitment {

HashCommit256& HashCommit256::UpdateBN(const safeheron::bignum::BN &num){
    std::string buf;
    num.ToBytesBE(buf);
    sha_.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

HashCommit256& HashCommit256::UpdateCurvePoint(const safeheron::curve::CurvePoint &point){
    std::string buf;
    point.EncodeFull(buf);
    sha_.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

HashCommit256& HashCommit256::UpdateString(const std::string &str){
    sha_.Write(reinterpret_cast<const unsigned char *>(str.c_str()), str.size());
    return *this;
}

HashCommit256& HashCommit256::UpdateBytes(const unsigned char *data, size_t len){
    sha_.Write(data, len);
    return *this;
}

void HashCommit256::Commit(const std::string &blind_factor, unsigned char commitment[OUTPUT_SIZE]){
    sha_.Write(reinterpret_cast<const unsigned char *>(blind_factor.c_str()), blind_factor.size());
    sha_.Finalize(commitment);
}

std::string HashCommit256::Commit(const std::string &blind_factor){
    unsigned char com[OUTPUT_SIZE];
    sha_.Write(reinterpret_cast<const unsigned char *>(blind_factor.c_str()), blind_factor.size());
    sha_.Finalize(com);
    return std::string((const char *)com, OUTPUT_SIZE);
}

bool HashCommit256::OpenAndVerify(const std::string &blind_factor, const std::string &commitment) {
    unsigned char com[OUTPUT_SIZE];
    sha_.Write(reinterpret_cast<const unsigned char *>(blind_factor.c_str()), blind_factor.size());
    sha_.Finalize(com);
    return BytesEqual(commitment, com, OUTPUT_SIZE);
}

bool HashCommit256::OpenAndVerify(const std::string &blind_factor, const unsigned char commitment[OUTPUT_SIZE]) {
    if (!commitment) return false;
    unsigned char com[OUTPUT_SIZE];
    sha_.Write(reinterpret_cast<const unsigned char *>(blind_factor.c_str()), blind_factor.size());
    sha_.Finalize(com);
    return (memcmp(commitment, com, OUTPUT_SIZE) == 0);
}

HashCommit256& HashCommit256::Reset() {
    sha_.Reset();
    return *this;
}

} // safeheron
} // commitment