//
// Created by Sword03 on 2023/9/11.
//

#include "crypto-suites/crypto-commitment/com512.h"
#include "crypto-suites/crypto-bn/rand.h"

namespace safeheron {
namespace commitment {

Com512& Com512::CommitBN(const safeheron::bignum::BN &num){
    std::string buf;
    num.ToBytesBE(buf);
    sha.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

Com512& Com512::CommitCurvePoint(const safeheron::curve::CurvePoint &point){
    std::string buf;
    point.EncodeFull(buf);
    sha.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

Com512& Com512::CommitString(const std::string &str){
    sha.Write(reinterpret_cast<const unsigned char *>(str.c_str()), str.size());
    return *this;
}

Com512& Com512::CommitBytes(const unsigned char *data, size_t len){
    sha.Write(data, len);
    return *this;
}

void Com512::Finalize(const std::string &blind_factor, unsigned char com[OUTPUT_SIZE]){
    // blind factor is included in the part of hash data
    sha.Write(reinterpret_cast<const unsigned char *>(blind_factor.c_str()), blind_factor.size());
    sha.Finalize(com);
}

void Com512::Finalize(const std::string &blind_factor, std::string &com){
    unsigned char t_com[OUTPUT_SIZE];
    Finalize(blind_factor, t_com);
    com.assign((const char *)t_com, OUTPUT_SIZE);
}

Com512& Com512::Reset() {
    sha.Reset();
    return *this;
}


} // safeheron
} // commitment