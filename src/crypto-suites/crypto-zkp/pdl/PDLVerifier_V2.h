#ifndef SAFEHERONCRYPTOSUITES_PDLVERIFIER_V2_H
#define SAFEHERONCRYPTOSUITES_PDLVERIFIER_V2_H

#include <string>
#include "pdl_message.h"
#include "pdl_common.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-bn/bn.h"

namespace safeheron{
namespace zkp {
namespace pdl {

class PDLVerifier_V2 {
public:
    PDLVerifier_V2(): is_initialized_(false) {}
    void SetSalt(const std::string &salt) { salt_ = salt; }
    bool Init(const PDLStatement &statement);
    bool Step1(PDLVMessage1 &v_message1);
    bool Step2(const PDLPMessage1 &p_message1, PDLVMessage2 &v_message2);
    bool Accept(const PDLPMessage2 &p_message2) const;
private:
    safeheron::bignum::BN c_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::curve::CurvePoint Q_prime_;
    std::string commit_Q_hat_;
    safeheron::bignum::BN a_;
    safeheron::bignum::BN b_;
    std::string blind_a_b_;

    std::string salt_;
private:
    bool is_initialized_;
};

}
}
}


#endif //SAFEHERONCRYPTOSUITES_PDLVERIFIER_V2_H