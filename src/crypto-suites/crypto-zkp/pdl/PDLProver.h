#ifndef SAFEHERONCRYPTOSUITES_PDLPROVER_H
#define SAFEHERONCRYPTOSUITES_PDLPROVER_H


#include <string>
#include "pdl_message.h"
#include "pdl_common.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"

namespace safeheron{
namespace zkp {
namespace pdl {

class PDLProver {
public:
    PDLProver(): is_initialized_(false) {}
    void SetSalt(const std::string &salt) { salt_ = salt; }
    bool Init(const PDLStatement &statement, const PDLWitness &witness);
    bool Step1(const PDLVMessage1 &v_message1, PDLPMessage1 &p_message1);
    bool Step2(const PDLVMessage2 &v_message2, PDLPMessage2 &p_message2);
private:
    safeheron::bignum::BN x_;
    safeheron::bignum::BN r_;
    safeheron::pail::PailPrivKey pail_priv_;
    safeheron::bignum::BN c_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::bignum::BN c1_; // c'
    std::string c2_; // c''
    safeheron::bignum::BN alpha_;
    safeheron::curve::CurvePoint Q_hat_;
    std::string blind_Q_hat_;

    std::string salt_;
private:
    bool is_initialized_;
};

}
}
}




#endif //SAFEHERONCRYPTOSUITES_PDLPROVER_H