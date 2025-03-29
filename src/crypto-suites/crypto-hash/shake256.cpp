#include <assert.h>
#include <string.h>

#include "openssl/core_names.h" // OSSL_DIGEST_PARAM_XOFLEN
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/provider.h" // OSSL_PROVIDER_load

#include "crypto-suites/crypto-hash/shake256.h"
#include "crypto-suites/crypto-hash/shake_imp.h"

namespace safeheron {
namespace hash {

CShake256::CShake256(size_t digest_size) {
    shake_imp_ptr_ = new CShakeImp(digest_size, CShakeImp::CShakeType::Shake256);
    if (!shake_imp_ptr_->Init()) {
        delete shake_imp_ptr_;
        throw std::runtime_error(std::string("CShake256 Constructor Failed : !shake_imp_ptr_->Init() : ErrorCode ") +
                                 std::to_string(static_cast<int>(shake_imp_ptr_->GetLastError())));
    }
}

CShake256::~CShake256() {
    if (!shake_imp_ptr_) {
        delete shake_imp_ptr_;
    }
}

CShake256& CShake256::Write(const unsigned char* data, size_t len) {
    if (!shake_imp_ptr_->Write(data, len)) {
        throw std::runtime_error(std::string("CShake256 Write Failed : !shake_imp_ptr_->Write(data, len) : ErrorCode ") +
                                 std::to_string(static_cast<int>(shake_imp_ptr_->GetLastError())));
    }
    return *this;
}

std::vector<uint8_t> CShake256::Finalize() {
    if (!shake_imp_ptr_->Finalize()) {
        throw std::runtime_error(std::string("CShake256 Finalize Failed : shake_imp_ptr_->Finalize() : ErrorCode ") +
            std::to_string(static_cast<int>(shake_imp_ptr_->GetLastError())));
    }
    if (shake_imp_ptr_->GetDigest().empty()) {
        throw std::runtime_error(std::string("CShake256 Finalize Failed : !shake_imp_ptr_->GetDigest().empty() : ErrorCode ") +
                                 std::to_string(static_cast<int>(shake_imp_ptr_->GetLastError())));
    }
    return std::move(shake_imp_ptr_->GetDigest());
}

} // namespace hash
} // namespace safeheron