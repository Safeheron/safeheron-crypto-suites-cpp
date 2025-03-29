#include "crypto-suites/crypto-hash/shake_imp.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

namespace safeheron {
namespace hash {

CShakeImp::CShakeImp(size_t digest_size, CShakeType st) {
    shake_type_ = st;
    digest_.resize(digest_size);
    default_provider_ = nullptr;
    md_ = nullptr;
    ctx_ = nullptr;
    last_error_ = CShakeError::Success;
}

CShakeImp::~CShakeImp() {
    InternalCleanUp();
}

bool CShakeImp::Init() {
    // Explicitly load the default provider (to ensure SHAKE128 is available)
    default_provider_ = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider_) {
        last_error_ = CShakeError::LoadDefaultProviderFailed;
        return false;
    }

    // Fetch the SHAKE128 algorithm
    if (shake_type_ == CShakeType::Shake128) {
        md_ = EVP_MD_fetch(NULL, "SHAKE128", NULL);
    } else {
        md_ = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    }
    if (!md_) {
        last_error_ =
            (shake_type_ == CShakeType::Shake128) ? CShakeError::FetchShakE128Failed : CShakeError::FetchShakE256Failed;
        return false;
    }

    // Create a digest context
    ctx_ = EVP_MD_CTX_new();
    if (!ctx_) {
        last_error_ = CShakeError::CreateMdCtxFailed;
        return false;
    }

    // Initialize the context with the digest algorithm
    if (EVP_DigestInit_ex(ctx_, md_, NULL) != 1) {
        last_error_ = CShakeError::DigestInitFailed;
        return false;
    }

    // Set the output length for SHAKE128 (critical for XOF)
    size_t outlen = digest_.size(); // Example: output 32 bytes
    OSSL_PARAM params[] = {OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &outlen), OSSL_PARAM_construct_end()};

    if (EVP_MD_CTX_set_params(ctx_, params) != 1) {
        last_error_ = CShakeError::SetXoflenParamFailed;
        return false;
    }

    return true;
}

bool CShakeImp::Write(const unsigned char* data, size_t len) {
    // Hash the input message
    if (EVP_DigestUpdate(ctx_, data, len) != 1) {
        last_error_ = CShakeError::DigestUpdateFailed;
        return false;
    }
    return true;
}

bool CShakeImp::Finalize() {
    // Finalize and get the output (use DigestFinalXOF for SHAKE128)
    if (EVP_DigestFinalXOF(ctx_, digest_.data(), digest_.size()) != 1) {
        last_error_ = CShakeError::DigestFinalXofFailed;
        return false;
    }
    return true;
}

std::vector<uint8_t>& CShakeImp::GetDigest() {
    return digest_;
}

void CShakeImp::InternalCleanUp() {
    EVP_MD_CTX_free(ctx_);
    EVP_MD_free(md_);
    OSSL_PROVIDER_unload(default_provider_); // Unload provider (optional)
}

CShakeImp::CShakeError CShakeImp::GetLastError() {
    return last_error_;
}

} // namespace hash
} // namespace safeheron