#ifndef SAFEHERON_CRYPTO_SHAKE_IMP_H
#define SAFEHERON_CRYPTO_SHAKE_IMP_H

#include <cstring>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "openssl/core_names.h" // OSSL_DIGEST_PARAM_XOFLEN
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/provider.h" // OSSL_PROVIDER_load

namespace safeheron {
namespace hash {

/** A hasher class for SHA-256. */
class CShakeImp {
  public:
    enum class CShakeError {
        Success = 0,                    // No error
        LoadDefaultProviderFailed = -1, // Failed to load default provider
        FetchShakE128Failed = -2,  // SHAKE128 not available in current provider
        FetchShakE256Failed = -3,  // SHAKE128 not available in current provider
        CreateMdCtxFailed = -4,         // Failed to create MD context
        DigestInitFailed = -5,          // DigestInit failed
        SetXoflenParamFailed = -6,      // Failed to set XOFLEN parameter
        DigestUpdateFailed = -7,        // DigestUpdate failed
        DigestFinalXofFailed = -8       // DigestFinalXOF failed
    };
    enum class CShakeType { Shake128 = 0, Shake256 = 1 };

  private:
    CShakeType shake_type_;
    std::vector<uint8_t> digest_;
    OSSL_PROVIDER* default_provider_;
    EVP_MD* md_;
    EVP_MD_CTX* ctx_;
    CShakeError last_error_;

  private:
    void InternalCleanUp();

  public:
    explicit CShakeImp(size_t digest_size, CShakeType st);
    ~CShakeImp();
    bool Init();
    bool Write(const unsigned char* data, size_t len);
    bool Finalize();
    std::vector<uint8_t>& GetDigest();
    CShakeError GetLastError();
};

}; // namespace hash
}; // namespace safeheron

#endif // SAFEHERON_CRYPTO_SHAKE_IMP_H
