#ifndef SAFEHERON_CRYPTO_SHAKE_128_H
#define SAFEHERON_CRYPTO_SHAKE_128_H

#include <cstring>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

namespace safeheron {
namespace hash {

class CShakeImp;

class CShake128 {
  private:
    std::vector<uint8_t> digest_;
    CShakeImp* shake_imp_ptr_;

  public:
    CShake128(size_t digest_size);
    ~CShake128();

    CShake128& Write(const unsigned char* data, size_t len);

    std::vector<uint8_t> Finalize();
};

}; // namespace hash
}; // namespace safeheron

#endif // SAFEHERON_CRYPTO_SHAKE_128_H
