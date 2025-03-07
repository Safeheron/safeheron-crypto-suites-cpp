//
// Created by Sword03 on 2022/3/11.
//

#include "crypto-suites/crypto-hash/keccak256.h"
#include "crypto-suites/common/custom_memzero.h"
#include "crypto-suites/crypto-hash/sha3_imp.h"

namespace safeheron{
namespace hash{

CKeccak256::CKeccak256() {
    ptr_ctx = new SHA3_CTX;
    keccak_256_Init(ptr_ctx);
}

CKeccak256::~CKeccak256() {
    crypto_memzero(ptr_ctx, sizeof(SHA3_CTX));
    delete ptr_ctx;
    ptr_ctx = nullptr;
}

void CKeccak256::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    keccak_Final(ptr_ctx, hash);
}

CKeccak256& CKeccak256::Write(const unsigned char *data, size_t len) {
    keccak_Update(ptr_ctx, data, len);
    return *this;
}

CKeccak256& CKeccak256::Reset() {
    keccak_256_Init(ptr_ctx);
    return *this;
}


}
}

