//
// Created by Sword03 on 2022/3/11.
//

#ifndef CRYPTOHASH_Keccak256_H
#define CRYPTOHASH_Keccak256_H

#include <cstddef>

struct SHA3_CTX;

namespace safeheron{
namespace hash{

class CKeccak256 {
private:
    SHA3_CTX *ptr_ctx;
public:
    static const size_t OUTPUT_SIZE = 32;

    CKeccak256();
    ~CKeccak256();

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    CKeccak256& Write(const unsigned char *data, size_t len);

    CKeccak256& Reset();
};


}
}



#endif //CRYPTOHASH_Keccak256_H
