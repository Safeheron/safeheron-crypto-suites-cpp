#include "rand.h"
#include "../exception/safeheron_exceptions.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <memory>
#include <cassert>

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;


namespace safeheron{
namespace rand{

void RandomBytes(unsigned char *buf, size_t size) {
    int ret = 0;
    if (!buf) {
        throw RandomSourceException(__FILE__, __LINE__, __FUNCTION__, -1, "!buf");
    }
    if ((ret = RAND_bytes(buf, size)) <= 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = RAND_bytes(buf, size)) <= 0");
    }
}

BN RandomBN(size_t bits) {
    BN n;
    size_t bytes = (bits + 7) / 8;
    size_t pad = bytes * 8 - bits; // 0 ~ 7
    if (bits <= 0) {
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "bits <= 0");
    }
    std::unique_ptr<unsigned char[]> buf(new(std::nothrow) unsigned char[bytes]);
    if (buf.get() == nullptr) throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, bytes, "buf.get() == nullptr");
    do{
        RandomBytes(buf.get(), bytes);
        uint8_t a = 0xff >> pad;
        buf[0] &= a;
        n = BN::FromBytesBE(buf.get(), bytes);
    }while(n == 0);
    return n;
}

BN RandomBNStrict(size_t bits) {
    size_t bytes = (bits + 7) / 8;
    size_t pad = bytes * 8 - bits;
    if (bits <= 0) {
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "bits <= 0");
    }
    std::unique_ptr<unsigned char[]> buf(new(std::nothrow) unsigned char[bytes]);
    if (buf == nullptr) throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, bytes, "buf == nullptr");
    do {
        RandomBytes(buf.get(), bytes);
        uint8_t a = 0xff >> pad;
        buf[0] &= a;
    }while((buf[0] & (0x80 >> pad)) == 0);
    BN n = BN::FromBytesBE(buf.get(), bytes);
    return n;
}

BN RandomPrime(size_t bits) {
    BN n;
    BIGNUM* p = nullptr;
    int ret = 0;
    if (bits <= 0) {
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "bits <= 0");
    }
    if (!(p = BN_new())) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!(p = BN_new())");
    }
    if ((ret = BN_generate_prime_ex(p, bits, 0, nullptr, nullptr, nullptr)) != 1) {
        BN_clear_free(p);
        p = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_generate_prime_ex(p, byteSize * 8, 0, nullptr, nullptr, nullptr)) != 1");
    }
    n.Hold(p);
    return n;
}

BN RandomPrimeStrict(size_t bits) {
    BN n;
    do {
        n = RandomPrime(bits);
    }while (!n.IsBitSet(bits-1));
    return n;
}

BN RandomSafePrime(size_t bits) {
    BN n;
    BIGNUM* p = nullptr;
    int ret = 0;
    if (bits <= 0) {
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "bits <= 0");
    }
    if (!(p = BN_new())) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!(p = BN_new())");
    }
    if ((ret = BN_generate_prime_ex(p, bits, 1, nullptr, nullptr, nullptr)) != 1) {
        BN_clear_free(p);
        p = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_generate_prime_ex(p, byteSize * 8, 1, nullptr, nullptr, nullptr)) != 1");
    }
    n.Hold(p);
    return n;
}

BN RandomSafePrimeStrict(size_t bits) {
    BN n;
    do {
        n = RandomSafePrime(bits);
    }while (!n.IsBitSet(bits - 1));
    return n;
}

BN RandomBNLt(const BN &max) {
    BN n;
    int bits = max.BitLength();
    do{
        n = RandomBN(bits);
    }while (n >= max);
    return n;
}

BN RandomBNLtGcd(const BN &max) {
    BN n;
    do{
        n = RandomBNLt(max);
    }while (n.Gcd(max) != 1);
    return n;
}

BN RandomBNLtCoPrime(const BN &max) {
    BN n;
    do{
        n = RandomBNLt(max);
    }while (n.Gcd(max) != 1);
    return n;
}

BN RandomBNInRange(const safeheron::bignum::BN &min, const safeheron::bignum::BN &max){
    assert(max > min);
    BN range = max - min;
    BN r = RandomBNLt(range);
    return min + r;
}

BN RandomNegBNInSymInterval(const safeheron::bignum::BN &limit){
    assert(limit > 0);
    BN r = RandomBNLt(limit);
    uint8_t sign[1];
    RandomBytes(sign, 1);
    return (sign[0] & 0x01) ? r : r.Neg();
}

BN RandomNegBNInSymInterval(size_t bits){
    BN r = RandomBN(bits);
    uint8_t sign[1];
    RandomBytes(sign, 1);
    return (sign[0] & 0x01) ? r : r.Neg();
}

}
}
