#include "bn.h"
#include <cassert>
#include <cstring>
#include <string>
#include <openssl/bn.h>
#include "../exception/safeheron_exceptions.h"

using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

namespace safeheron {
namespace bignum {


/**
 * convert binary string to hex str
 * @param[in] s
 * @return a hex string
 */
static std::string bin2hex(const std::string &s) {
    const char chs[17] = "0123456789ABCDEF";
    std::string padded_str;
    std::string out;
    // Range of valid hex
    unsigned start = 0;
    unsigned end = 0;

    // neg
    if (s[0] == '-') {
        out.push_back('-');
        start++;
        end++;
    }else if (s[0] == '+'){
        start++;
        end++;
    }
    for (size_t i = start; i < s.size(); ++i) {
        if(s.at(i) != '0' && s.at(i) != '1') break;
        end++;
    }
    if(end == start) return out;
    // convert 4 bin chars to 1 hex char
    size_t pad = 4 - (end - start) % 4;
    uint8_t c = 0;
    for (size_t i = start; i < end; ++i){
        if(s.at(i) == '0'){
            c <<= 1;
        }else{
            c <<= 1;
            c += 1;
        }
        if((pad + i - start + 1) % 4 == 0){
            out.push_back(chs[c & 0x0F]);
            c = 0;
        }
    }

    return out;
}


/**
 * const variables definition
*/
const BN BN::ZERO = BN(); // same as BN(0)
const BN BN::ONE = BN(1);
const BN BN::TWO = BN(2);
const BN BN::THREE = BN(3);
const BN BN::FOUR = BN(4);
const BN BN::FIVE = BN(5);
const BN BN::MINUS_ONE = BN(-1);

/**
 * Construct a BN object and initialized it with 0
*/
BN::BN()
        : bn_(nullptr)
{
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(bn_ = BN_new())");
    }
    // BN_zero() never fails and returns no value.
    BN_zero(bn_);
}

/**
 * Construct a BN object and initialized it with word i
 * @param[in] i
 */
BN::BN(long i)
        : bn_(nullptr)
{
    int ret = 0;
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, 0, "!(bn_ = BN_new())");
    }
    if (i >= 0) {
        if ((ret = BN_set_word(bn_, i)) != 1) {
            BN_clear_free(bn_);
            bn_ = nullptr;
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_set_word(bn_, i)) != 1");
        }
    }
    else {
        if ((ret = BN_set_word(bn_, -i) ) != 1) {
            BN_clear_free(bn_);
            bn_ = nullptr;
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_set_word(bn_, -i) ) != 1");
        }
        BN_set_negative(bn_, 1);
    }
}

/**
 * Construct a BN objet and initialized it with str
 * @param[in] str A pointer to a 2/10/16 radix number string.
 * @param[in] base the radix, only support 2/10/16 radix
 */
BN::BN(const char *str, int base)
        : bn_(nullptr)
{
    assert(str);
    assert(base == 2 || base == 10 || base == 16);

    int ret = 0;
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, 0, "!(bn_ = BN_new())");
    }

    switch (base)
    {
        case 2:
        {
            std::string hex_str = bin2hex(str);
            if ((ret = BN_hex2bn(&bn_, hex_str.c_str())) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_hex2bn(&bn_, hex_str.c_str())) <= 0");
            }
            break;
        }
        case 10:
            if ((ret = BN_dec2bn(&bn_, str)) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_dec2bn(&bn_, str)) <= 0");
            }
            break;
        case 16:
            if ((ret = BN_hex2bn(&bn_, str)) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_hex2bn(&bn_, str)) <= 0");
            }
            break;
        default:
            // invalid base
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, base, "invalid base");
    }
}

/**
 * Destruction
*/
BN::~BN()
{
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
}

/**
 * A copy constructor
 * @param[in] num
*/
BN::BN(const BN &num)
        : bn_(nullptr)
{
    if (!(bn_ = BN_dup(num.bn_))) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!(bn_ = BN_dup(num.bn_))");
    }
}

/**
 * A copy assignment operator
 * @param[in] num
 * @return Return a copy BN object from num
 */
BN &BN::operator=(const BN &num)
{
    assert(bn_);
    if (this == &num) {
        return *this;
    }
    if (!(BN_copy(bn_, num.bn_))) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!(BN_copy(bn_, num.bn_))");
    }
    return *this;
}

/**
 * A move constructor
 * @param[in, out] num
 */
BN::BN(BN &&num) noexcept
        : bn_(nullptr)
{
    bn_ = num.bn_;
    num.bn_ = nullptr;
}

/**
 * A move assignment operator
 * @param[in,out] num
 * @return A BN object moved from num.
 */
BN &BN::operator=(BN &&num) noexcept
{
    if (this == &num) {
        return *this;
    }
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
    bn_ = num.bn_;
    num.bn_ = nullptr;
    return *this;
}

/**
 * Addition of BNs.
 * @param[in] num
 * @return (*this) + num
 */
BN BN::operator+(const BN &num) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_ && num.bn_);
    if ((ret = BN_add(n.bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add(n.bn_, bn_, num.bn_)) != 1");
    }
    return n;
}

/**
 * Subtraction of BNs.
 * @param[in] num
 * @return (*this) - num
 */
BN BN::operator-(const BN &num) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_ && num.bn_);
    if ((ret = BN_sub(n.bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub(n.bn_, bn_, num.bn_)) != 1");
    }
    return n;
}

/**
 * Multiplication of BNs.
 * @param[in] num
 * @return (*this) * num
 */
BN BN::operator*(const BN &num) const
{
    BN n;
    BN_CTX* ctx = nullptr;
    int ret = 0;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_mul(n.bn_, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul(n.bn_, bn_, num.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}

/**
 * Division of BNs.
 * @param[in] num
 * @return (*this) / num
 */
BN BN::operator/(const BN &num) const
{
    BN n;
    BN_CTX* ctx = nullptr;
    int ret = 0;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_div(n.bn_, nullptr, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div(n.bn_, nullptr, bn_, num.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}

/**
 * Self-addition of BNs.
 * @param[in] num
 * @return (*this) + num
 */
BN &BN::operator+=(const BN &num)
{
    int ret = 0;
    assert(bn_ && num.bn_);
    if ((ret = BN_add(bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add(bn_, bn_, num.bn_)) != 1");
    }
    return *this;
}

/**
 * Self-subtraction of BNs.
 * @param[in] num
 * @return (*this) - num
 */
BN &BN::operator-=(const BN &num)
{
    int ret = 0;
    assert(bn_ && num.bn_);
    if ((ret = BN_sub(bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub(bn_, bn_, num.bn_)) != 1");
    }
    return *this;
}

/**
 * Self-multiplication of BNs.
 * @param[in] num
 * @return (*this) * num
 */
BN &BN::operator*=(const BN &num)
{
    int ret = 0;
    BN_CTX* ctx = nullptr;

    assert(bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_mul(bn_, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul(bn_, bn_, num.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return *this;
}

/**
 * Self-division of BNs.
 * @param[in] num
 * @return (*this) / num
 */
BN &BN::operator/=(const BN &num)
{
    int ret = 0;
    BN_CTX* ctx = nullptr;

    assert(bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_div(bn_, nullptr, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div(bn_, nullptr, bn_, num.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return *this;
}

/**
 * Addition with a long int.
 * @param[in] num
 * @return (*this) + n
 */
BN BN::operator+(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_add_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add_word(n.bn_, si)) != 1");
        }
    } else {
        if ((ret = BN_sub_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub_word(n.bn_, -si)) != 1");
        }
    }
    return n;
}

/**
 * Subtraction with a long int.
 * @param[in] num
 * @return (*this) - n
 */
BN BN::operator-(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_sub_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub_word(n.bn_, si)) != 1");
        }
    } else {
        if ((ret = BN_add_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add_word(n.bn_, -si)) != 1");
        }
    }
    return n;
}

/**
 * Multiplication with a long int.
 * @param[in] num
 * @return (*this) * n
 */
BN BN::operator*(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_mul_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul_word(n.bn_, si)) != 1");
        }
    }
    else {
        BN_set_negative(n.bn_, 1);
        if ((ret = BN_mul_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul_word(n.bn_, -si)) != 1");
        }
    }
    return n;
}

/**
 * Self-division with a long int.
 * @param[in] num
 * @return (*this) / n
 */
BN BN::operator/(long si) const
{
    BN n(*this);
    unsigned long ret = 0;

    assert(n.bn_);
    if (si >= 0) {
        if ((ret = BN_div_word(n.bn_, si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div_word(n.bn_, si)) == (BN_ULONG)-1");
        }
    }
    else {
        BN_set_negative(n.bn_, 1);
        if ((ret = BN_div_word(n.bn_, -si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div_word(n.bn_, -si)) == (BN_ULONG)-1");
        }
    }
    return n;
}

/**
 * Self-addition with a long int.
 * @param[in] num
 * @return (*this) + n
 */
BN &BN::operator+=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_add_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add_word(bn_, si)) != 1");
        }
    } else {
        if ((ret = BN_sub_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub_word(bn_, -si)) != 1");
        }
    }
    return *this;
}

/**
 * Self-subtraction with a long int.
 * @param[in] num
 * @return (*this) - n
 */
BN &BN::operator-=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_sub_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_sub_word(bn_, si)) != 1");
        }
    } else {
        if ((ret = BN_add_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_add_word(bn_, -si)) != 1");
        }
    }
    return *this;
}

/**
 * Self-multiplication with a long int.
 * @param[in] num
 * @return (*this) * n
 */
BN &BN::operator*=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_mul_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul_word(bn_, si)) != 1");
        }
    }
    else {
        BN_set_negative(bn_, 1);
        if ((ret = BN_mul_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mul_word(bn_, -si)) != 1");
        }
    }
    return *this;
}

/**
 * Self-division with a long int.
 * @param[in] num
 * @return (*this) / n
 */
BN &BN::operator/=(long si)
{
    unsigned long ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_div_word(bn_, si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div_word(bn_, si)) == (BN_ULONG)-1");
        }
    } else {
        BN_set_negative(bn_, 1);
        if ((ret = BN_div_word(bn_, -si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div_word(bn_, -si)) == (BN_ULONG)-1");
        }
    }
    return *this;
}

/**
 * Modulo operation.
 * @param[in] num
 * @return (*this) mod num
 */
BN BN::operator%(const BN &num) const
{
    int ret = 0;
    BN n(*this);
    BN_CTX* ctx = nullptr;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_nnmod(n.bn_, n.bn_, num.bn_, ctx)) != 1){
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_nnmod(n.bn_, n.bn_, num.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}

/**
 * Modulo operation with a unsigned long int.
 * @param[in] num
 * @return (*this) mod num
 */
BN BN::operator%(unsigned long ui) const
{
    return *this % BN(ui);
}

/**
 * Bitwise left shift.
 * @param[in] n
 * @return (*this) << n, that is left shift of (*this) by n bits.
 */
BN BN::operator<<(unsigned long ui) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_);
    if ((ret = BN_lshift(n.bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_lshift(n.bn_, bn_, ui)) != 1");
    }
    return n;
}

/**
 * Bitwise right shift.
 * @param[in] n
 * @return (*this) >> n, that is right shift of (*this) by n bits.
 */
BN BN::operator>>(unsigned long ui) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_);
    if ((ret = BN_rshift(n.bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_rshift(n.bn_, bn_, ui)) != 1");
    }
    return n;
}

/**
 * Bitwise left shift(self assignment).
 * @param[in] n
 * @return (*this) << n, that is left shift of (*this) by n bits.
 */
BN &BN::operator<<=(unsigned long ui)
{
    int ret = 0;
    assert(bn_);
    if ((ret = BN_lshift(bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_lshift(bn_, bn_, ui)) != 1");
    }
    return *this;
}

/**
 * Bitwise right shift(self assignment).
 * @param[in] n
 * @return (*this) >> n, that is right shift of (*this) by n bits.
 */
BN &BN::operator>>=(unsigned long ui)
{
    int ret = 0;
    assert(bn_);
    if ((ret = BN_rshift(bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_rshift(bn_, bn_, ui)) != 1");
    }
    return *this;
}

/**
 * Comparison operator: equal to
 * @param[in] num
 * @return true if (*this) is equal to num, false otherwise.
 */
bool BN::operator==(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) == 0;
}

/**
 * Comparison operator: not equal to
 * @param[in] num
 * @return true if (*this) is not equal to num, false otherwise.
 */
bool BN::operator!=(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) != 0;
}

/**
 * Comparison operator: less than
 * @param[in] num
 * @return true if (*this) is less than num, false otherwise.
 */
bool BN::operator<(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) == -1;
}

/**
 * Comparison operator: less than or equal to
 * @param[in] num
 * @return true if (*this) is less than or equal to num, false otherwise.
 */
bool BN::operator<=(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) <= 0;
}

/**
 * Comparison operator: greater than
 * @param[in] num
 * @return true if (*this) is greater than num, false otherwise.
 */
bool BN::operator>(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) == 1;
}

/**
 * Comparison operator: greater than or equal to
 * @param[in] num
 * @return true if (*this) is greater than or equal to num, false otherwise.
 */
bool BN::operator>=(const BN &num) const
{
    assert(bn_ && num.bn_);
    return BN_cmp(bn_, num.bn_) >= 0;
}

/**
 * Comparison operator: equal to
 * @param[in] si
 * @return true if (*this) is equal to si, false otherwise.
 */
bool BN::operator==(long si) const
{
    assert(bn_);
    BN n(si);
    return *this == n;
}

/**
 * Comparison operator: not equal to
 * @param[in] si
 * @return true if (*this) is not equal to si, false otherwise.
 */
bool BN::operator!=(long si) const
{
    assert(bn_);
    BN n(si);
    return *this != n;
}

/**
 * Comparison operator: greater than
 * @param[in] si
 * @return true if (*this) is greater than si, false otherwise.
 */
bool BN::operator>(long si) const
{
    assert(bn_);
    BN n(si);
    return *this > n;
}

/**
 * Comparison operator: less than
 * @param[in] si
 * @return true if (*this) is less than si, false otherwise.
 */
bool BN::operator<(long si) const
{
    assert(bn_);
    BN n(si);
    return *this < n;
}

/**
 * Comparison operator: greater than or equal to
 * @param[in] si
 * @return true if (*this) is greater than or equal to si, false otherwise.
 */
bool BN::operator>=(long si) const
{
    assert(bn_);
    BN n(si);
    return *this >= n;
}

/**
 * Comparison operator: less than or equal to
 * @param[in] si
 * @return true if (*this) is less than or equal to si, false otherwise.
 */
bool BN::operator<=(long si) const
{
    assert(bn_);
    BN n(si);
    return *this <= n;
}

/**
 * Return the negative of this BN
*/
BN BN::Neg() const
{
    assert(bn_);
    BN n(*this);
    if (n.IsNeg()) {
        BN_set_negative(n.bn_, 0);
    }
    else {
        BN_set_negative(n.bn_, 1);
    }
    return n;
}

/**
 * Division of BNs: *this = q * d + r.
 * @param[in] d divider
 * @param[out] q quotient
 * @param[out] r remainder
 */
void BN::Div(const BN &d, BN &q, BN &r)
{
    assert(bn_ && d.bn_ && q.bn_ && r.bn_);
    int ret = 0;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_div(q.bn_, r.bn_, bn_, d.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_div(q.bn_, r.bn_, bn_, d.bn_, ctx)");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
}

/**
 * Calculate the inverse modulo m.
 * @param[in] m
 * @warning (*this) and m must be co-prime. It's all safe if m is a prime.
 * @return the inverse modulo m
 */
BN BN::InvM(const BN &m) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if (!BN_mod_inverse(r.bn_, bn_, m.bn_, ctx)) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!BN_mod_inverse(r.bn_, bn_, m.bn_, ctx)");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}

/**
 * Calculate the greatest common divisor of (*this) and n
 * @param[in] n
 * @return the greatest common divisor
 */
BN BN::Gcd(const BN &n) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    int ret = 0;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_gcd(r.bn_, bn_, n.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_gcd(r.bn_, bn_, n.bn_, ctx)) != 1");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}

/**
 * Calculate the least common multiple of this and n.
 *      lcm(a, b) = ab/gcd(a,b))
 * @param[in] n
 * @return the least common multiple
 */
BN BN::Lcm(const BN &n) const
{
    BN r = (*this) * n;
    r /= Gcd(n);
    return r;
}

/**
 * Calculate the y-th power of this and modulo m
 *      r = (this ^ y) % m
 * @param[in] y
 * @param[in] m
 * @return the y-th power
 */
BN BN::PowM(const BN &y, const BN &m) const
{
    assert(bn_ && y.bn_ && m.bn_);
    BN r;
    BN t_y = y.IsNeg()? y.Neg() : y;
    BN_CTX* ctx = nullptr;
    int ret = 0;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if ((ret = BN_mod_exp(r.bn_, bn_, t_y.bn_, m.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_mod_exp(r.bn_, bn_, t_y.bn_, m.bn_, ctx)) != 1");

    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return y.IsNeg()? r.InvM(m): r;
}

/**
 * Calculate square root 'r' on modulo m where
 *      r^2 == this (mod p),
 *
 * @warning You must check if a square root exists before invoking the function.
 *  \code{.cpp}
 *       if(!a.ExistSqrtM(p)) return false;
 *       BN root = a.SqrtM(p);
 *  \endcode
 *
 * @param[in] m
 * @return the square rootn
 */
BN BN::SqrtM(const BN &p) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1, "!(ctx = BN_CTX_new())");
    }
    if (!(BN_mod_sqrt(r.bn_, bn_, p.bn_, ctx))) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!(BN_mod_sqrt(r.bn_, bn_, p.bn_, ctx))");
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}

/**
 * @brief Calculate square root of this object
 * 
 * @return BN the square root of this big number
 */
BN BN::Sqrt() const
{
	int shift = 0;
    BN mask(0);
    BN sqrt(0);
    BN x(*this);
    BN r(0);

	shift = BN_num_bits(bn_) / 2;

	while (shift >= 0) {
        mask = BN::ONE << shift;
        sqrt = (mask + (r << 1)) << shift;

        if (sqrt <= x) {
            r += mask;
            x -= sqrt;
        }
		shift--;
    }

    return r;
}

/**
 * Check if a square root 'r' exists where
 *      r^2 == this (mod p),
 * @param[in] m
 * @return true if 'r' exists, false otherwise.
 */
bool BN::ExistSqrtM(const BN &p) const
{
    BN p_minus_1 = p - 1;
    BN lpow = p_minus_1 >> 1; // lpow = (p-1)/2
    BN n = *this % p;
    if (n.IsZero()) return true;
    if (n.PowM(lpow, p) == BN::ONE) {
        return true;
    } else{
        return false;
    }
}

/**
 * Return true is this is a prime, otherwise return false
 * @return true if this is probably prime, false otherwise.
 */
bool BN::IsProbablyPrime() const
{
    return BN_is_prime_fasttest_ex(bn_, 0, nullptr, 1, nullptr);
}

/**
 * Conversion from hex string to BN.
 * @param[in] str
 * @return a BN object.
 */
BN BN::FromHexStr(const char *str)
{
    assert(str);

    BN n;
    int ret = 0;
    if (n.bn_) {
        BN_clear_free(n.bn_);
        n.bn_ = nullptr;
    }
    if ((ret = BN_hex2bn(&n.bn_, str)) == 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_hex2bn(&n.bn_, str)) == 0");
    }
    return n;
}

/**
 * Conversion from HEX string to BN
 * @param[in] str
 * @return a BN object.
 */
BN BN::FromHexStr(const std::string &str)
{
    return BN::FromHexStr(str.c_str());
}

/**
 * Conversion from decimal string to BN.
 * @param[in] str
 * @return a BN object.
 */
BN BN::FromDecStr(const char *str)
{
    assert(str);

    BN n;
    int ret = 0;
    if (n.bn_) {
        BN_clear_free(n.bn_);
        n.bn_ = nullptr;
    }
    if ((ret = BN_dec2bn(&n.bn_, str)) == 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_dec2bn(&n.bn_, str)) == 0");
    }
    return n;
}

/**
 * Conversion from decimal string to BN
 * @param[in] str
 * @return a BN object.
 */
BN BN::FromDecStr(const std::string &str)
{
    return BN::FromDecStr(str.c_str());
}

/**
 * Conversion from BN to HEX string
 * @param[in, out] str
 */
void BN::ToHexStr(std::string &str) const
{
    char *ch = BN_bn2hex((const BIGNUM*)bn_);
    if (ch == nullptr) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "ch == nullptr");
    }

    str.assign(ch, strlen(ch));
    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion from BN to HEX string
 * @param[in,out] str
 */
void BN::ToDecStr(std::string &str) const
{
    char *ch = BN_bn2dec((const BIGNUM*)bn_);
    if (ch == nullptr) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "ch == nullptr");
    }

    str.assign(ch, strlen(ch));
    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion from a byte buffer to a BN object in big endian
 * @param[in] buf
 * @param[in] len
 * @return a BN object
 */
BN BN::FromBytesBE(const uint8_t *buf, int len)
{
    assert(buf);

    BN n;
    if (!BN_bin2bn(buf, len, n.bn_)) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!BN_bin2bn(buf, len, n.bn_)");
    }
    return n;
}

/**
 * Conversion from a byte buffer to a BN object in big endian
 * @param[in] buf
 * @return a BN object
 */
BN BN::FromBytesBE(const std::string &buf)
{
    return FromBytesBE((const uint8_t *)buf.c_str(), buf.length());
}

/**
 * Conversion from a byte buffer to a BN object in little endian
 * @param[in] buf
 * @param[in] len
 * @return a BN object
 */
BN BN::FromBytesLE(const uint8_t *buf, int len)
{
    assert(buf);

    BN n;
    if (!BN_lebin2bn(buf, len, n.bn_)) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0, "!BN_lebin2bn(buf, len, n.bn_)");
    }
    return n;
}

/**
 * Conversion from a byte buffer to a BN object in little endian
 * @param[in] buf
 * @return a BN object
 */
BN BN::FromBytesLE(const std::string &buf)
{
    return FromBytesLE((const uint8_t *)buf.c_str(), buf.length());
}

/**
 * Conversion to bytes string in big endian
 * @param[out] buf
 */
void BN::ToBytesBE(std::string &buf) const
{
    int len = BN_num_bytes(bn_);
    if (len == 0 ) {
        buf.clear();
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len, "ch == nullptr");
    }

    memset(ch, 0, len);
    if ((len = BN_bn2bin(bn_, ch)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len, "(len = BN_bn2bin(bn_, ch)) <= 0");
    }

    buf.assign((const char*)ch, len);
    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion to bytes string in little endian
 * @param[out] buf
 */
void BN::ToBytesLE(std::string &buf) const
{
    int len = BN_num_bytes(bn_);
    if (len == 0 ) {
        buf.clear();
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len, "ch == nullptr");
    }

    memset(ch, 0, len);
    if ((len = BN_bn2lebinpad(bn_, ch, len)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len, "(len = BN_bn2lebinpad(bn_, ch, len)) <= 0");
    }

    buf.assign((const char*)ch, len);
    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion to bytes string in big endian, which is 32 in length by byte
 * @param[out] buf32
 * @param[in] blen
 */
void BN::ToBytes32BE(uint8_t *buf32, int blen) const
{
    assert(buf32);
    assert(blen >= 32);
    memset(buf32, 0, 32);

    int len = BN_num_bytes(bn_);
    if (len == 0) {
        return;
    }

    uint8_t*ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len, "ch == nullptr");
    }

    memset(ch, 0, len);
    if ((len = BN_bn2bin(bn_, ch)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len, "(len = BN_bn2bin(bn_, ch)) <= 0");
    }

    if (len < 32) {
        uint8_t *des = buf32 + 32 - len;
        memcpy(des, ch, len);
    } else {
        uint8_t *src = ch + len - 32;
        memcpy(buf32, src, 32);
    }

    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion to bytes string in little endian, which is 32 in length by byte
 * @param[out] buf32
 * @param[in] blen
 */
void BN::ToBytes32LE(uint8_t *buf32, int blen) const
{
    assert(buf32);
    assert(blen >= 32);
    memset(buf32, 0, 32);

    int len = BN_num_bytes(bn_);
    if (len == 0) {
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len, "ch == nullptr");
    }

    memset(ch, 0, len);
    if ((len = BN_bn2lebinpad(bn_, ch, len)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len, "(len = BN_bn2lebinpad(bn_, ch, len)) <= 0");
    }

    if (len < 32) {
        // memcpy_s
        memcpy(buf32, ch, len);
    }
    else {
        memcpy(buf32, ch, 32);
    }

    OPENSSL_free(ch);
    ch = nullptr;
}

/**
 * Conversion to bytes string in big endian, which is 32 in length by byte
 * @param[out] buf
 */
void BN::ToBytes32BE(std::string &buf) const
{
    uint8_t t_buf32[32] = {0};
    ToBytes32BE(t_buf32);
    buf.assign((const char *)t_buf32, 32);
}

/**
 * Conversion to bytes string in little endian, which is 32 in length by byte
 * @param[out] buf
 */
void BN::ToBytes32LE(std::string &buf) const
{
    uint8_t t_buf32[32];
    ToBytes32LE(t_buf32);
    buf.assign((const char *)t_buf32, 32);
}

/**
 * Hold no a new BN object specified by "bn", which is a pointer to a memory in struct "bignum_st".
 * @warning "bn" must be created by the key word "new" and initialized before calling this API. It will be freed automatically in the destructor.
 * @param[in] bn
 */
void BN::Hold(bignum_st* bn)
{
    assert(bn);
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
    bn_ = bn;
}

/**
 * Return bits size of this BN
 * @return bit size
 */
size_t BN::BitLength() const
{
    return BN_num_bits(bn_);
}

/**
 * Return bytes size of this BN
 * @return bytes size.
 */
size_t BN::ByteLength() const
{
    return (BitLength() + 7) / 8;
}

/**
 * Check if this BN is a negative number.
 * @return true if this BIGUN is a negative number, false otherwise.
 */
bool BN::IsNeg() const
{
    return BN_is_negative(bn_) == 1;
}

/**
 * Check if this BN is even.
 * @return true if this BN is even, false otherwise.
 */
bool BN::IsEven() const
{
    return !IsOdd();
}

/**
 * Check if this BN is odd.
 * @return true if this BN is odd, false otherwise.
 */
bool BN::IsOdd() const
{
    return BN_is_odd(bn_) == 1;
}

/**
 * Check if this BN is equal to zero.
 * @return true if this BN is equal to zero, false otherwise.
 */
bool BN::IsZero() const
{
    return BN_is_zero(bn_) == 1;
}

/**
 * Return the max one between a and b
 * @param[in] a
 * @param[in] b
 * @return  max(a, b)
 */
BN BN::Max(const BN &a, const BN &b)
{
    return (a > b) ? a : b;
}

/**
 * Return the min one between a and b
 * @param[in] a
 * @param[in] b
 * @return min(a, b)
 */
BN BN::Min(const BN &a, const BN &b)
{
    return (a < b) ? a : b;
}

/**
 * Swap the values between a and b
 * @param[in,out] a
 * @param[in,out] b
 */
void BN::Swap(BN &a, BN &b)
{
    assert(a.bn_ && b.bn_);
    BN_swap(a.bn_, b.bn_);
}

/**
 * Set the bit in position "index".
 * @param[in] index the index of the bit
 */
void BN::SetBit(unsigned long index)
{
    assert(bn_);

    int ret = 0;
    if ((ret = BN_set_bit(bn_, index)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_set_bit(bn_, index)) != 1");
    }
}

/**
 * Clear the bit in position "index".
 * @param[in] index the index of the bit
 */
void BN::ClearBit(unsigned long index)
{
    assert(bn_);

    int ret = 0;
    if ((ret = BN_clear_bit(bn_, index)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = BN_clear_bit(bn_, index)) != 1");
    }
}

/**
 * Check if the bit was set in position "index"
 * @param[in] index
 * @return true if the bit was set, false otherwise.
 */
bool BN::IsBitSet(unsigned long index) const
{
    assert(bn_);
    return BN_is_bit_set(bn_, index) == 1;
}

/**
 * Inspect the value.
 * @param[in] radix 10 or 16 radix number
 * @return A string which indicate this BN to the specified radix.
 */
std::string BN::Inspect(int base) const
{
    assert(base == 10 || base == 16);

    std::string str;
    if (base == 10) {
        ToDecStr(str);
    }
    else {
        ToHexStr(str);
    }
    return str;
}

/**
 * Extended Euclidean algorithm
 *      ax + by = d
 *
 * @param[in] a
 * @param[in] b
 * @param[out] d greatest common divider of a and b.
 * @param[out] x
 * @param[out] y
 */
void BN::ExtendedEuclidean(const BN& a, const BN &b, BN &x, BN &y, BN &d){
    /**
     * @note
     * Extended Euclidean algorithm: \p
     *     - Given a, b              \p
     *     - Compute x, y, d, so that  ax + by = d
     *
     * \code{.cpp}
     * def ext_euclid(a, b):
     *  old_s, s = 1, 0
     *  old_t, t = 0, 1
     *  old_r, r = a, b
     *  if b == 0:
     *      return 1, 0, a
     *  else:
     *      while(r!=0):
     *          q = old_r // r
     *          old_r, r = r, old_r-q*r
     *          old_s, s = s, old_s-q*s
     *          old_t, t = t, old_t-q*t
     *  return old_s, old_t, old_r
     *  \endcode
     */
    bool is_a_neg = false;
    bool is_b_neg = false;
    BN t_a = a;
    BN t_b = b;
    if(t_a < 0) {
        is_a_neg = true;
        t_a = t_a.Neg();
    }
    if(t_b < 0) {
        is_b_neg = true;
        t_b = t_b.Neg();
    }

    BN old_s(1), s(0);
    BN old_t(0), t(1);
    BN old_r(a), r(b);

    if(t_b == 0) {
        d = t_a;
        x = BN(1);
        y = BN(0);
        return;
    }

    while(r != 0){
        BN q = old_r / r;
        // old_r, r = r, old_r-q*r
        old_r = old_r - q * r;
        BN::Swap(old_r, r);
        // old_s, s = s, old_s-q*s
        old_s = old_s - q * s;
        BN::Swap(old_s, s);
        // old_t, t = t, old_t-q*t
        old_t = old_t - q * t;
        BN::Swap(old_t, t);
    }
    d = old_r;
    x = old_s;
    y = old_t;

    if(is_a_neg) x = x.Neg();
    if(is_b_neg) y = y.Neg();
}

/**
 * Compute jacobi symbol (k, n)
 *
 * Refer to the page: https://en.wikipedia.org/wiki/Jacobi_symbol
 *
 * The above formulas lead to an efficient O(log a log b)[3] algorithm for calculating the Jacobi symbol, analogous to the Euclidean algorithm for finding the gcd of two numbers. (This should not be surprising in light of rule 2.)
 *     1. Extract any even "numerator" using rule 9.
 *     2. Reduce the "numerator" modulo the "denominator" using rule 2.
 *     3. Extract any even "numerator" using rule 9.
 *     4. If the "numerator" is 1, rules 3 and 4 give a result of 1. If the "numerator" and "denominator" are not coprime, rule 3 gives a result of 0.
 *     5. Otherwise, the "numerator" and "denominator" are now odd positive coprime integers, so we can flip the symbol using rule 6, then return to step 1.
 * @param k
 * @param n
 * @return jacobi(n, k)
 */
int BN::JacobiSymbol(const BN &_k, const BN &_n){
    int symbol = 1;
    BN n = _n;
    BN k = _k;
    int r = 0;

    // Rule 2
    k = k % n;
    while (k != 0){
        // Rule 9, k = 2^s * a
        int s = 0;
        while (!k.IsBitSet(s)){
            s++;
        }
        k >>= s;
        if(s % 2 == 1){
            // r = n % 8;
            r = 0;
            if(n.IsBitSet(0)) r |= 0x1;
            if(n.IsBitSet(1)) r |= 0x2;
            if(n.IsBitSet(2)) r |= 0x4;
            if( (r == 3) || (r == 5) ){
                symbol *= -1;
            }
        }
        // Rule 6
        BN::Swap(k, n);

        // remain_n = n % 4
        int remain_n = 0;
        if(n.IsBitSet(0)) remain_n |= 0x1;
        if(n.IsBitSet(1)) remain_n |= 0x2;

        // remain_k = k % 4
        int remain_k = 0;
        if(k.IsBitSet(0)) remain_k |= 0x1;
        if(k.IsBitSet(1)) remain_k |= 0x2;

        // if( (n % 4 == 3) && (k % 4 == 3) ){
        if( (remain_n == 3) && (remain_k == 3) ){
            symbol = -symbol;
        }

        // Rule 2
        k = k % n;
    }
    if(n == 1){
        // Here (0, 1) actual comes from (1, n). And (1, n) = 1.
        // Return s * (1, n) = s
        return symbol;
    }else{
        // If the "numerator" and "denominator" are not coprime, rule 3 gives a result of 0.
        return 0;
    }
}

/**
 * Return the pointer to the internal struct.
 */
const bignum_st* BN::GetBIGNUM() const
{
    return bn_;
}

}
}
