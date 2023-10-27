#ifndef SAFEHERON_BIG_NUMBER_H
#define SAFEHERON_BIG_NUMBER_H

#include<string>

struct bignum_st;

namespace safeheron {
namespace bignum {

/**
 * A big number class.
 */
class BN {
public:
    /**
     * Construct a BN object and initialized it with 0
    */
    explicit BN();

    /**
     * Construct a BN object and initialized it with word i
     * @param[in] i
     */
    explicit BN(long i);

    /**
     * Construct a BN objet and initialized it with str
     * @param[in] str A pointer to a 2/10/16 radix number string.
     * @param[in] base the radix, only support 2/10/16 radix
     */
    explicit BN(const char *str, int base);

    /**
     * A copy constructor
     * @param[in] num
    */
    BN(const BN &num);

    /**
     * A copy assignment operator
     * @param[in] num
     * @return Return a copy BN object from num
     */
    BN &operator=(const BN &num);

    /**
     * A move constructor
     * @param[in, out] num
     */
    BN(BN &&num) noexcept;

    /**
     * A move assignment operator
     * @param[in,out] num
     * @return A BN object moved from num.
     */
    BN &operator=(BN &&num) noexcept;

    /**
     * Destruction
    */
    virtual ~BN();

    /**
     * Addition of BNs.
     * @param[in] num
     * @return (*this) + num
     */
    BN operator+(const BN &num) const;

    /**
     * Subtraction of BNs.
     * @param[in] num
     * @return (*this) - num
     */
    BN operator-(const BN &num) const;

    /**
     * Multiplication of BNs.
     * @param[in] num
     * @return (*this) * num
     */
    BN operator*(const BN &num) const;

    /**
     * Division of BNs.
     * @param[in] num
     * @return (*this) / num
     */
    BN operator/(const BN &num) const;

    /**
     * Self-addition of BNs.
     * @param[in] num
     * @return (*this) + num
     */
    BN &operator+=(const BN &num);

    /**
     * Self-subtraction of BNs.
     * @param[in] num
     * @return (*this) - num
     */
    BN &operator-=(const BN &num);

    /**
     * Self-multiplication of BNs.
     * @param[in] num
     * @return (*this) * num
     */
    BN &operator*=(const BN &num);

    /**
     * Self-division of BNs.
     * @param[in] num
     * @return (*this) / num
     */
    BN &operator/=(const BN &num);

    /**
     * Addition with a long int.
     * @param[in] num
     * @return (*this) + n
     */
    BN operator+(long n) const;

    /**
     * Subtraction with a long int.
     * @param[in] num
     * @return (*this) - n
     */
    BN operator-(long n) const;

    /**
     * Multiplication with a long int.
     * @param[in] num
     * @return (*this) * n
     */
    BN operator*(long n) const;

    /**
     * Self-division with a long int.
     * @param[in] num
     * @return (*this) / n
     */
    BN operator/(long n) const;

    /**
     * Self-addition with a long int.
     * @param[in] num
     * @return (*this) + n
     */
    BN &operator+=(long n);

    /**
     * Self-subtraction with a long int.
     * @param[in] num
     * @return (*this) - n
     */
    BN &operator-=(long n);

    /**
     * Self-multiplication with a long int.
     * @param[in] num
     * @return (*this) * n
     */
    BN &operator*=(long n);

    /**
     * Self-division with a long int.
     * @param[in] num
     * @return (*this) / n
     */
    BN &operator/=(long n);

    /**
     * Modulo operation.
     * @param[in] num
     * @return (*this) mod num
     */
    BN operator%(const BN &num) const;

    /**
     * Modulo operation with a unsigned long int.
     * @param[in] num
     * @return (*this) mod num
     */
    BN operator%(unsigned long n) const;

    /**
     * Bitwise left shift.
     * @param[in] n
     * @return (*this) << n, that is left shift of (*this) by n bits.
     */
    BN operator<<(unsigned long n) const;

    /**
     * Bitwise right shift.
     * @param[in] n
     * @return (*this) >> n, that is right shift of (*this) by n bits.
     */
    BN operator>>(unsigned long n) const;

    /**
     * Bitwise left shift(self assignment).
     * @param[in] n
     * @return (*this) << n, that is left shift of (*this) by n bits.
     */
    BN &operator<<=(unsigned long n);

    /**
     * Bitwise right shift(self assignment).
     * @param[in] n
     * @return (*this) >> n, that is right shift of (*this) by n bits.
     */
    BN &operator>>=(unsigned long n);

    /**
     * Comparison operator: equal to
     * @param[in] num
     * @return true if (*this) is equal to num, false otherwise.
     */
    bool operator==(const BN &num) const;

    /**
     * Comparison operator: not equal to
     * @param[in] num
     * @return true if (*this) is not equal to num, false otherwise.
     */
    bool operator!=(const BN &num) const;

    /**
     * Comparison operator: greater than
     * @param[in] num
     * @return true if (*this) is greater than num, false otherwise.
     */
    bool operator>(const BN &num) const;

    /**
     * Comparison operator: less than
     * @param[in] num
     * @return true if (*this) is less than num, false otherwise.
     */
    bool operator<(const BN &num) const;

    /**
     * Comparison operator: greater than or equal to
     * @param[in] num
     * @return true if (*this) is greater than or equal to num, false otherwise.
     */
    bool operator>=(const BN &num) const;

    /**
     * Comparison operator: less than or equal to
     * @param[in] num
     * @return true if (*this) is less than or equal to num, false otherwise.
     */
    bool operator<=(const BN &num) const;

    /**
     * Comparison operator: equal to
     * @param[in] si
     * @return true if (*this) is equal to si, false otherwise.
     */
    bool operator==(long si) const;

    /**
     * Comparison operator: not equal to
     * @param[in] si
     * @return true if (*this) is not equal to si, false otherwise.
     */
    bool operator!=(long si) const;

    /**
     * Comparison operator: greater than
     * @param[in] si
     * @return true if (*this) is greater than si, false otherwise.
     */
    bool operator>(long si) const;

    /**
     * Comparison operator: less than
     * @param[in] si
     * @return true if (*this) is less than si, false otherwise.
     */
    bool operator<(long si) const;

    /**
     * Comparison operator: greater than or equal to
     * @param[in] si
     * @return true if (*this) is greater than or equal to si, false otherwise.
     */
    bool operator>=(long si) const;

    /**
     * Comparison operator: less than or equal to
     * @param[in] si
     * @return true if (*this) is less than or equal to si, false otherwise.
     */
    bool operator<=(long si) const;

    /**
     * Return the negative of BN
    */
    BN Neg()const;

    /**
     * Division of BNs: *this = q * d + r.
     * @param[in] d divider
     * @param[out] q quotient
     * @param[out] r remainder
     */
    void Div(const BN &d, BN &q, BN &r);

    /**
     * Calculate the inverse modulo m.
     * @param[in] m
     * @warning (*this) and m must be co-prime. It's all safe if m is a prime.
     * @return the inverse modulo m.
     */
    BN InvM(const BN &m) const;

    /**
     * Calculate the greatest common divisor of (*this) and n
     * @param[in] n
     * @return the greatest common divisor
     */
    BN Gcd(const BN &n) const;

    /**
     * Calculate the least common multiple of this and n.
     *      lcm(a, b) = ab/gcd(a,b))
     * @param[in] n
     * @return the least common multiple
     */
    BN Lcm(const BN &n) const;

    /**
     * Calculate the y-th power of this and modulo m
     *      r = (this ^ y) % m
     * @param[in] y
     * @param[in] m
     * @return the y-th power
     */
    BN PowM(const BN &y, const BN &m) const;

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
    BN SqrtM(const BN &m) const;

    /**
     * @brief Calculate square root of this object
     * 
     * @return BN the square root of this big number
     */
    BN Sqrt() const;

    /**
     * Check if a square root 'r' exists where
     *      r^2 == this (mod p),
     * @param[in] m
     * @return true if 'r' exists, false otherwise.
     */
    bool ExistSqrtM(const BN &m) const;

    /**
     * Return true is this is a prime, otherwise return false
     * @return true if this is probably prime, false otherwise.
     */
    bool IsProbablyPrime() const;

    /**
     * Conversion from hex string to BN.
     * @param[in] str
     * @return a BN object.
     */
    static BN FromHexStr(const char *str);

    /**
     * Conversion from HEX string to BN
     * @param[in] str
     * @return a BN object.
     */
    static BN FromHexStr(const std::string &str);

    /**
     * Conversion from decimal string to BN.
     * @param[in] str
     * @return a BN object.
     */
    static BN FromDecStr(const char *str);

    /**
     * Conversion from decimal string to BN
     * @param[in] str
     * @return a BN object.
     */
    static BN FromDecStr(const std::string &str);

    /**
     * Conversion from BN to HEX string
     * @param[out] str
     */
    void ToHexStr(std::string &str) const;

    /**
     * Conversion from BN to decimal string
     * @param[out] str
     */
    void ToDecStr(std::string &str) const;

    /**
     * Conversion from a byte buffer to a BN object in big endian
     * @param[in] buf
     * @param[in] len
     * @return a BN object
     */
    static BN FromBytesBE(const uint8_t *buf, int len);

    /**
     * Conversion from a byte buffer to a BN object in big endian
     * @param[in] buf
     * @return a BN object
     */
    static BN FromBytesBE(const std::string &buf);

    /**
     * Conversion from a byte buffer to a BN object in little endian
     * @param[in] buf
     * @param[in] len
     * @return a BN object
     */
    static BN FromBytesLE(const uint8_t *buf, int len);

    /**
     * Conversion from a byte buffer to a BN object in little endian
     * @param[in] buf
     * @return a BN object
     */
    static BN FromBytesLE(const std::string &buf);

    /**
     * Conversion to bytes string in big endian
     * @param[out] buf
     */
    void ToBytesBE(std::string &buf) const;

    /**
     * Conversion to bytes string in little endian
     * @param[out] buf
     */
    void ToBytesLE(std::string &buf) const;

    /**
     * Conversion to bytes string in big endian, which is 32 in length by byte
     * @param[out] buf
     */
    void ToBytes32BE(std::string &buf) const;

    /**
     * Conversion to bytes string in little endian, which is 32 in length by byte
     * @param[out] buf
     */
    void ToBytes32LE(std::string &buf) const;

    /**
     * Conversion to bytes string in big endian, which is 32 in length by byte
     * @param[out] buf32
     * @param[in] blen
     */
    void ToBytes32BE(uint8_t *buf32, int blen=32) const;

    /**
     * Conversion to bytes string in little endian, which is 32 in length by byte
     * @param[out] buf32
     * @param[in] blen
     */
    void ToBytes32LE(uint8_t *buf32, int blen=32) const;

    /**
     * Hold no a new BN object specified by "bn", which is a pointer to a memory in struct "bignum_st".
     * @warning "bn" must be created by the key word "new" and initialized before calling this API. It will be freed automatically in the destructor.
     * @param[in] bn
     */
    void Hold(bignum_st* bn);

    /**
     * Return bits size of this BN
     * @return bit size
     */
    size_t BitLength() const;

    /**
     * Return bytes size of this BN
     * @return bytes size.
     */
    size_t ByteLength() const;

    /**
     * Check if this BN is a negative number.
     * @return true if this BIGUN is a negative number, false otherwise.
     */
    bool IsNeg() const;

    /**
     * Check if this BN is even.
     * @return true if this BN is even, false otherwise.
     */
    bool IsEven() const;

    /**
     * Check if this BN is odd.
     * @return true if this BN is odd, false otherwise.
     */
    bool IsOdd() const;

    /**
     * Check if this BN is equal to zero.
     * @return true if this BN is equal to zero, false otherwise.
     */
    bool IsZero() const;

    /**
     * Return the max one between a and b
     * @param[in] a
     * @param[in] b
     * @return  max(a, b)
     */
    static BN Max(const BN &a, const BN &b);

    /**
     * Return the min one between a and b
     * @param[in] a
     * @param[in] b
     * @return min(a, b)
     */
    static BN Min(const BN &a, const BN &b);

    /**
     * Swap the values between a and b
     * @param[in,out] a
     * @param[in,out] b
     */
    static void Swap(BN &a, BN &b);

    /**
     * Set the bit in position "index".
     * @param[in] index the index of the bit
     */
    void SetBit(unsigned long index);

    /**
     * Clear the bit in position "index".
     * @param[in] index the index of the bit
     */
    void ClearBit(unsigned long index);

    /**
     * Check if the bit was set in position "index"
     * @param[in] index
     * @return true if the bit was set, false otherwise.
     */
    bool IsBitSet(unsigned long index) const;

    /**
     * Inspect the value.
     * @param[in] base 10 or 16 radix number
     * @return A string which indicate this BN to the specified base.
     */
    std::string Inspect(int base = 16) const;

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
    static void ExtendedEuclidean(const BN& a, const BN &b, BN &x, BN &y, BN &d);

    /**
     * Compute jacobi symbol (n, k)
     *
     * Refer to the page: https://en.wikipedia.org/wiki/Jacobi_symbol
     * @param[in] n
     * @param[in] k
     * @return jacobi(n, k)
     */
    static int JacobiSymbol(const BN &k, const BN &n);

    /**
     * Return the pointer to the internal struct.
     */
    const bignum_st* GetBIGNUM() const;

public:
    static const BN ZERO;       /**< constant value BN(0) */
    static const BN ONE;        /**< constant value BN(1) */
    static const BN TWO;        /**< constant value BN(2) */
    static const BN THREE;      /**< constant value BN(3) */
    static const BN FOUR;       /**< constant value BN(4) */
    static const BN FIVE;       /**< constant value BN(5) */

    static const BN MINUS_ONE;  /**< constant value BN(-1) */
private:
    struct bignum_st* bn_;      /**< a pointer to BIGNUM object */
};

};
};

#endif //SAFEHERON_BIG_NUMBER_H