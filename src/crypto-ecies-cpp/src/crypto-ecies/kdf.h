#ifndef SAFEHERON_CRYPTO_ECIES_KDF_H
#define SAFEHERON_CRYPTO_ECIES_KDF_H

#include <string>

namespace safeheron {
namespace ecies {

/**
 * The key derivation function (KDF) class for ECIES, belowing KDFs are implemented:
 * - X9.63
 * - KDF1 in 18033-2
 * - KDF2 in 18033-2
 */
class IKDF {
public:
    IKDF() {
        hash_nid_ = 0;
        iv_ = "";
    };

    IKDF(int hash_nid) {
        hash_nid_ = hash_nid;
        iv_ = "";
    };

    virtual ~IKDF() {};

    virtual int getHashNid() { return hash_nid_; };

    virtual void setIV(const std::string iv) { iv_ = iv; };

    virtual void getIV(std::string &iv) { iv = iv_; };

    virtual bool generateBytes(const unsigned char *input, size_t in_size, size_t out_size, std::string &out) = 0;

    virtual bool generateBytes(const std::string &input, size_t out_size, std::string &out) = 0;

protected:
    static bool
    baseKDF(int hash_nid, int iter_from, const unsigned char *input, size_t in_size, const unsigned char *salt,
            size_t salt_size, size_t out_size, std::string &out);

protected:
    int hash_nid_;
    std::string iv_;
};

//  Key derivation function from X9.63/SECG 
//  key = Hash(x||I2OSP(1, 4)||iv) || · · · ||Hash(x||I2OSP(k, 4)||iv))
//    where k = out_size/Hash.len
class KDF_X9_63 : public IKDF {
public:
    KDF_X9_63() {
        hash_nid_ = 0;
        iv_ = "";
    };

    KDF_X9_63(int hash_nid) {
        hash_nid_ = hash_nid;
        iv_ = "";
    };

    KDF_X9_63(int hash_nid, std::string iv) {
        hash_nid_ = hash_nid;
        iv_ = iv;
    };

    virtual ~KDF_X9_63() {};
public:
    bool generateBytes(const unsigned char *input, size_t in_size, size_t out_size, std::string &out);

    bool generateBytes(const std::string &input, size_t out_size, std::string &out);
};

//  Key derivation function1 (KDF1) from 18033-2 
//  key = Hash(x||I2OSP(0, 4)) || · · · ||Hash(x||I2OSP(k-1, 4)))
//    where k = out_size/Hash.len
class KDF1_18033 : public IKDF {
public:
    KDF1_18033() {
        hash_nid_ = 0;
        iv_ = "";
    };

    KDF1_18033(int hash_nid) {
        hash_nid_ = hash_nid;
        iv_ = "";
    };

    virtual ~KDF1_18033() {};
public:
    bool generateBytes(const unsigned char *input, size_t in_size, size_t out_size, std::string &out);

    bool generateBytes(const std::string &input, size_t out_size, std::string &out);
};

//  Key derivation function2 (KDF2) from 18033-2 
//  key = Hash(x||I2OSP(1, 4)) || · · · ||Hash(x||I2OSP(k, 4)))
//    where k = out_size/Hash.len
class KDF2_18033 : public IKDF {
public:
    KDF2_18033() {
        hash_nid_ = 0;
        iv_ = "";
    };

    KDF2_18033(int hash_nid) {
        hash_nid_ = hash_nid;
        iv_ = "";
    };

    virtual ~KDF2_18033() {};
public:
    bool generateBytes(const unsigned char *input, size_t in_size, size_t out_size, std::string &out);

    bool generateBytes(const std::string &input, size_t out_size, std::string &out);
};

}
}

#endif //SAFEHERON_CRYPTO_ECIES_KDF_H
