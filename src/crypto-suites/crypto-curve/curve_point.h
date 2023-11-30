#ifndef SAFEHERON_CURVE_POINT_H
#define SAFEHERON_CURVE_POINT_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/proto_gen/curve_point.pb.switch.h"
#include "crypto-suites/crypto-curve/curve_type.h"

struct ec_group_st;
struct ec_point_st;

namespace safeheron{
namespace curve{

typedef unsigned char ed25519_public_key_byte32[32];

/**
 * Curve Point Class
 */
class CurvePoint {
    CurveType curve_type_;  /**< type of curve */
    const ec_group_st* curve_grp_;  /**< a pointer to a struct "ec_group_st" which was defined in library openssl. */
    /**
     * @union a block of memory to indicate the point.
     */
    union {
        ec_point_st* short_point_;  /**< a pointer to a struct "ec_point_st" */
        ed25519_public_key_byte32 edwards_point_;  /**< a memory to store the point on curve ed25519. */
    };

public:
    /**
     * Constructor for class CurvePoint.
     *
     * An blank CurvePoint will be created, that means:
     * \code{.cpp}
     *      CurvePoint point;
     *      assert(!point.IsValid());
     * \endcode
     *
     * @warning An object created by the constructor can't be used for any arithmetical operations on curve.
     */
    explicit CurvePoint();

    /**
     * Constructor.
     * @note An CurvePoint on Curve of "c_type" will be created, which will be initiated as an infinity point.
     *
     * \code{.cpp}
     *      CurvePoint point(CurveType::SECP256K1);
     *      assert(point.IsValid());
     *      assert(point.IsInfinity());
     * \endcode
     *
     * @param[in] c_type type of the curve
     */
    explicit CurvePoint(CurveType c_type);

    /**
     * Copy constructor.
     * @param[in] point
     */
    CurvePoint(const CurvePoint &point);            // copy constructor

    /**
     * Constructor.
     * @warning The constructor should be used carefully, usually invoked after the function "CurvePoint::ValidatePoint".
     *
     * \code{.cpp}
     *      if(!CurvePoint::ValidatePoint(x, y, cType)) return false;
     *      CurvePoint point(x, y, cType);
     * \endcode
     *
     * @param[in] x coordinate x of the curve point
     * @param[in] y coordinate y of the curve point
     * @param[in] c_type type of the curve
     */
    explicit CurvePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);

    /**
     * Copy assignment operator.
     * @param[in] point
     * @return A CurvePoint object.
     */
    CurvePoint &operator=(const CurvePoint &point);
    //CurvePoint(CurvePoint &&num) noexcept;           // move constructor
    //CurvePoint &operator=(CurvePoint &&point) noexcept;// move assignment

    /**
     * Destructor.
     */
    ~CurvePoint();

    /**
     * Return the type of the curve.
     * @return type of curve
     */
    CurveType GetCurveType() const;

    /**
     * Return the handler of the curve group.
     * @return the handler of group.
     */
    const ec_group_st* GetEcdsaCurveGrp() const;

    /**
     * Get information of the point
     * - < Infinity >
     * - < Curve: secp256k1, x: xxxxxxxxxx, y: xxxxxxxxxxxxxx >
     * @return a string to represent a CurvePoint object
     */
    std::string Inspect() const;

    /**
     * Check if the curve point is valid
     * @return true if the curve point is valid, false otherwise.
     */
    bool IsValid() const;

    /**
     * Check if the point with specified x and y is valid
     * @param[in] x
     * @param[in] y
     * @param[in] c_type
     * @return true if it's a valid curve point, false otherwise.
     */
    static bool ValidatePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);

    /**
     * Set this CurvePoint with the specified coordinate (x, y) and curve type.
     * @param x
     * @param y
     * @param c_type
     * @warning It will return false if the input parameter is invalid.
     * @return true if it succeed, false otherwise.
     */
    bool PointFromXY(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);

    /**
     * Check this CurvePoint is infinity
     * @return true if this CurvePoint is infinity, false otherwise.
     */
    bool IsInfinity() const;

    /**
     * Set this CurvePoint with the specified coordinate x, parity of coordinate y and curve type.
     * @param[in] x
     * @param[in] yIsOdd
     * @param[in] c_type
     * @warning It will return false if the input parameter is invalid.
     * @return true if it succeed, false otherwise.
     */
    bool PointFromX(safeheron::bignum::BN &x, bool yIsOdd, CurveType c_type);

    /**
     * Set this CurvePoint with the specified coordinate y, parity of coordinate x and curve type.
     * @param[in] y
     * @param[in] xIsOdd
     * @param[in] c_type
     * @warning It only works on Edwards curves, and it will return false if the input parameter is invalid.
     * @return true if it succeeded, false otherwise.
     */
    bool PointFromY(safeheron::bignum::BN &y, bool xIsOdd, CurveType c_type);

    /**
     * Encode this CurvePoint into 33 bytes(compressed format).
     * @param[out] pub33
     */
    void EncodeCompressed(uint8_t* pub33) const;

    /**
     * Decode 33 bytes(compressed format) and set this CurvePoint.
     * @param[in] pub33
     * @param[in] c_type
     * @return true if it succeeded, false otherwise.
     */
    bool DecodeCompressed(const uint8_t* pub33, CurveType c_type);

    /**
     * Encode this CurvePoint into 65 bytes(format of full public key).
     * @param[out] pub33
     */
    void EncodeFull(uint8_t* pub65) const;

    /**
     * Decode 65 bytes(full public key) and set this CurvePoint.
     * @param[in] pub65
     * @param[in] c_type
     * @return true if it succeeded, false otherwise.
     */
    bool DecodeFull(const uint8_t* pub65, CurveType c_type);

    /**
     * Encode the edwards point into 32 bytes.
     * @warning It will throw an exception if this CurvePoint came from a curve different from Ed25519.
     * @param[out] pub32
     */
    void EncodeEdwardsPoint(uint8_t *pub32) const;

    /**
     * Decode 32 bytes as an Edward point and set this CurvePoint.
     * @param[in] pub32
     * @param[in] c_type
     * @return
     */
    bool DecodeEdwardsPoint(uint8_t *pub32, CurveType c_type);

    /**
     * Addition on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      CurvePoint p2 = p0 + p1;
     * \endcode
     * @param[in] point
     * @return Res = *this + point
     */
    CurvePoint operator+(const CurvePoint &point) const;

    /**
     * Subtraction on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      CurvePoint p2 = p0 - p1;
     * \endcode
     * @param[in] point
     * @return Res = *this - point
     */
    CurvePoint operator-(const CurvePoint &point) const;

    /**
     * Multiplication on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      BN n(4);
     *          ......
     *      CurvePoint p2 = p0 * n;
     * \endcode
     * @param[in] point
     * @return Res = (*this) * bn
     */
    CurvePoint operator*(const safeheron::bignum::BN &bn) const;

    /**
     * Multiplication on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      long n = 4;
     *          ......
     *      CurvePoint p2 = p0 * n;
     * \endcode
     * @param[in] point
     * @return Res = (*this) * n
     */
    CurvePoint operator*(long n) const;

    /**
     * Self-Addition on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      p1 += p0;
     * \endcode
     * @param[in] point
     * @return *this += point
     */
    CurvePoint &operator+=(const CurvePoint &point);

    /**
     * Self-Subtraction on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      p1 -= p0;
     * \endcode
     * @param[in] point
     * @return *this -= point
     */
    CurvePoint &operator-=(const CurvePoint &point);

    /**
     * Self-Multiplication on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      BN n(4);
     *          ......
     *      p0 *= n;
     * \endcode
     * @param[in] point
     * @return *this *= bn
     */
    CurvePoint &operator*=(const safeheron::bignum::BN &bn);

    /**
     * Self-Multiplication on curve.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      long n = 4;
     *          ......
     *      p0 *= n;
     * \endcode
     * @param[in] point
     * @return *this *= bn
     */
    CurvePoint &operator*=(long n);

    /**
     * Get negative of this CurvePoint.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      p1 = p0.Neg();
     * \endcode
     * @return A CurvePoint object.
     */
    CurvePoint Neg() const;

    /**
     * Comparison between two points.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      bool ret = (p0 == p1);
     * \endcode
     * @param[in] point
     * @return  true if this CurvePoint is equal to "point", false otherwise.
     */
    bool operator==(const CurvePoint &point) const;

    /**
     * Comparison between two points.
     * \code{.cpp}
     *      CurvePoint p0(CurveType::Ed25519);
     *      CurvePoint p1(CurveType::Ed25519);
     *          ......
     *      bool ret = (p0 != p1);
     * \endcode
     * @param[in] point
     * @return  true if this CurvePoint is not equal to "point", false otherwise.
     */
    bool operator!=(const CurvePoint &point) const;

    /**
     * Get coordinate x of the point
     * @return coordinate x
     */
    safeheron::bignum::BN x() const;

    /**
     * Get coordinate y of the point
     * @return coordinate y
     */
    safeheron::bignum::BN y() const;

    /**
     * Serialize the point to a proto object.
     * @param[out] curve_point
     * @return true if no check fails; false otherwise.
     */
    bool ToProtoObject(safeheron::proto::CurvePoint &curve_point) const;

    /**
     * Deserialize from a proto object and set this CurvePoint.
     * @param[in] curve_point
     * @return true if no check fails; false otherwise.
     */
    bool FromProtoObject(const safeheron::proto::CurvePoint &curve_point);

    /**
     * Serialize the point to base64 string.
     * @param[out] base64
     * @return true if no check fails; false otherwise.
     */
    bool ToBase64(std::string& base64) const;

    /**
     * Deserialize from a base64 string and set this CurvePoint.
     * @param[in] base64
     * @return true if no check fails; false otherwise.
     */
    bool FromBase64(const std::string& base64);

    /**
     * Serialize the point to json.
     * @param[out] json_str
     * @return true if no check fails; false otherwise.
     */
    bool ToJsonString(std::string &json_str) const;

    /**
     * Deserialize from json and set this CurvePoint.
     * @param[in] json_str
     * @return true if no check fails; false otherwise.
     */
    bool FromJsonString(const std::string &json_str);

private:
    /**
     * Reset the state of the point.
     *
     * \code{.cpp}
     * CurvePoint p0();
     * assert(!p0.IsValid());
     *
     * CurvePoint p1(CurveType::SECP256K1);
     * assert(p1.IsValid());
     * assert(p1.IsInfinity());
     * p1.Reset();
     * assert(!p1.IsValid());
     * assert(p1 == p0);
     * \endcode
     */
    void Reset();

};

};
};
#endif //SAFEHERON_CURVE_POINT_H
