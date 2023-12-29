#include <cassert>
#include <openssl/ec.h>
#include <google/protobuf/util/json_util.h>
#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-curve/openssl_curve_wrapper.h"
#include "crypto-suites/crypto-curve/ed25519_ex.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/common/ByteArrayDeleter.h"
#include "crypto-suites/common/custom_assert.h"

using std::string;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using safeheron::exception::OpensslException;
using safeheron::exception::LocatedException;
using safeheron::bignum::BN;
using safeheron::common::ByteArrayDeleter;

namespace safeheron{
namespace curve {

/**
 * Get byte-length of coordinate x or y
 * @return
 *      - byte-length of coordinate x or y
 *      - -1 for invalid curve
 */
static int CoordinateLength(CurveType c_type){
    switch (c_type) {
        case CurveType::SECP256K1:
        case CurveType::P256:
#if ENABLE_STARK
        case CurveType::STARK:  /**< Curve Stark256v1 */
#endif //ENABLE_STARK
        case CurveType::ED25519: // Edwards curve: Ed25519
        {
            return 32;
        }
        default:
        {
            return -1;
        }
    }
}


/**
 * 0 -  short curve
 * 1 -  edwards curve
 * 2 -  montgomery curve
 */
static uint32_t get_category(CurveType curveType){
    uint32_t category = static_cast<uint32_t>(curveType) >> 5;
    return category;
}

void CurvePoint::Reset() {
    if (curve_type_ == CurveType::INVALID_CURVE) {
        return;
    }

    uint32_t category = get_category(curve_type_);
    if (0 == category) {
        EC_POINT_clear_free(short_point_);
        short_point_ = nullptr;
    }
    memset(edwards_point_, 0, sizeof(edwards_point_));
    
    curve_type_ = CurveType::INVALID_CURVE;
    curve_grp_ = nullptr;
}

CurveType CurvePoint::GetCurveType() const {
    return curve_type_;
}

const ec_group_st* CurvePoint::GetEcdsaCurveGrp() const {
    return curve_grp_;
}

CurvePoint::CurvePoint() {
    curve_type_ = CurveType::INVALID_CURVE;
    memset(edwards_point_, 0, sizeof(edwards_point_));
    curve_grp_ = nullptr;
}

CurvePoint::CurvePoint(CurveType c_type) {
    ASSERT_THROW(c_type != CurveType::INVALID_CURVE);

    curve_type_ = c_type;
    curve_grp_ = safeheron::curve::GetCurveGroup(curve_type_);

    uint32_t category = get_category(c_type);
    // Current point is initialized as Infinity Point(Zero Point).
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if (!(short_point_ = EC_POINT_new(curve_grp_))) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "!(short_point_ = EC_POINT_new(curve_grp_))");
            }
            if ((ret = EC_POINT_set_to_infinity(curve_grp_, short_point_)) != 1) {
                EC_POINT_clear_free(short_point_);
                short_point_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_set_to_infinity(curve_grp_, short_point_)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For all edwards curve and twist edwards curve, the point P = (0, 1) is the infinity 0.
            memset(edwards_point_, 0, sizeof(edwards_point_));
            edwards_point_[0] = 1;
            break;
        }
        default:
            break;
    }
}

CurvePoint::CurvePoint(const CurvePoint &point) {
    memset(&edwards_point_, 0, sizeof(edwards_point_));

    curve_type_ = point.curve_type_;
    curve_grp_ = safeheron::curve::GetCurveGroup(curve_type_);
    if(point.curve_type_ == CurveType::INVALID_CURVE) return;

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            if (!(short_point_ = EC_POINT_dup(point.short_point_, point.curve_grp_))) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "!(short_point_ = EC_POINT_dup(point.short_point_, point.curve_grp_))");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            memcpy(&edwards_point_, &point.edwards_point_, sizeof(edwards_point_));
            break;
        }
        default:
            break;
    }
}

CurvePoint::CurvePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type)
{
    memset(&edwards_point_, 0, sizeof(edwards_point_));

    ASSERT_THROW(c_type != CurveType::INVALID_CURVE);

    curve_type_ = c_type;
    curve_grp_ = safeheron::curve::GetCurveGroup(curve_type_);

    uint32_t category = get_category(c_type);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if (!(short_point_ = EC_POINT_new(curve_grp_))) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "!(short_point_ = EC_POINT_new(curve_grp_))");
            }
            if (x.IsZero() && y.IsZero()) {
                if ((ret = EC_POINT_set_to_infinity(curve_grp_, short_point_)) != 1) {
                    EC_POINT_clear_free(short_point_);
                    short_point_ = nullptr;
                    throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "x.IsZero() && y.IsZero()");
                }
            }
            else if ((ret = EC_POINT_set_affine_coordinates(curve_grp_, short_point_, x.GetBIGNUM(), y.GetBIGNUM(), nullptr)) != 1) {
                EC_POINT_clear_free(short_point_);
                short_point_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_set_affine_coordinates(curve_grp_, short_point_, x.GetBIGNUM(), y.GetBIGNUM(), nullptr)) != 1)");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            y.ToBytes32LE(edwards_point_);
            edwards_point_[31] ^= x.IsOdd() ? 0x80 : 0x00;
            break;
        }
        default:
            break;
    }
}

CurvePoint &CurvePoint::operator=(const CurvePoint &point) {
    // hand self-assignment
    if(this == &point) return *this;
    
    Reset();
    curve_type_ = point.curve_type_;
    curve_grp_ = point.curve_grp_;
    if(point.curve_type_ == CurveType::INVALID_CURVE) return *this;

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            if (!(short_point_ = EC_POINT_dup(point.short_point_, point.curve_grp_))) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "!(short_point_ = EC_POINT_dup(point.short_point_, point.curve_grp_))");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            memcpy(&edwards_point_, &point.edwards_point_, sizeof(edwards_point_));
            break;
        }
        default:
            break;
    }
    return *this;
}

CurvePoint::~CurvePoint() {
    Reset();
}

std::string CurvePoint::Inspect() const {
    std::string c_name, x_str, y_str, ret;
    if(curve_type_ == CurveType::INVALID_CURVE ){
        return "curve [invalid curve]\n";
    }
    if (curve_type_ == CurveType::SECP256K1) {
        c_name = "curve Secp256k1";
    }
    if (curve_type_ == CurveType::P256) {
        c_name = "curve P256";
    }
#if ENABLE_STARK
    if (curve_type_ == CurveType::STARK) {
        c_name = "curve STARK";
    }
#endif //ENABLE_STARK
    if (curve_type_ == CurveType::ED25519) {
        c_name = "curve Ed25519";
    }
    if(IsInfinity()){
        ret = c_name + std::string("[infinity]\n");
    } else{
        x().ToHexStr(x_str);
        y().ToHexStr(y_str);
        ret = c_name + std::string("\n  -x=") + x_str + std::string("\n") +std::string("  -y=")+ y_str+std::string("\n");
    }
    return ret;
}

bool CurvePoint::IsValid() const {
    return curve_type_ != CurveType::INVALID_CURVE;
}

bool CurvePoint::ValidatePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type) {
    if(c_type == CurveType::INVALID_CURVE) return false;
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    uint32_t category = get_category(c_type);
    // Current point is initialized as Infinity Point(Zero Point).
    switch (category) {
        case 0: // Short curve
        {
            // Zero element
            if(x == 0 && y == 0) return true;
            // y^2 = x^3 + a*x + b
            BN left = (y * y) % curv->p;
            BN x_sqr = (x * x) % curv->p;
            BN right = (x_sqr * x + curv->a * x + curv->b) % curv->p;
            return left == right;
        }
        case 1: // Edwards curve
        {
            // For Twisted Edwards curves, not only Ed25519.
            // y^2 = (a * x^2 - 1) / (d * x^2 - 1)  % p
            // Same as:
            // a * x^2 + y^2 = 1 + d * x^2 * y^2
            BN x_sqr = (x * x) % curv->p;
            BN y_sqr = (y * y) % curv->p;
            BN left = (curv->a * x_sqr + y_sqr) % curv->p;
            BN x_sqr_y_sqr = (x_sqr * y_sqr ) % curv->p;
            BN right = (curv->d * x_sqr_y_sqr + 1) % curv->p;
            return left == right;
        }
        default:
            return false;
    }
}

bool CurvePoint::PointFromXY(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type) {
    bool is_valid = CurvePoint::ValidatePoint(x, y, c_type);
    if(!is_valid) return false;
    
    Reset();
    CurvePoint point(x, y, c_type);
    *this = point;
    return true;
}

bool CurvePoint::IsInfinity() const {
    if(curve_type_ == CurveType::INVALID_CURVE) return false;
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            return EC_POINT_is_at_infinity(curve_grp_, short_point_);
        }
        case 1: // Edwards curve
        {
            // For Ed25519, Infinity Point = (x, y) = (0, 1)
            bool ret = (edwards_point_[0] == 1);
            for (size_t i = 1; i < sizeof(edwards_point_); ++i) {
                ret = ret && (edwards_point_[i] == 0);
            }
            return ret;
        }
        default:
            return false;
    }
}

bool CurvePoint::PointFromX(const safeheron::bignum::BN &x, bool y_is_odd, CurveType c_type) {
    if(c_type == CurveType::INVALID_CURVE) return false;
    Reset();
    curve_type_ = c_type;
    curve_grp_ = safeheron::curve::GetCurveGroup(curve_type_);

    uint32_t category = get_category(c_type);
    // Current point is initialized as Infinity Point(Zero Point).
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if (!(short_point_ = EC_POINT_new(curve_grp_))) {
                return false;
            }
            if ((ret = EC_POINT_set_compressed_coordinates(curve_grp_, short_point_, x.GetBIGNUM(), y_is_odd, nullptr)) != 1) {
                EC_POINT_clear_free(short_point_);
                short_point_ = nullptr;
                return false;
            }
            return true;        }
        case 1: // Edwards curve
        {
            // For Ecdsa, not only Ed25519.
            const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
            // y^2 = (a * x^2 - 1) / (d * x^2 - 1)  % p
            safeheron::bignum::BN x_sqr = (x * x) % curv->p;
            safeheron::bignum::BN num = (curv->a * x_sqr - 1) % curv->p;
            safeheron::bignum::BN den = (curv->d * x_sqr - 1) % curv->p;
            safeheron::bignum::BN y_sqr = (num * den.InvM(curv->p)) % curv->p;
            safeheron::bignum::BN y = y_sqr.SqrtM(curv->p);
            if (y < 0) {
                return false;
            }
            if ((y * y) % curv->p != y_sqr) {
                return false;
            }
            if ((y.IsOdd() && !y_is_odd) || (!y.IsOdd() && y_is_odd)) {
                y = curv->p - y;
            }
            safeheron::curve::CurvePoint point(x, y, c_type);
            *this = point;
            return true;
        }
        default:
            return false;
    }
}

bool CurvePoint::PointFromY(const safeheron::bignum::BN &y, bool x_is_odd, CurveType c_type) {
    if(c_type == CurveType::INVALID_CURVE) return false;
    Reset();
    curve_type_ = c_type;
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
    BN y_sqr = (y * y) % curv->p;
    BN c_sqr = (curv->c * curv->c) % curv->p;
    // u = (y^2 - c^2)
    BN u = (y_sqr - c_sqr) % curv->p;
    // v = (c^2 d y^2 - a)
    BN v = (c_sqr * curv->d * y_sqr - curv->a) % curv->p;
    BN x_sqr = (u * v.InvM(curv->p)) % curv->p;

    BN x = x_sqr.SqrtM(curv->p);
    if (x < 0) {
        return false;
    }
    if ((x * x) % curv->p != x_sqr) {
        return false;
    }
    if ((x.IsOdd() && !x_is_odd) || (!x.IsOdd() && x_is_odd)) {
        x = curv->p - x;
    }
    safeheron::curve::CurvePoint point(x, y, c_type);
    *this = point;
    return true;
}

void CurvePoint::EncodeCompressed(uint8_t* pub33) const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    if(IsInfinity()) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "Failed in CurvePoint::EncodeCompressed(uint8_t* pub33): IsInfinity");
    }
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub33, 33, true)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub33, true)) != 0");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            char y_is_odd = edwards_point_[0] & 0x1 ;
            pub33[0] = 0x02 + y_is_odd; // 0x02 or 0x03
            x().ToBytes32BE(pub33 + 1);
            break;
        }
        default:
            break;
    }
}

bool CurvePoint::DecodeCompressed(const uint8_t* pub33, CurveType c_type) {
    if((pub33[0] != 0x02) && (pub33[0] != 0x03)) return false;
    CurvePoint t_point;
    BN x = BN::FromBytesBE(pub33 + 1, 32);
    char sign = pub33[0] - 0x02;
    bool y_is_odd = (sign == 1);
    bool ret = t_point.PointFromX(x, y_is_odd, c_type);
    if(!ret) return false;
    *this = t_point;
    return true;
}

void CurvePoint::EncodeFull(uint8_t* pub65) const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    // Refuse to encode infinity point
    if(IsInfinity()) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, -1, "Failed in CurvePoint::EncodeFull(uint8_t* pub65): IsInfinity");
    }
    // Full public key
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub65, 65, false)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub65, false)) != 0");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            pub65[0] = 0x04;
            x().ToBytes32BE(pub65 + 1);
            y().ToBytes32BE(pub65 + 33);
            break;
        }
        default:
            break;
    }
}

bool CurvePoint::DecodeFull(const uint8_t* pub65, CurveType c_type) {
    if(pub65[0] != 0x04) return false;
    BN x = BN::FromBytesBE(pub65 + 1, 32);
    BN y = BN::FromBytesBE(pub65 + 33, 32);
    bool ret = CurvePoint::ValidatePoint(x, y, c_type);
    if(!ret) return false;
    CurvePoint t_point(x, y, c_type);
    *this = t_point;
    return true;
}

void CurvePoint::EncodeEdwardsPoint(uint8_t *pub) const {
    if(curve_type_ != CurveType::ED25519){
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, static_cast<int>(curve_type_), "curve_type_ != CurveType::ED25519");
    }
    memcpy(pub, edwards_point_, 32);
}

bool CurvePoint::DecodeEdwardsPoint(const uint8_t *pub, CurveType c_type) {
    Reset();
    curve_type_ = c_type;

    // We need to check if "pub" is valid
    // Get y coordinate, Reverse copy
    uint8_t point_y[32];
    for(int i = 0; i < 32; i++){
        point_y[i] = pub[31 - i];
    }
    point_y[0] &= 0x7f;
    bool x_is_odd = (pub[31] & 0x80) != 0;
    BN y = BN::FromBytesBE(point_y, 32);

    // Get x
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
    BN y_sqr = (y * y) % curv->p;
    BN c_sqr = (curv->c * curv->c) % curv->p;
    // u = (y^2 - c^2)
    BN u = (y_sqr - c_sqr) % curv->p;
    // v = (c^2 d y^2 - a)
    BN v = (c_sqr * curv->d * y_sqr - curv->a) % curv->p;
    BN x_sqr = (u * v.InvM(curv->p)) % curv->p;

    if(!x_sqr.ExistSqrtM(curv->p)) return false;

    memcpy(edwards_point_, pub,32);
    return true;
}

void CurvePoint::EncodeCompressed(std::string & bytes) const{
    if(curve_type_ == CurveType::INVALID_CURVE){
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, static_cast<int>(curve_type_), "curve_type_ == CurveType::INVALID_CURVE");
    }

    bytes.clear();

    if(IsInfinity()) {
        bytes.push_back(0x00);
        return;
    }

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int coord_len = CoordinateLength(curve_type_);
            if(coord_len < 0){
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, coord_len, "invalid CoordinateLength");
            }
            // 02/03 + X
            int pub_bytes_len = coord_len + 1;
            std::unique_ptr<uint8_t[], ByteArrayDeleter> pub_bytes(new uint8_t[pub_bytes_len], ByteArrayDeleter(pub_bytes_len));
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub_bytes.get(), pub_bytes_len, true)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub33, true)) != 0");
            }
            bytes.assign((char *)pub_bytes.get(), pub_bytes_len);
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            uint8_t pub33[33];
            char y_is_odd = edwards_point_[0] & 0x1 ;
            pub33[0] = 0x02 + y_is_odd; // 0x02 or 0x03
            x().ToBytes32BE(pub33 + 1);
            bytes.assign((char *)pub33, 33);
            memset(pub33, 0, sizeof pub33);
            break;
        }
        default:
            throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "Invalid Curve Type!");
    }
}

bool CurvePoint::DecodeCompressed(const std::string &bytes, CurveType c_type){
    // 00 : infinity point
    if(bytes.length() == 1){
        if(bytes[0] == 0x00) {
            *this = CurvePoint(c_type);
            return true;
        } else{
            return false;
        }
    }

    int coord_len = CoordinateLength(curve_type_);
    if(coord_len < 0) return false;

    // 02/03 + X
    size_t pub_bytes_len = coord_len + 1;
    if(pub_bytes_len != bytes.length()) return false;

    // First byte = 0x02/0x03
    if((bytes[0] != 0x02) && (bytes[0] != 0x03)) return false;
    CurvePoint t_point;
    BN x = BN::FromBytesBE((const uint8_t *)bytes.data() + 1, coord_len);
    bool y_is_odd = bytes[0] - 0x02;
    bool ret = t_point.PointFromX(x, y_is_odd, c_type);
    if(!ret) return false;
    *this = t_point;
    return true;
}

void CurvePoint::EncodeFull(std::string &bytes) const{
    if(curve_type_ == CurveType::INVALID_CURVE){
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, static_cast<int>(curve_type_), "curve_type_ == CurveType::INVALID_CURVE");
    }

    bytes.clear();

    if(IsInfinity()) {
        bytes.push_back(0x00);
        return;
    }

    // Full public key
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int coord_len = CoordinateLength(curve_type_);
            if(coord_len < 0){
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, coord_len, "invalid CoordinateLength");
            }
            // 02/03 + X + Y
            int pub_bytes_len = coord_len * 2 + 1;
            std::unique_ptr<uint8_t[], ByteArrayDeleter> pub_bytes(new uint8_t[pub_bytes_len], ByteArrayDeleter(pub_bytes_len));
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub_bytes.get(), pub_bytes_len, false)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub_bytes.get(), pub_bytes_len, false) != 0");
            }
            bytes.assign((char *)pub_bytes.get(), pub_bytes_len);
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            uint8_t pub65[65];
            pub65[0] = 0x04;
            x().ToBytes32BE(pub65 + 1);
            y().ToBytes32BE(pub65 + 33);
            bytes.assign((const char *)pub65, 65);
            memset(pub65, 0, 65);
            break;
        }
        default:
            throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "Invalid curve type!");
    }
}

bool CurvePoint::DecodeFull(const std::string &bytes, CurveType c_type){
    // 00 : infinity point
    if(bytes.length() == 1){
        if(bytes[0] == 0x00) {
            *this = CurvePoint(c_type);
            return true;
        } else{
            return false;
        }
    }

    // 04 + X + Y
    int coord_len = CoordinateLength(curve_type_);
    if(coord_len < 0) return false;

    size_t pub_bytes_len = coord_len * 2 + 1;
    if(pub_bytes_len != bytes.length()) return false;

    // check first byte
    if(bytes[0] != 0x04) return false;

    // get x, y
    BN x = BN::FromBytesBE((const uint8_t *)bytes.data() + 1, coord_len);
    BN y = BN::FromBytesBE((const uint8_t *)bytes.data() + coord_len + 1, coord_len);
    // validate x, y
    bool ret = CurvePoint::ValidatePoint(x, y, c_type);
    if(!ret) return false;
    // return point
    CurvePoint t_point(x, y, c_type);
    *this = t_point;
    return true;
}

void CurvePoint::EncodeEdwardsPoint(std::string &bytes) const{
    if(curve_type_ != CurveType::ED25519){
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, static_cast<int>(curve_type_), "curve_type_ != CurveType::ED25519");
    }
    bytes.assign((const char *)edwards_point_, 32);
}

bool CurvePoint::DecodeEdwardsPoint(const std::string &bytes, CurveType c_type){
    // only Ed25519 is supported
    if(c_type != CurveType::ED25519) return false;

    // get coordinate length and check it
    int coord_len = CoordinateLength(c_type);
    if(coord_len < 0) return false;
    // check input bytes
    if((size_t )coord_len != bytes.length()) return false;

    Reset();
    curve_type_ = c_type;

    // We need to check if "pub" is valid
    // Get y coordinate, Reverse copy
    uint8_t point_y[32];
    for(int i = 0; i < 32; i++){
        point_y[i] = bytes[31 - i];
    }
    point_y[0] &= 0x7f;
    bool x_is_odd = (bytes[31] & 0x80) != 0;
    BN y = BN::FromBytesBE(point_y, 32);

    // Get x
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
    BN y_sqr = (y * y) % curv->p;
    BN c_sqr = (curv->c * curv->c) % curv->p;
    // u = (y^2 - c^2)
    BN u = (y_sqr - c_sqr) % curv->p;
    // v = (c^2 d y^2 - a)
    BN v = (c_sqr * curv->d * y_sqr - curv->a) % curv->p;
    BN x_sqr = (u * v.InvM(curv->p)) % curv->p;

    if(!x_sqr.ExistSqrtM(curv->p)) return false;

    memcpy(edwards_point_, bytes.data(),32);
    return true;
}


CurvePoint CurvePoint::operator+(const CurvePoint &point) const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    ASSERT_THROW(curve_type_ == point.curve_type_);
    CurvePoint res(*this);

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if ((ret = EC_POINT_add(curve_grp_, res.short_point_, point.short_point_, res.short_point_, nullptr)) != 1) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_add(curve_grp_, res.short_point_, point.short_point_, res.short_point_, nullptr)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            ed25519_cosi_combine_two_publickeys(res.edwards_point_, edwards_point_, point.edwards_point_);
            break;
        }
        default:
            break;
    }
    return res;
}

CurvePoint CurvePoint::operator-(const CurvePoint &point) const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    ASSERT_THROW(curve_type_ == point.curve_type_);
    CurvePoint res = *this + point.Neg();
    return res;
}

CurvePoint CurvePoint::operator*(const safeheron::bignum::BN &bn) const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    CurvePoint res(*this);
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type_);
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            BN k = bn % curv->n;
            if ((ret = EC_POINT_mul(curve_grp_, res.short_point_, nullptr, res.short_point_, k.GetBIGNUM(), nullptr)) != 1) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_mul(curve_grp_, res.short_point_, nullptr, res.short_point_, k.GetBIGNUM(), nullptr)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            ed25519_secret_key sk;
            if(bn.ByteLength() > 32){
                BN t_bn = bn % curv->n;
                t_bn.ToBytes32LE(sk);
            } else{
                bn.ToBytes32LE(sk);
            }
            if(*this == curv->g){
                // Fast multiply
                ed25519_publickey_pure(sk, res.edwards_point_);
            }else{
                ed25519_scalarmult_pure(res.edwards_point_, sk, edwards_point_);
            }
            break;
        }
        default:
            break;
    }
    return res;
}

CurvePoint CurvePoint::operator*(long n) const {
    BN bn(n);
    return *this * bn;
}

CurvePoint &CurvePoint::operator+=(const CurvePoint &point){
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    ASSERT_THROW(curve_type_ == point.curve_type_);
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            if ((ret = EC_POINT_add(curve_grp_, short_point_, point.short_point_, short_point_, nullptr)) != 1) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_add(curve_grp_, short_point_, point.short_point_, short_point_, nullptr)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            ed25519_cosi_combine_two_publickeys(edwards_point_, edwards_point_, point.edwards_point_);
            break;
        }
        default:
            break;
    }
    return *this;
}

CurvePoint &CurvePoint::operator-=(const CurvePoint &point){
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    ASSERT_THROW(curve_type_ == point.curve_type_);
    *this = *this + point.Neg();
    return *this;
}

CurvePoint &CurvePoint::operator*=(const safeheron::bignum::BN &bn){
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type_);
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            BN k = bn % curv->n;
            if ((ret = EC_POINT_mul(curve_grp_, short_point_, nullptr, short_point_, k.GetBIGNUM(), nullptr)) != 1) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_mul(curve_grp_, short_point_, nullptr, short_point_, k.GetBIGNUM(), nullptr)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            ed25519_secret_key sk;
            if(bn.ByteLength() > 32){
                BN t_bn = bn % curv->n;
                t_bn.ToBytes32LE(sk);
            } else{
                bn.ToBytes32LE(sk);
            }
            ed25519_scalarmult_pure(edwards_point_, sk, edwards_point_);
            break;
        }
        default:
            break;
    }
    return *this;
}

CurvePoint &CurvePoint::operator*=(long n){
    BN bn(n);
    (*this) *= bn;
    return *this;
}

CurvePoint CurvePoint::Neg() const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);

    CurvePoint res(*this);

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int ret = 0;
            // (x, y) => (x, -y)
            if ((ret = EC_POINT_invert(curve_grp_, res.short_point_, nullptr)) != 1) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = EC_POINT_invert(curve_grp_, res.short_point_, nullptr)) != 1");
            }
            break;
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            ed25519_publickey_neg(res.edwards_point_, (unsigned char *)edwards_point_);
            break;
        }
        default:
            break;
    }
    return res;
}

bool CurvePoint::operator==(const CurvePoint &point) const {
    bool same_mem = false;
    bool same_type = (curve_type_ == point.curve_type_);

    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            if (EC_POINT_cmp(curve_grp_, short_point_, point.short_point_, nullptr) == 0) {
                same_mem = true;
            }
            break;
        }
        case 1: // Edwards curve
        {
            same_mem = (memcmp((const void *)&edwards_point_, (const void *)&point.edwards_point_, sizeof(ed25519_public_key)) == 0);
            break;
        }
        default:
            same_mem = false;
            break;
    }

    return same_type && same_mem;
}

bool CurvePoint::operator!=(const CurvePoint &point) const {
    return !(*this == point);
}

safeheron::bignum::BN CurvePoint::x() const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int coord_len = CoordinateLength(curve_type_);
            if(coord_len < 0){
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, coord_len, "invalid CoordinateLength");
            }
            // 02/03 + x + y
            int pub_bytes_len = coord_len * 2 + 1;
            std::unique_ptr<uint8_t[], ByteArrayDeleter> pub_bytes(new uint8_t[pub_bytes_len], ByteArrayDeleter(pub_bytes_len));
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub_bytes.get(), pub_bytes_len, false)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, xy, false)) != 0");
            }
            // return x
            return safeheron::bignum::BN::FromBytesBE(pub_bytes.get() + 1, coord_len);
        }
        case 1: // Edwards curve
        {
            // For Ecdsa, not only Ed25519
            // Get y coordinate, Reverse copy
            bool x_is_odd = (edwards_point_[31] & 0x80) != 0;
            BN y = this->y();

            // Get x
            const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type_);
            // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
            BN y_sqr = (y * y) % curv->p;
            BN c_sqr = (curv->c * curv->c) % curv->p;
            // u = (y^2 - c^2)
            BN u = (y_sqr - c_sqr) % curv->p;
            // v = (c^2 d y^2 - a)
            BN v = (c_sqr * curv->d * y_sqr - curv->a) % curv->p;
            BN x_sqr = (u * v.InvM(curv->p)) % curv->p;

            BN x = x_sqr.SqrtM(curv->p);
            if ((x.IsOdd() && !x_is_odd) || (!x.IsOdd() && x_is_odd)) {
                x = curv->p - x;
            }
            return x;
        }
        default:
            throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "Unexpected exception in CurvePoint::x()");
    }
}

safeheron::bignum::BN CurvePoint::y() const {
    ASSERT_THROW(curve_type_ != CurveType::INVALID_CURVE);
    BN y;
    uint32_t category = get_category(curve_type_);
    switch (category) {
        case 0: // Short curve
        {
            int coord_len = CoordinateLength(curve_type_);
            if(coord_len < 0){
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, coord_len, "invalid CoordinateLength");
            }
            // 02/03 + x + y
            int pub_bytes_len = coord_len * 2 + 1;
            std::unique_ptr<uint8_t[], ByteArrayDeleter> pub_bytes(new uint8_t[pub_bytes_len], ByteArrayDeleter(pub_bytes_len));
            int ret = 0;
            if ((ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, pub_bytes.get(), pub_bytes_len, false)) != 0) {
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret, "(ret = safeheron::_openssl_curve_wrapper::encode_ec_point(curve_grp_, short_point_, xy, false)) != 0");
            }
            // return Y
            return safeheron::bignum::BN::FromBytesBE(pub_bytes.get() + coord_len + 1, coord_len);
        }
        case 1: // Edwards curve
        {
            // For Ed25519
            // Get y coordinate, Reverse copy
            uint8_t point_y[32];
            memcpy(point_y, edwards_point_, 32);
            point_y[31] &= 0x7f;
            return BN::FromBytesLE(point_y, 32);
        }
        default:
            throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "Unexpected exception in CurvePoint::y()");
    }
}

bool CurvePoint::ToProtoObject(safeheron::proto::CurvePoint &point) const {
    if(curve_type_ == CurveType::INVALID_CURVE) return false;
    string str;
    if(!IsInfinity()) {
        x().ToHexStr(str); point.set_x(str);
        y().ToHexStr(str); point.set_y(str);
    }
    switch (curve_type_) {
        case CurveType::SECP256K1:
            point.set_curve("secp256k1");
            break;
        case CurveType::P256:
            point.set_curve("p256");
            break;
#if ENABLE_STARK
        case CurveType::STARK:
            point.set_curve("stark");
            break;
#endif //ENABLE_STARK
        case CurveType::ED25519:
            point.set_curve("ed25519");
            break;
        case CurveType::INVALID_CURVE:
            // Can't touch
            break;
    }
    return true;
}

bool CurvePoint::FromProtoObject(const safeheron::proto::CurvePoint &point) {
    CurveType c_type = CurveType::INVALID_CURVE;
    if(strncasecmp(point.curve().c_str(), "secp256k1", point.curve().length()) == 0){
        c_type = CurveType::SECP256K1;
    }else if(strncasecmp(point.curve().c_str(), "p256", point.curve().length()) == 0){
        c_type = CurveType::P256;
#if ENABLE_STARK
    }else if(strncasecmp(point.curve().c_str(), "stark", point.curve().length()) == 0){
        c_type = CurveType::STARK;
#endif //ENABLE_STARK
    }else if(strncasecmp(point.curve().c_str(), "ed25519", point.curve().length()) == 0) {
        c_type = CurveType::ED25519;
    }
    if(point.x().length() == 0 || point.y().length() == 0){
        // for infinity point, x,y is empty in json format
        CurvePoint t_point(c_type);
        *this = t_point;
        return true;
    }else{
        BN x = BN::FromHexStr(point.x());
        BN y = BN::FromHexStr(point.y());
        if(!CurvePoint::ValidatePoint(x, y, c_type)) return false;
        CurvePoint t_point(x, y, c_type);
        *this = t_point;
        return true;
    }
}

bool CurvePoint::ToBase64(string &base64) const {
    bool ok = true;
    base64.clear();
    safeheron::proto::CurvePoint proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    base64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool CurvePoint::FromBase64(const string &base64) {
    bool ok = true;

    string data = safeheron::encode::base64::DecodeFromBase64(base64);

    safeheron::proto::CurvePoint proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool CurvePoint::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    safeheron::proto::CurvePoint proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}

bool CurvePoint::FromJsonString(const string &json_str) {
    safeheron::proto::CurvePoint proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
