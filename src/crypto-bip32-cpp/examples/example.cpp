#include "crypto-bn/bn.h"
#include "exception/located_exception.h"
#include "crypto-curve/curve.h"
#include "crypto-bip32/bip32.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/base58.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

int main(int argc, char **argv) {
    HDKey root_hd_key;
    string seed("000102030405060708090a0b0c0d0e0f");
    string path("m/0'/1/2'/2/1000000000");
    string data = hex::DecodeFromHex(seed);
    bool ok = root_hd_key.FromSeed(CurveType::SECP256K1, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    string xprv, xpub;
    root_hd_key.ToExtendedPrivateKey(xprv);
    root_hd_key.ToExtendedPublicKey(xpub);
    std::cout << "xprv: " << xprv << std::endl;
    std::cout << "xprv(hex)     :  " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    std::cout << "xpub: " << xpub << std::endl;
    std::cout << "xpub(hex)     :  " << hex::EncodeToHex(base58::DecodeFromBase58(xpub)) << std::endl;

    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    std::cout << "child_xprv: " << child_xprv << std::endl;
    std::cout << "child_xprv(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    std::cout << "child_xpub: " << child_xpub << std::endl;
    std::cout << "child_xpub(hex): " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    return 0;
}
