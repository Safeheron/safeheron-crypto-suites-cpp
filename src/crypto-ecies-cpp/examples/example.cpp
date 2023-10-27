#include <cstring>
#include "crypto-bn/rand.h"
#include "crypto-curve/curve.h"
#include "crypto-encode/hex.h"
#include "crypto-ecies/ecies.h"
#include "crypto-ecies/auth_enc.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::ecies::ECIES;
using safeheron::ecies::AuthEnc;

int main(int argc, char **argv) {
    bool ok = true;
    std::string str;
    std::string data;
    const Curve *curv = GetCurveParam(CurveType::P256);

    std::string message = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18};
    std::string plain;
    std::string cypher;
    std::string iv;

    // private key
    BN priv = safeheron::rand::RandomBNLt(curv->n);
    priv.ToBytes32BE(data);
    std::cout << "priv: " << safeheron::encode::hex::EncodeToHex(data) << std::endl;

    // public key(in full format)
    CurvePoint pub = curv->g * priv;
    uint8_t buf65[65];
    pub.EncodeFull(buf65);
    std::cout << "pub(full format): " << safeheron::encode::hex::EncodeToHex(buf65, 65) << std::endl;

    // ecies encryption
    ECIES enc;
    enc.set_curve_type(CurveType::P256);
    ok = enc.Encrypt(pub, message, iv, cypher);
    std::cout << "succeed to encrypt: " << ok << std::endl;
    std::cout << "iv: " << safeheron::encode::hex::EncodeToHex(iv) << std::endl;
    std::cout << "cypher: " << safeheron::encode::hex::EncodeToHex(cypher) << std::endl;

    // ecies decryption
    ok = enc.Decrypt(priv, cypher, iv, plain);
    std::cout << "succeed to encrypt: " << ok << std::endl;
    std::cout << "plain: " << safeheron::encode::hex::EncodeToHex(plain) << std::endl;

    // comparison
    bool is_same = true;
    for(size_t i = 0; i < message.length(); i ++){
        if(message[i] != plain[i]){
            is_same = false;
            break;
        }
    }
    std::cout << "compare: " << is_same << std::endl;

    return 0;
}
