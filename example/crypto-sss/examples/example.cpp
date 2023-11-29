#include <cstring>
#include <vector>
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-sss/vsss_secp256k1.h"

using safeheron::bignum::BN;
using namespace safeheron::rand;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using namespace safeheron::sss;
using safeheron::sss::Point;
using safeheron::sss::Polynomial;
using std::vector;

int main(int argc, char **argv) {
    // 2 out of 4
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 2;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("1", 16));
    shareIndexs.push_back(BN("2", 16));
    shareIndexs.push_back(BN("3", 16));
    shareIndexs.push_back(BN("4", 16));
    vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, shareIndexs);

    for(int i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "x: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "y: " << str << std::endl;
        std::cout<< "Verify share: " << vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y);
    }

    BN recovered_secret;
    vsss_secp256k1::RecoverSecret(recovered_secret, shares);
    std::cout<< "Recover secret: " << (secret == recovered_secret) <<std::endl;
    return 0;
}
