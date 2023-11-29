# crypto-sss-cpp

![img](../src/crypto-sss-cpp/doc/logo.png)

This software implements a library for secret sharing scheme. 

## Example

```c++
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-sss/vsss_secp256k1.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::sss::Point;
using safeheron::sss::Polynomial;
using std::vector;

int main(){
    // 4 shares with threshold 2: 2/4
    BN secret("85cf61629bc58c8f03af4e54c69f2a23cc7e967c19a48fb155ba1e08f999b385", 16);
    int threshold = 2;
    vector<CurvePoint> cmts;
    vector<Point> shares;
    vector<BN> shareIndexs;
    shareIndexs.push_back(BN("1", 16));
    shareIndexs.push_back(BN("2", 16));
    shareIndexs.push_back(BN("3", 16));
    shareIndexs.push_back(BN("4", 16));
    safeheron::sss::vsss_secp256k1::MakeSharesWithCommits(shares, cmts, secret, threshold, shareIndexs);

    for(int i = 0; i < shares.size(); i++){
        std::string str;
        shares[i].x.ToHexStr(str);
        std::cout << "index: " << str << std::endl;
        shares[i].y.ToHexStr(str);
        std::cout << "share: " << str << std::endl;
        EXPECT_TRUE(safeheron::sss::vsss_secp256k1::VerifyShare(cmts, shares[i].x, shares[i].y));
    }

    BN recovered_secret;
    safeheron::sss::vsss_secp256k1::RecoverSecret(recovered_secret, shares);

    EXPECT_TRUE(secret == recovered_secret);
    
    return 0;
}
```

# Usage
## Class - safeheron::sss::Polynomial
>- Polynomial(const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime) - Constructor of Polynomial
>- Polynomial(const safeheron::bignum::BN &secret, const std::vector<safeheron::bignum::BN> &coeArr, const safeheron::bignum::BN &prime) - Constructor of Polynomial
>- CreateRandomPolynomial(const safeheron::bignum::BN &secret, int threshold, const safeheron::bignum::BN &prime) - Create a random Polynomial with specified secret and threshold.

>- GetY(safeheron::bignum::BN &y, const safeheron::bignum::BN &x) - Get coordinate y of point with specified coordinate x for current polynomial.
>- GetYArray(std::vector<safeheron::bignum::BN> &yArr, const std::vector<safeheron::bignum::BN> &xArr) - Get an array of coordinate y of point with specified array of coordinate  x for current polynomial.
>- GetPoints(std::vector<Point> &vecPoint, const std::vector<safeheron::bignum::BN> &xArr) - Get an array of points with specified array of coordinate  x for current polynomial.
>- GetCommits(std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::curve::CurvePoint &g) - Get commitment of current polynomial.

>- VerifyCommits(const std::vector<safeheron::curve::CurvePoint> &commits, const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, const safeheron::curve::CurvePoint &g, const safeheron::bignum::BN &prime) - Verify commitment of current polynomial.
>- LagrangeInterpolate(safeheron::bignum::BN &y, const safeheron::bignum::BN &x, const std::vector<Point> &vecPoint, const safeheron::bignum::BN &prime ) - Lagrange interpolate.
>- GetLArray(std::vector<safeheron::bignum::BN> &lArr, const safeheron::bignum::BN &x, const std::vector<safeheron::bignum::BN> &xArr, const safeheron::bignum::BN &prime ) - Get coefficients for Lagrange interpolating.
 
## Namespace - safeheron::sss::vsss

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme. 
>- RecoverSecret(...) - Recover secret.

## Namespace - safeheron::sss::vsss_ed25519

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme.
>- RecoverSecret(...) - Recover secret.
 
## Namespace - safeheron::sss::vsss_secp256k1

>- MakeShares(...) - Make shares of 'secret'.
>- MakeSharesWithCommits(...) - Make shares with commitments for 'secret'.
>- MakeSharesWithCommitsAndCoes(...) - Make shares with commitments and coefficients for 'secret'.
>- VerifyShare(...) - Verify share in Feldman's scheme.
>- RecoverSecret(...) - Recover secret.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
