# crypto-commitment-cpp

![img](../src/crypto-commitment-cpp/doc/logo.png)

This software implements a library for commitment scheme. The library comes with serialize/deserialize support to be used in higher level code to implement networking.



## Example

```c++
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-commitment/commitment.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::commitment::KgdCurvePoint;
using safeheron::commitment::KgdNumber;

int main(){
    const Curve * curv = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    BN r = safeheron::rand::RandomBNLt(curv->n);
    BN msg = safeheron::rand::RandomBNLt(curv->n);
    BN blind_factor = safeheron::rand::RandomBNLt(curv->n);
    CurvePoint point = curv->g * r;

    // Create a commitment
    std::string str;
    BN com_point = safeheron::commitment::CreateComWithBlind(point, blind_factor);
    com_point.ToHexStr(str);
    std::cout << "commitment of point:" << str << std::endl;
    
    return 0;
}
```

# Usage

## Namespace - safeheron::commitment
>- CreateComWithBlind(safeheron::bignum::BN &num, safeheron::bignum::BN &blind_factor) - Create a commitment of big number with specified blind factor.
>- CreateComWithBlind(curve::CurvePoint &point, safeheron::bignum::BN &blind_factor) - Create a commitment of CurvePoint with specified blind factor.
>- CreateComWithBlind(std::vector<curve::CurvePoint> &points, safeheron::bignum::BN &blind_factor) - Create an array of CurvePoint of big number with specified blind factor.

>- CreateCom(safeheron::bignum::BN &num) - Create a commitment of big number.
>- CreateCom(curve::CurvePoint &point, safeheron::bignum::BN &blind_facto) - Create a commitment of CurvePoint.
>- CreateCom(std::vector<curve::CurvePoint> &points) - Create an array of CurvePoint of big number.

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
