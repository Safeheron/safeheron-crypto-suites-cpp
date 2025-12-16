#ifndef SAFEHERONCRYPTOSUITES_PDL_PROOF_H
#define SAFEHERONCRYPTOSUITES_PDL_PROOF_H
/**
* @brief This protocol is a zero knowledge proof of a Paillier encryption of a discrete log (PDL).
* It proves that a value encrypted in a given Paillier ciphertext is the discrete log of a given Elliptic curve point.
*
* We implemented two versions of PDL.
* PDLProver and PDLVerifier implement the original version of PDL described in the paper, which requires x to be in the range [q/3, 2*q/3]. Reference https://eprint.iacr.org/2017/552.
* We improved this in PDLProver_V2 and PDLVerifier_V2 by only requiring x to be in the range [0, q] to accommodate the lindell(+) protocol. Reference A Variant of Lindell17_Lindell(+).pdf.
*
* Statement: δ = (c, pail_pub, Q), where:
* Witness:   ω = (x, r, pail_priv)
* Prove relation: c = Enc(pail_pub, x, r) and Q = xG
*
* Process:
* V: message1(c1, c2) => P
* P: message2(commit(Q_hat)) => V
* V: message3(a, b) => P
* P: message4( decommit(Q_hat) ) => V
* V: Accept if it decommits successfully and Q_hat == Q_prime and the following Range Proof passes
*
*
*/

#include "pdl_common.h"
#include "PDLProver.h"
#include "PDLVerifier.h"
#include "PDLProver_V2.h"
#include "PDLVerifier_V2.h"
#include "pdl_message.h"
#endif //SAFEHERONCRYPTOSUITES_PDL_PROOF_H