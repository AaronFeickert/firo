#ifndef ZCOIN_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H
#define ZCOIN_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class InnerProductProofVerifier {

public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    InnerProductProofVerifier(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
            const GroupElement& u,
            const GroupElement& P);

    bool verify(const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof);
    bool verify_fast(uint64_t n, const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof);

private:
    bool verify_util(
            const InnerProductProof<Exponent, GroupElement>& proof,
            typename std::vector<GroupElement>::const_iterator ltr_l,
            typename std::vector<GroupElement>::const_iterator itr_r);

    bool verify_fast_util(uint64_t n, const InnerProductProof<Exponent, GroupElement>& proof);

private:
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;

};

} // namespace lelantus

#include "innerproduct_proof_verifier.hpp"

#endif //ZCOIN_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H