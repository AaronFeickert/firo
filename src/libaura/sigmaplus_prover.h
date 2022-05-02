#ifndef FIRO_AURA_SIGMA_SIGMAPLUS_PROVER_H
#define FIRO_AURA_SIGMA_SIGMAPLUS_PROVER_H

#include "r1_proof_generator.h"
#include "sigmaplus_proof.h"

#include <cstddef>

namespace aura {

template <class Exponent, class GroupElement>
class SigmaPlusProver{

public:
    SigmaPlusProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, int n, int m);
    void proof(const std::vector<GroupElement>& commits,
               std::size_t l,
               const Exponent& r,
               bool fPadding,
               Exponent challenge,
               SigmaPlusProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    int n_;
    int m_;
};

} // namespace aura

#include "sigmaplus_prover.hpp"

#endif // FIRO_AURA_SIGMA_SIGMAPLUS_PROVER_H
