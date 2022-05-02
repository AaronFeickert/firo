#ifndef FIRO_AURA_HOOM_PROVER_H
#define FIRO_AURA_HOOM_PROVER_H

#include "sigmaplus_prover.h"
#include "hoom_proof.h"

#include <cstddef>

namespace aura {

template <class Exponent, class GroupElement>
class HOOMProver{

public:
    HOOMProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens,
                    int t_n, int t_m, int m_n, int m_m);
    void proof(const std::vector<GroupElement>& commits,
               const int& l,
               const Exponent& r,
               HOOMProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    int t_n_;
    int t_m_;
    int m_n_;
    int m_m_;
};

} // namespace aura

#include "hoom_prover.hpp"

#endif // FIRO_AURA_SIGMA_SIGMAPLUS_PROVER_H
