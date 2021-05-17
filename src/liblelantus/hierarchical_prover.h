#ifndef FIRO_LIBLELANTUS_HIERARCHICAL_PROVER_H
#define FIRO_LIBLELANTUS_HIERARCHICAL_PROVER_H

#include "lelantus_primitives.h"
#include "sigmaextended_prover.h"
#include "challenge_generator_impl.h"

namespace lelantus {

class HierarchicalProver{

public:
    HierarchicalProver(
        const GroupElement& g,
        const GroupElement& h1,
        const GroupElement& h2,
        const std::vector<GroupElement>& h_gens_T,
        const std::vector<GroupElement>& h_gens_M,
        std::size_t n_T, std::size_t m_T,
        std::size_t n_M, std::size_t m_M);

    void proof(
        const std::vector<GroupElement>& C,
        int L,
        const Scalar& v,
        const Scalar& r,
        HierarchicalProof& proof_out);

    GroupElement digest(
        const std::vector<Scalar>& scalars,
        const std::vector<GroupElement>& points);
    
    SigmaExtendedProof build_sigma(
        SigmaExtendedProver& prover,
        unique_ptr<ChallengeGenerator>& transcript,
        const std::size_t n,
        const std::size_t m,
        const std::vector<GroupElement>& commits,
        const std::size_t l,
        const Scalar& v,
        const Scalar& r
    );

private:
    GroupElement g_;
    GroupElement h1_;
    GroupElement h2_;
    std::vector<GroupElement> h_T_;
    std::vector<GroupElement> h_M_;
    std::size_t n_T_;
    std::size_t m_T_;
    std::size_t n_M_;
    std::size_t m_M_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_HIERARCHICAL_PROVER_H
