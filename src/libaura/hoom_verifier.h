#ifndef FIRO_AURA_HOOM_VERIFIER_H
#define FIRO_AURA_HOOM_VERIFIER_H

#include "sigmaplus_verifier.h"
#include "util.h"

namespace aura {
template<class Exponent, class GroupElement>
class HOOMVerifier{

public:
    HOOMVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      int t_n, int t_m, int m_n, int m_m);

    bool verify(const std::vector<GroupElement>& commits,
                const HOOMProof<Exponent, GroupElement>& proof) const;

    bool batch_verify(const std::vector<GroupElement>& commits,
                      const std::vector<Exponent>& serials,
                      const std::vector<HOOMProof<Exponent, GroupElement>>& proofs) const;


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    int t_n_;
    int t_m_;
    int m_n_;
    int m_m_;
};

} // namespace aura

#include "hoom_verifier.hpp"

#endif // FIRO_AURA_HOOM_VERIFIER_H
