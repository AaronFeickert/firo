#ifndef FIRO_AURA_SIGMA_SIGMAPLUS_VERIFIER_H
#define FIRO_AURA_SIGMA_SIGMAPLUS_VERIFIER_H

#include "r1_proof_verifier.h"
#include "util.h"

namespace aura {
template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      int n, int m_);

    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof,
                bool fPadding,
                Exponent challenge) const;

    bool batch_verify(const std::vector<GroupElement>& commits,
                      const std::vector<Exponent>& serials,
                      const std::vector<bool>& fPadding,
                      const std::vector<size_t>& setSizes,
                      const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const;


    bool calculate_batch(const std::vector<GroupElement>& commits,
                         const SigmaPlusProof<Exponent, GroupElement>& proof,
                         GroupElement& t,
                         std::vector<Exponent>& f_i_,
                         GroupElement& zero_commit,
                         Exponent challenge) const;

    bool membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const;
    bool compute_fs(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, std::vector<Exponent>& f_) const;
    bool abcd_checks(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, const std::vector<Exponent>& f_) const;

    void compute_fis(int j, const std::vector<Exponent>& f, std::vector<Exponent>& f_i_) const;
    void compute_fis(const Exponent& f_i, int j, const std::vector<Exponent>& f, typename std::vector<Exponent>::iterator& ptr, typename std::vector<Exponent>::iterator end_ptr) const;
    void compute_batch_fis(
            const Exponent& f_i,
            int j,
            const std::vector<Exponent>& f,
            const Exponent& y,
            Exponent& e,
            typename std::vector<Exponent>::iterator& ptr,
            typename std::vector<Exponent>::iterator start_ptr,
            typename std::vector<Exponent>::iterator end_ptr) const;


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    int n;
    int m;
};

} // namespace aura

#include "sigmaplus_verifier.hpp"

#endif // FIRO_AURA_SIGMA_SIGMAPLUS_VERIFIER_H
