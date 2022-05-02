#include <math.h>
#include <iostream>

namespace aura {

    template<class Exponent, class GroupElement>
    HOOMVerifier<Exponent, GroupElement>::HOOMVerifier(const GroupElement &g,
                                                       const std::vector <GroupElement> &h_gens,
                                                       int t_n, int t_m, int m_n, int m_m)
            : g_(g), h_(h_gens), t_n_(t_n), t_m_(t_m), m_n_(m_n), m_m_(m_m) {
    }

    template<class Exponent, class GroupElement>
    bool HOOMVerifier<Exponent, GroupElement>::verify(const std::vector <GroupElement> &commits,
                                                      const HOOMProof <Exponent, GroupElement> &proof) const {


        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> d_verifier(g_, h_, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> D_verifier(g_, h_, t_n_, t_m_);

        //binds the commitments to the y challenge
        Exponent y;
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(commits, y);

        //checks one out of many sigma proof for the blinded subset
        if(!d_verifier.verify(proof.d_, proof.d_Proof_, true, y)) {
            LogPrintf("Hierarchic one out of many proof failed due to d_ check failed.");
            return false;
        }

        //generates x challenge using the y challenge calculated in the sigma
        std::vector<Scalar> x;
        x.resize(m_);
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * y}, x[0]);
        for (int k = 1; k < m_; ++k) {
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * x[k - 1]}, x[k]);
        }

        //creates digests of the subsets
        std::vector <GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof.d_, x);
        for (int k = 0; k < t_; ++k) {
            D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction({commits.begin() + k * m_, commits.begin() + (k + 1) * m_}, x).inverse();
        }

        //the proof that the digest of our blinded subset is a member of the digests of all subsets
        if(!D_verifier.verify(D_, proof.D_Proof_, true, x[m_ - 1])) {
            LogPrintf("Hierarchic one out of many proof failed due to D_ check failed.");
            return false;
        }
        return true;
    }

    template<class Exponent, class GroupElement>
    bool HOOMVerifier<Exponent, GroupElement>::batch_verify(const std::vector<GroupElement>& commits,
                                                      const std::vector<Exponent>& serials,
                                                      const std::vector<HOOMProof<Exponent, GroupElement>>& proofs)  const {

        //Pre-hashing the commits for challenge generation
        Exponent commits_hash;
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(commits, commits_hash);

        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        int batchsize = serials.size();

        std::vector <GroupElement> D_;
        D_.resize(t_);
        GroupElement D;

        GroupElement left;
        GroupElement right;

        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> d_verifier(g_, h_, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> D_verifier(g_, h_, t_n_, t_m_);

        std::vector<Exponent> x;
        x.resize(m_);

        //where we calculate the powers required for the exponentation
        std::vector<Exponent> pows;
        pows.resize(commits.size());

        for(int i = 0; i < batchsize; ++i){
            //those values are used to store the results of SigmaPlusVerifier's calculate_batch()
            GroupElement t;
            std::vector<Exponent> f_i_;
            GroupElement zero_commit;

            //checks the one out of many proof in the blinded subset
            Exponent y = commits_hash;
            if(!d_verifier.verify(proofs[i].d_, proofs[i].d_Proof_, true, y)){
                LogPrintf("Hierarchic one out of many proof failed due to d_ check failed.");
                return false;
            }

            //generates the x challenge and the subset digests
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * y}, x[0]);
            for (int k = 1; k < m_; ++k) {
                SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * x[k - 1]}, x[k]);
            }
            D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proofs[i].d_, x);
            for (int k = 0; k < t_; ++k) {
                D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction({commits.begin() + k * m_, commits.begin() + (k + 1) * m_}, x).inverse();
            }

            //We use temporary variable to not alter the x[m_ - 1] value
            Exponent xtemp = x[m_ - 1];
            if(!D_verifier.calculate_batch(D_, proofs[i].D_Proof_, t, f_i_, zero_commit, xtemp)){
                LogPrintf("Hierarchic one out of many proof failed due to one of D_ checks failed.");
                return false;
            }

            //uses the f_i to add up the powers of commits in the final batch
            Exponent f_i_sum;
            for(int k = 0; k < t_; ++k){
                for(int j = 0; j < m_; ++j) {
                    pows[k * m_ + j] += x[j] * f_i_[k] * serials[i];
                }
                //used for the right side of the equation
                f_i_sum += f_i_[k];
            }

            left += t * serials[i];
            right += zero_commit * serials[i] + D.inverse() * f_i_sum * serials[i];
        }

        secp_primitives::MultiExponent mult(commits, pows);
        left += mult.get_multiple().inverse();

        if(left != right) {
            LogPrintf("Hierarchic one out of many proof failed due to final batch check failed.");
            return false;
        }
        return true;
    }

} // namespace aura
