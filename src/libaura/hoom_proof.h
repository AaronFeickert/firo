#ifndef FIRO_AURA_HOOM_PROOF_H
#define FIRO_AURA_HOOM_PROOF_H

#include "params.h"
#include "sigmaplus_proof.h"

namespace aura {

template<class Exponent, class GroupElement>
class HOOMProof {
public:
    int t_n_;
    int t_m_;
    int m_n_;
    int m_m_;
    std::vector<GroupElement> d_;
    SigmaPlusProof<Exponent, GroupElement> d_Proof_;
    SigmaPlusProof<Exponent, GroupElement> D_Proof_;

public:
    HOOMProof(int t_n_, int t_m_, int m_n_, int m_m_):
        t_n_(t_n_), t_m_(t_m_), m_n_(m_n_), m_m_(m_m_), d_Proof_(m_n_, m_m_), D_Proof_(t_n_, t_m_) {};

public:
    bool operator==(const HOOMProof& other) const {
        return t_n_ == other.t_n_ &&
            t_m_ == other.t_m_ &&
            m_n_ == other.t_n_ &&
            m_m_ == other.t_m_ &&
            d_ == other.d_ &&
            d_Proof_ == other.d_Proof_ &&
            D_Proof_ == other.D_Proof_;
    }

    bool operator!=(const HOOMProof& other) const {
        return !(*this == other);
    }

public:
    inline int memoryRequired() const {
        return d_.memoryRequired()
               + d_Proof_.memoryRequired(m_n_, m_m_)
               + D_Proof_.memoryRequired(t_n_, t_m_);
    }

/*    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = B_.serialize(buffer);
        current = r1Proof_.serialize(current);
        for (std::size_t i = 0; i < Gk_.size(); ++i)
            current = Gk_[i].serialize(current);
        return z_.serialize(current);
    }

    inline unsigned const char* deserialize(unsigned const char* buffer) {
        unsigned const char* current = B_.deserialize(buffer);
        current = r1Proof_.deserialize(current, n, m);
        Gk_.resize(m);
        for(int i = 0; i < m; ++i)
            current = Gk_[i].deserialize(current);
        return z_.deserialize(current);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(B_);
        READWRITE(r1Proof_);
        READWRITE(Gk_);
        READWRITE(z_);
    } */
};

} //namespace aura

#endif // FIRO_AURA_HOOM_PROOF_H
