#ifndef FIRO_AURA_PARAMS_H
#define FIRO_AURA_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace aura {

class Params {
public:
    static Params* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const std::vector<GroupElement>& get_h() const;
    uint64_t get_n() const;
    uint64_t get_m() const;
    uint64_t get_t_n() const;
    uint64_t get_t_m() const;
    uint64_t get_m_n() const;
    uint64_t get_m_m() const;

private:
   Params(const GroupElement& g, int n, int m, int t_n, int t_m, int m_n, int m_m);
    ~Params();

private:
    static Params* instance;
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
    int t_m_;
    int t_n_;
    int m_m_;
    int m_n_;
};

}//namespace aura

#endif //FIRO_AURA_PARAMS_H
