#include "chainparams.h"
#include "params.h"

namespace aura {

Params* Params::instance;
Params* Params::get_default() {
    if(instance != nullptr)
        return instance;
    else {
        //fixing generator G;
        GroupElement g;

        if(!(::Params().GetConsensus().IsTestnet())) {
            unsigned char buff[32] = {0};
            GroupElement base;
            base.set_base_g();
            base.sha256(buff);
            g.generate(buff);
        }
        else
            g = GroupElement("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                             "33986433546870000256104618635743654523665060392313886665479090285075695067131");

        //fixing n and m; N = n^m = 16,384
        int n = 4;
        int m = 7;
        int t_n = 4;
        int t_m = 7;
        int m_n = 4;
        int m_m = 7;
        instance = new Params(g, n, m, t_m, t_n, m_m, m_n);
        return instance;
    }
}

Params::Params(const GroupElement& g, int n, int m, int t_n, int t_m, int m_n, int m_m) :
    g_(g),
    m_(m),
    n_(n),
    t_m_(t_m),
    t_n_(t_n),
    m_m_(m_m),
    m_n_(m_n)

{
    unsigned char buff0[32] = {0};
    g.sha256(buff0);
    GroupElement h0;
    h0.generate(buff0);
    h_.reserve(28);
    h_.emplace_back(h0);
    for(int i = 1; i < n*m; ++i) {
        h_.push_back(GroupElement());
        unsigned char buff[32] = {0};
        h_[i - 1].sha256(buff);
        h_[i].generate(buff);
    }
}

Params::~Params(){
    delete instance;
}

const GroupElement& Params::get_g() const{
    return g_;
}
const GroupElement& Params::get_h0() const{
    return h_[0];
}

const std::vector<GroupElement>& Params::get_h() const{
    return h_;
}

uint64_t Params::get_n() const{
    return n_;
}
uint64_t Params::get_m() const{
    return m_;
}
    uint64_t Params::get_t_n() const{
        return t_n_;
    }
    uint64_t Params::get_t_m() const{
        return t_m_;
    }
    uint64_t Params::get_m_n() const{
        return m_n_;
    }
    uint64_t Params::get_m_m() const{
        return m_m_;
    }
} //namespace aura
