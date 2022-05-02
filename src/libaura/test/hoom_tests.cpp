#include "../params.h"
#include "../sigmaplus_prover.h"
#include "../sigmaplus_verifier.h"
#include "../hoom_prover.h"
#include "../hoom_verifier.h"

#include <boost/test/unit_test.hpp>

#include "../../test/fixtures.h"

BOOST_FIXTURE_TEST_SUITE(aura_hoom_protocol_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(one_out_of_n)
{
    int N = 65536;
    int t_n = 2;
    int t_m = 3;
    int m_n = 3;
    int m_m = 4;
    int index = 20;

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(1);
    h_gens[0].randomize();
    aura::HOOMProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g, h_gens, t_n, t_m, m_n, m_m);
    std::vector<secp_primitives::GroupElement> commits;
    secp_primitives::Scalar r;
    r.randomize();
    for(int i = 0; i < N; ++i){
        if(i == index){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = aura::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);
        }
        else{
            secp_primitives::GroupElement c;
            secp_primitives::Scalar value;
            value.randomize();
            c = aura::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, value, h_gens[0], r);
            commits.push_back(c);
        }
    }
    aura::HOOMProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(t_n, t_m, m_n, m_m);

    prover.proof(commits, index, r, proof);

    aura::HOOMVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, t_n, t_m, m_n, m_m);

    BOOST_CHECK(verifier.verify(commits, proof));
}

BOOST_AUTO_TEST_SUITE_END()
