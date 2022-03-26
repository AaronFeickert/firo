#include "../params.h"
#include "../hoom_prover.h"
#include "../hoom_verifier.h"
#include "../hoom_proof.h"

#include <boost/test/unit_test.hpp>

#include "../../test/fixtures.h"

void test(int t_n, int t_m, int m_n, int m_m, int n, int m, int index)
{
    int N = std::pow(t_n, t_m) * std::pow(m_n, m_m);

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(1);
    h_gens[0].randomize();

    aura::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> sigmaprover(g, h_gens, n, m);
    aura::HOOMProver<secp_primitives::Scalar, secp_primitives::GroupElement> prover(g, h_gens, t_n, t_m, m_n, m_m);
    std::vector<secp_primitives::GroupElement> commits;
    secp_primitives::Scalar r;
    r.randomize();
    for (int i = 0; i < N; ++i){
        if (i == index) {
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = aura::SigmaPrimitives<secp_primitives::Scalar, secp_primitives::GroupElement>::commit(g, zero,
                                                                                                      h_gens[0], r);
            commits.push_back(c);
        } else {
            secp_primitives::GroupElement c;
            secp_primitives::Scalar value;
            value.randomize();
            c = aura::SigmaPrimitives<secp_primitives::Scalar, secp_primitives::GroupElement>::commit(g, value,
                                                                                                      h_gens[0], r);
            commits.push_back(c);
        }
    }

    aura::HOOMProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof(t_n, t_m, m_n, m_m);

    std::clock_t verify_start = std::clock();
    prover.proof(commits, index, r, proof);
    std::cout<< "HOOM PROOF GENERATED" << std::endl;
    std::cout <<" t_n = " << t_n <<" t_m = " << t_m <<" m_n = " << m_n <<" m_m = " << m_m;
    auto  duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Proof time  " <<  duration_clock << " ms \n";

    aura::HOOMVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(g, h_gens, t_n, t_m, m_n, m_m);

    verify_start = std::clock();
    if(verifier.verify(commits, proof))
        std::cout<< "PASSED" << std::endl;
    std::cout <<" t_n = " << t_n <<" t_m = " << t_m <<" m_n = " << m_n <<" m_m = " << m_m;
    duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Verify time  " <<  duration_clock << " ms \n";

    aura::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> sigmaproof(n, m);

    verify_start = std::clock();
    sigmaprover.proof(commits, index, r, true, sigmaproof);
    std::cout<< "SIGMA PROOF GENERATED" << std::endl;
    std::cout <<" N = " << N << " n = " << n << " m = " <<m;
    duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Proof time  " <<  duration_clock << " ms \n";

    aura::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> sigmaverifier(g, h_gens, n, m);
    verify_start = std::clock();
    if(sigmaverifier.verify(commits, sigmaproof, true))
        std::cout<< "PASSED" << std::endl;
    std::cout <<" N = " << N << " n = " << n << " m = " <<m;
    duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Verify time  " <<  duration_clock << " ms \n";
}


BOOST_FIXTURE_TEST_SUITE(aura_protocol_tests, ZerocoinTestingSetup200
)

BOOST_AUTO_TEST_CASE(one_out_of_n)
{


        test(2,6,4,6,8,6,11);
        test(2,6,5,6,10,6,11);
        test(2,7,4,7,8,7,11);
        test(2,8,3,8,6,8,11);
        test(2,8,3,8,6,8,11);


}



BOOST_AUTO_TEST_SUITE_END()
