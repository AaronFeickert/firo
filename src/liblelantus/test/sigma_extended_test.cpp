#include "../sigmaextended_prover.h"
#include "../sigmaextended_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>
#include <chrono>

namespace lelantus {

class SigmaExtendedTests : public LelantusTestingSetup {
public:
    struct Secret {
    public:
        Secret(std::size_t l) : l(l) {
            s.randomize();
            v.randomize();
            r.randomize();
        }

    public:
        std::size_t l;
        Scalar s, v, r;
    };

public:
    typedef SigmaExtendedProver Prover;
    typedef SigmaExtendedProof Proof;
    typedef SigmaExtendedVerifier Verifier;

public:
    SigmaExtendedTests() {}

public:
    void GenerateParams(std::size_t _N, std::size_t _n, std::size_t _m = 0) {
        N = _N;
        n = _n;
        m = _m;
        if (!m) {
            if (n <= 1) {
                throw std::logic_error("Try to get value of m from invalid n");
            }

            m = (std::size_t)std::round(log(N) / log(n));
        }

        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
    }

    void GenerateBatchProof(
        Prover &prover,
        std::vector<GroupElement> const &coins,
        std::size_t l,
        Scalar const &s,
        Scalar const &v,
        Scalar const &r,
        Scalar const &x,
        Proof &proof
    ) {
        auto gs = g * s.negate();
        std::vector<GroupElement> commits(coins.begin(), coins.end());
        for (auto &c : commits) {
            c += gs;
        }

        Scalar rA, rB, rC, rD;
        rA.randomize();
        rB.randomize();
        rC.randomize();
        rD.randomize();

        std::vector<Scalar> sigma;
        std::vector<Scalar> Tk, Pk, Yk;
        Tk.resize(m);
        Pk.resize(m);
        Yk.resize(m);

        std::vector<Scalar> a;
        a.resize(n * m);

        prover.sigma_commit(
            commits, l, rA, rB, rC, rD, a, Tk, Pk, Yk, sigma, proof);

        prover.sigma_response(
            sigma, a, rA, rB, rC, rD, v, r, Tk, Pk, x, proof);
    }

public:
    std::size_t N;
    std::size_t n;
    std::size_t m;

    std::vector<GroupElement> h_gens;
    GroupElement g;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_sigma_tests, SigmaExtendedTests)

BOOST_AUTO_TEST_CASE(one_out_of_N_variable_batch)
{
    const std::size_t N = 65536;
    const std::size_t n = 16;
    const std::size_t m = 4;
    const std::size_t batch = 20;
    GenerateParams(N, n, m);

    std::size_t commit_size = N; // require padding
    auto commits = RandomizeGroupElements(commit_size);

    // Generate
    std::vector<Secret> secrets;
    std::vector<std::size_t> indexes;
    std::vector<std::size_t> set_sizes;
    for (std::size_t j = 0; j < batch; j++) {
        indexes.emplace_back(j);
        set_sizes.emplace_back(N);
    }
    
    for (auto index : indexes) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r
        );
    }

    Prover prover(g, h_gens, n, m);
    Verifier verifier(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;
    std::vector<Scalar> challenges;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        Scalar x;
        x.randomize();
        proofs.emplace_back();
        serials.push_back(secrets[i].s);
        std::vector<GroupElement> commits_(commits.begin() + commit_size - set_sizes[i], commits.end());
        GenerateBatchProof(
            prover,
            commits_,
            secrets[i].l - (commit_size - set_sizes[i]),
            secrets[i].s,
            secrets[i].v,
            secrets[i].r,
            x,
            proofs.back()
        );
        challenges.emplace_back(x);
    }

    auto start = std::chrono::steady_clock::now();
    BOOST_CHECK(verifier.batchverify(commits, challenges, serials, set_sizes, proofs));
    auto stop = std::chrono::steady_clock::now();
    printf("Timing (ms) for batch %ld: %ld\n", batch, std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count());
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus