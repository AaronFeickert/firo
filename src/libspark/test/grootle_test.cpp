#include "../grootle.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>
#include <chrono>

namespace spark {

static std::vector<GroupElement> random_group_vector(const std::size_t n) {
    std::vector<GroupElement> result;
    result.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        result[i].randomize();
    }
    return result;
}

BOOST_FIXTURE_TEST_SUITE(spark_grootle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(batch)
{
    // Parameters
    const std::size_t N = 65536;
    const std::size_t n = 16;
    const std::size_t m = 4;
    const std::size_t batch = 20;

    // Generators
    GroupElement H;
    H.randomize();
    std::vector<GroupElement> Gi = random_group_vector(n*m);
    std::vector<GroupElement> Hi = random_group_vector(n*m);

    // Commitments
    std::size_t commit_size = N; // require padding
    std::vector<GroupElement> S = random_group_vector(commit_size);
    std::vector<GroupElement> V = random_group_vector(commit_size);

    // Generate valid commitments to zero
    std::vector<std::size_t> indexes;
    std::vector<std::size_t> sizes;
    for (std::size_t j = 0; j < batch; j++) {
        indexes.emplace_back(j);
        sizes.emplace_back(N);
    }
    std::vector<GroupElement> S1, V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<Scalar> s, v;
    for (std::size_t index : indexes) {
        Scalar s_, v_;
        s_.randomize();
        v_.randomize();
        s.emplace_back(s_);
        v.emplace_back(v_);

        S1.emplace_back(S[index]);
        V1.emplace_back(V[index]);

        S[index] += H*s_;
        V[index] += H*v_;

        // Prepare random data in place of Merkle root
        Scalar temp;
        temp.randomize();
        std::vector<unsigned char> root;
        root.reserve(SCALAR_ENCODING);
        temp.serialize(root.data());
        roots.emplace_back(root);
    }

    // Prepare proving system
    Grootle grootle(H, Gi, Hi, n, m);
    std::vector<GrootleProof> proofs;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        proofs.emplace_back();
        std::vector<GroupElement> S_(S.begin() + commit_size - sizes[i], S.end());
        std::vector<GroupElement> V_(V.begin() + commit_size - sizes[i], V.end());
        grootle.prove(
            indexes[i] - (commit_size - sizes[i]),
            s[i],
            S_,
            S1[i],
            v[i],
            V_,
            V1[i],
            roots[i],
            proofs.back()
        );
    }

    auto start = std::chrono::steady_clock::now();
    BOOST_CHECK(grootle.verify(S, S1, V, V1, roots, sizes, proofs));
    auto stop = std::chrono::steady_clock::now();
    printf("Timing (ms) for batch %ld: %ld\n", batch, std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count());
}


BOOST_AUTO_TEST_SUITE_END()

}