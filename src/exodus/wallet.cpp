#include "wallet.h"

#include "sigma.h"

#include "../main.h"
#include "../sync.h"
#include "../util.h"

#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/function_output_iterator.hpp>

#include <functional>

namespace exodus {

Wallet *wallet;

Wallet::Wallet(const std::string& walletFile) : walletFile(walletFile)
{
    using std::placeholders::_1;
    using std::placeholders::_2;
    using std::placeholders::_3;
    using std::placeholders::_4;
    using std::placeholders::_5;
    using std::placeholders::_6;

    // Subscribe to events.
    LOCK(cs_main);

    {
        auto h = std::bind(&Wallet::OnMintAdded, this, _1, _2, _3, _4, _5, _6);
        eventConnections.emplace_front(sigmaDb->MintAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnMintRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb->MintRemoved.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnSpendAdded, this, _1, _2, _3, _4);
        eventConnections.emplace_front(sigmaDb->SpendAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnSpendRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb->SpendRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

SigmaMintId Wallet::CreateSigmaMint(PropertyId property, SigmaDenomination denomination)
{
    SigmaPrivateKey priv;
    std::tie(std::ignore, priv) = mintWallet.GenerateMint(property, denomination);

    return SigmaMintId(property, denomination, SigmaPublicKey(priv, DefaultSigmaParams));
}

void Wallet::ClearAllChainState()
{
    mintWallet.ClearMintsChainState();
}

SigmaSpend Wallet::CreateSigmaSpend(PropertyId property, SigmaDenomination denomination)
{
    LOCK(cs_main);

    auto mint = GetSpendableSigmaMint(property, denomination);
    if (!mint) {
        throw InsufficientFunds(_("No available mint to spend"));
    }

    // Get anonimity set for spend.
    std::vector<SigmaPublicKey> anonimitySet;

    sigmaDb->GetAnonimityGroup(
        mint->property,
        mint->denomination,
        mint->chainState.group,
        std::back_inserter(anonimitySet)
    );

    if (anonimitySet.size() < 2) {
        throw WalletError(_("Amount of coins in anonimity set is not enough to spend"));
    }

    // Create spend.
    auto key = GetKey(mint.get());
    SigmaProof proof(DefaultSigmaParams, key, anonimitySet.begin(), anonimitySet.end());

    if (!VerifySigmaSpend(mint->property, mint->denomination, mint->chainState.group, anonimitySet.size(), proof)) {
        throw WalletError(_("Failed to create spendable spend"));
    }

    return SigmaSpend(SigmaMintId(mint->property, mint->denomination, SigmaPublicKey(key, DefaultSigmaParams)),
        mint->chainState.group, anonimitySet.size(), proof);
}

void Wallet::DeleteUnconfirmedSigmaMint(const SigmaMintId &id)
{
    mintWallet.DeleteUnconfirmedMint(id);
}

bool Wallet::HasSigmaMint(const SigmaMintId& id)
{
    return mintWallet.HasMint(id);
}

bool Wallet::HasSigmaMint(const secp_primitives::Scalar& serial)
{
    return mintWallet.HasMint(serial);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    return mintWallet.GetMint(id);
}

boost::optional<SigmaMint>
    Wallet::GetSpendableSigmaMint(PropertyId property, SigmaDenomination denomination)
{
    // Get all spendable mints.
    std::vector<SigmaMint> spendables;

    mintWallet.ListMints(boost::make_function_output_iterator(
        [denomination, &spendables] (SigmaMint const &mint) {

            // doesn't match
            if (denomination != mint.denomination) {
                return;
            }

            // is not on chain
            if (mint.chainState.block < 0) {
                return;
            }

            // is spend
            if (!mint.spendTx.IsNull()) {
                return;
            }

            spendables.push_back(mint);
        }
    ));

    if (spendables.empty()) {
        return boost::none;
    }

    // Pick the oldest mint.
    auto oldest = std::min_element(
        spendables.begin(),
        spendables.end(),
        [](const SigmaMint& a, const SigmaMint& b) -> bool {

            if (a.chainState.group == b.chainState.group) {
                return a.chainState.index < b.chainState.index;
            }

            return a.chainState.group < b.chainState.group;
        }
    );

    return *oldest;
}

SigmaPrivateKey Wallet::GetKey(const SigmaMint &mint)
{
    return mintWallet.GeneratePrivateKey(mint.seedId);
}

void Wallet::SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx)
{
    mintWallet.UpdateMintSpendTx(id, tx);
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    mintWallet.UpdateMintChainstate(id, state);
}

void Wallet::OnSpendAdded(
    PropertyId property,
    SigmaDenomination denomination,
    const secp_primitives::Scalar &serial,
    const uint256 &tx)
{
    if (!HasSigmaMint(serial)) {
        // the serial is not in wallet.
        return;
    }

    SigmaMintId id;
    try {
        id = mintWallet.GetMintId(serial);
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to get mint id when spend added have been triggered, %s\n", e.what());
        throw;
    }
    SetSigmaMintUsedTransaction(id, tx);
}

void Wallet::OnSpendRemoved(
    PropertyId property,
    SigmaDenomination denomination,
    const secp_primitives::Scalar &serial)
{
    if (!HasSigmaMint(serial)) {
        // the serial is not in wallet.
        return;
    }

    try {
        auto id = mintWallet.GetMintId(serial);
        SetSigmaMintUsedTransaction(id, uint256());
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to get mint id when spend removed have been triggered, %s\n", e.what());
        throw;
    }
}

void Wallet::OnMintAdded(
    PropertyId property,
    SigmaDenomination denomination,
    SigmaMintGroup group,
    SigmaMintIndex idx,
    const SigmaPublicKey& pubKey,
    int block)
{
    SigmaMintId id(property, denomination, pubKey);

    if (HasSigmaMint(id)) {

        // 1. is in wallet then update state
        SetSigmaMintChainState(id, SigmaMintChainState(block, group, idx));
    } else {

        // 2. try to recover new mint
        if (mintWallet.TryRecoverMint(
            id, SigmaMintChainState(block, group, idx)
        )) {
            LogPrintf("%s : Found new mint when try to recover\n", __func__);
        }
    }
}

void Wallet::OnMintRemoved(PropertyId property, SigmaDenomination denomination, const SigmaPublicKey& pubKey)
{
    SigmaMintId id(property, denomination, pubKey);

    if (!HasSigmaMint(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState());
}

} // namespace exodus
