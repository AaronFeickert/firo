#ifndef FIRO_SPARK_PAYOUT_TRANSACTION_H
#define FIRO_SPARK_PAYOUT_TRANSACTION_H
#include "keys.h"
#include "coin.h"
#include "schnorr.h"
#include "util.h"

namespace spark {

using namespace secp_primitives;

struct PayoutCoinData {
	Address address;
	uint64_t v;
};

class PayoutTransaction {
public:
	PayoutTransaction(
		const Params* params,
		const PayoutCoinData& output,
		const std::vector<unsigned char>& serial_context
	);
	bool verify();

private:
	const Params* params;
	Coin coin;
	Address address;
	std::vector<unsigned char> serial_context;
};

}

#endif
