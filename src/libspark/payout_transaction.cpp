#include "payout_transaction.h"

namespace spark {

PayoutTransaction::PayoutTransaction(
	const Params* params,
	const PayoutCoinData& output,
	const std::vector<unsigned char>& serial_context
) {
	// Important note: This construction assumes that the public coin value and address are correct according to higher-level consensus rules!
	// Important note: The serial context should contain a unique reference to the block height

	this->params = params;

	// Generate the coin
	Scalar k = SparkUtils::hash_payout(serial_context, output.address.get_d(), output.address.get_Q1(), output.address.get_Q2());
	this->coin = Coin(
		this->params,
		COIN_TYPE_PAYOUT,
		k,
		output.address,
		output.v,
		"", // the memo isn't included
		serial_context
	);

	this->address = output.address;
	this->serial_context = serial_context;
}

bool PayoutTransaction::verify() {
	// Try to generate the same coin
	Scalar k = SparkUtils::hash_payout(this->serial_context, this->address.get_d(), this->address.get_Q1(), this->address.get_Q2());
	Coin coin = Coin(
		this->params,
		COIN_TYPE_PAYOUT,
		k,
		this->address,
		this->coin.v,
		"", // the memo isn't included
		serial_context
	);

	return
		this->coin.type == coin.type &&
		this->coin.S == coin.S &&
		this->coin.K == coin.K &&
		this->coin.C == coin.C &&
		// the encrypted data field doesn't matter here
		this->coin.v == coin.v;
}

}
