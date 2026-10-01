// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF22 gateway→wallet withdrawal: construction, the
// gateway_balance_proof (residual double-Schnorr), the connection-time
// commitment-sum check, inflation rejection, and the signer-side summary.
// Self-contained — no chain or DB is required, because the balance proof and
// sum check are pure functions of the transaction.

#include <gtest/gtest.h>

#include <cstring>
#include <stdexcept>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "device/device.hpp"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"

using namespace cryptonote;

namespace {

  constexpr network_type NET = network_type::MAINNET;
  constexpr hf HF = hf::hf22_gateway_addresses;

  // A random source gateway id (identity only; the balance proof / sum check
  // never touch DB state, so this need not be "registered" for these tests).
  crypto::public_key random_gateway_id()
  {
    crypto::public_key pk; crypto::secret_key sk;
    crypto::generate_keys(pk, sk);
    return pk;
  }

  account_public_address random_wallet_address()
  {
    account_base acc;
    acc.generate();
    return acc.get_keys().m_account_address;
  }

  // Build a valid gateway→wallet withdrawal spending `total + fee` from a
  // gateway, paying `total` split across `n` wallet outputs.
  transaction build_withdrawal(uint64_t total, uint64_t fee, size_t n,
                               crypto::hash& hash_to_sign)
  {
    std::vector<gateway_wallet_destination> dests;
    uint64_t remaining = total;
    for (size_t i = 0; i < n; ++i)
    {
      gateway_wallet_destination d{};
      d.addr   = random_wallet_address();
      d.amount = (i + 1 == n) ? remaining : total / n;
      remaining -= d.amount;
      dests.push_back(d);
    }
    transaction tx{};
    EXPECT_TRUE(construct_gateway_withdraw_to_wallet_tx(HF, NET, random_gateway_id(), dests, fee, tx, hash_to_sign));
    return tx;
  }

  TEST(GatewayWithdrawal, constructs_and_verifies)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    // One gateway input, two stealth (txout_to_key) outputs, BP+ type.
    EXPECT_TRUE(tx.has_gateway_inputs());
    EXPECT_EQ(tx.vout.size(), 2u);
    EXPECT_EQ(tx.rct_signatures.type, rct::RCTType::BulletproofPlus);

    // Exactly one balance proof, and it verifies.
    const gateway_balance_proof* bp = get_gateway_balance_proof(tx);
    ASSERT_NE(bp, nullptr);
    std::string reason;
    EXPECT_TRUE(verify_gateway_balance_proof(NET, tx, *bp, reason)) << reason;

    // The connection-time commitment-sum check passes.
    EXPECT_TRUE(verify_gateway_wallet_balance(tx, reason)) << reason;
  }

  TEST(GatewayWithdrawal, single_destination_expands_to_two_outputs)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(777, 7, 1, h); // one requested dest
    // Auto-split to satisfy the min-2-outputs rule.
    EXPECT_EQ(tx.vout.size(), 2u);
    std::string reason;
    EXPECT_TRUE(verify_gateway_wallet_balance(tx, reason)) << reason;
  }

  TEST(GatewayWithdrawal, inflation_via_tampered_output_is_rejected)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    // Simulate an inflated output: bump one output commitment by +1·H. The
    // outputs would now "carry" more value than the gateway was debited, so the
    // commitment-sum check must fail (Σ outPk + fee·H − in·H − mask_point ≠ 0).
    rct::addKeys(tx.rct_signatures.outPk[0].mask, tx.rct_signatures.outPk[0].mask,
                 rct::scalarmultH(rct::d2h(1)));

    std::string reason;
    EXPECT_FALSE(verify_gateway_wallet_balance(tx, reason));
  }

  TEST(GatewayWithdrawal, tampered_mask_point_is_rejected)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    const gateway_balance_proof* bp = get_gateway_balance_proof(tx);
    ASSERT_NE(bp, nullptr);
    gateway_balance_proof tampered = *bp;
    // Flip the mask point: the mask_sig (a Schnorr keyed by mask_point) no
    // longer verifies against it, so the proof is rejected. Without this the
    // residual could hide an H component (inflation).
    tampered.mask_point = random_gateway_id();

    std::string reason;
    EXPECT_FALSE(verify_gateway_balance_proof(NET, tx, tampered, reason));
  }

  TEST(GatewayWithdrawal, cross_network_message_differs)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(500, 5, 2, h);
    // The signing message is chain-bound: mainnet and testnet must differ, so a
    // signature from one network cannot be replayed on the other.
    EXPECT_NE(gateway_input_message(network_type::MAINNET, tx),
              gateway_input_message(network_type::TESTNET, tx));
  }

  TEST(GatewayWithdrawal, summary_is_signer_verifiable)
  {
    crypto::hash h{};
    const uint64_t total = 1000, fee = 10;
    transaction tx = build_withdrawal(total, fee, 2, h);

    gateway_withdraw_summary sum{};
    std::string reason;
    ASSERT_TRUE(summarize_gateway_withdraw(NET, tx, sum, reason)) << reason;

    EXPECT_TRUE(sum.to_wallet);                      // stealth outputs
    EXPECT_EQ(sum.total_debit, total + fee);         // amount leaving the gateway
    EXPECT_EQ(sum.fee, fee);
    EXPECT_TRUE(sum.gateway_dests.empty());          // recipients are hidden
    // The signer must be able to re-derive the exact hash it will sign from the
    // blob alone, matching what construction returned.
    EXPECT_EQ(sum.hash_to_sign, h);
  }

}

namespace {

  // A release proposal author holds both secrets the balance proof needs, so it can
  // re-prove any tx it edits. Each attack below therefore passes every check the
  // inspection already made (proof, sum, recipient, amount) and fails only the new one.
  struct release_fixture
  {
    account_base recipient;
    transaction tx;
    crypto::secret_key disclosed;
    crypto::secret_key mask_sum;

    release_fixture()
    {
      recipient.generate();
      gateway_wallet_destination dest{};
      dest.addr = recipient.get_keys().m_account_address;
      dest.amount = 1000000000000;
      tx_extra_gateway_release_ref ref{};
      ref.chain_id = 1;
      ref.evm_txid.data[0] = 1;
      crypto::hash h;
      if (!construct_gateway_withdraw_to_wallet_tx(hf::hf23_bridge, NET, random_gateway_id(),
              {dest}, 10000000, tx, h, &ref, &disclosed))
        throw std::runtime_error("release construction failed");
      crypto::key_derivation d;
      crypto::generate_key_derivation(dest.addr.m_view_public_key, disclosed, d);
      rct::key sum = rct::zero();
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::secret_key amount_key;
        crypto::derivation_to_scalar(d, i, amount_key);
        auto mask = hw::get_device("default").genCommitmentMask(rct::sk2rct(amount_key));
        sc_add(sum.bytes, sum.bytes, mask.bytes);
      }
      mask_sum = rct::rct2sk(sum);
    }

    void reprove(const crypto::secret_key& tx_secret)
    {
      tx.invalidate_hashes();
      tx.rct_signatures.message = rct::hash2rct(get_transaction_prefix_hash(tx));
      gateway_balance_proof proof;
      ASSERT_TRUE(generate_gateway_balance_proof(NET, tx, mask_sum, tx_secret, proof));
      tx.gateway_proofs[0] = proof;
      tx.invalidate_hashes();
    }

    // What gateway_decode_withdrawal checked before: valid proof and sum, and every
    // output opens, under the disclosed key, to the recipient for the full amount.
    void passes_the_existing_checks()
    {
      gateway_withdraw_summary summary;
      std::string reason;
      ASSERT_TRUE(summarize_gateway_withdraw(NET, tx, summary, reason)) << reason;
      ASSERT_TRUE(verify_gateway_balance_proof(NET, tx, *get_gateway_balance_proof(tx), reason)) << reason;
      ASSERT_TRUE(verify_gateway_wallet_balance(tx, reason)) << reason;
      const auto& addr = recipient.get_keys().m_account_address;
      crypto::key_derivation d;
      ASSERT_TRUE(crypto::generate_key_derivation(addr.m_view_public_key, disclosed, d));
      uint64_t paid = 0;
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::public_key expected;
        ASSERT_TRUE(crypto::derive_public_key(d, i, addr.m_spend_public_key, expected));
        ASSERT_EQ(expected, std::get<txout_to_key>(tx.vout[i].target).key);
        crypto::secret_key amount_key;
        crypto::derivation_to_scalar(d, i, amount_key);
        auto e = tx.rct_signatures.ecdhInfo[i];
        hw::get_device("default").ecdhDecode(e, rct::sk2rct(amount_key), true);
        const uint64_t amount = rct::h2d(e.amount);
        ASSERT_TRUE(rct::equalKeys(rct::commit(amount, e.mask), tx.rct_signatures.outPk[i].mask));
        paid += amount;
      }
      ASSERT_EQ(paid, 1000000000000u);
    }
  };

  TEST(GatewayWithdrawal, release_checks_accept_a_builder_payout)
  {
    release_fixture f;
    std::string reason;
    EXPECT_TRUE(verify_gateway_release_unlocks(f.tx, reason)) << reason;
    EXPECT_TRUE(verify_gateway_release_tx_key(f.tx, f.disclosed, reason)) << reason;
  }

  TEST(GatewayWithdrawal, release_rejects_a_locked_payout)
  {
    release_fixture f;
    for (auto& t : f.tx.output_unlock_times)
      t = 4102444800ULL; // 2100-01-01
    f.reprove(f.disclosed);
    f.passes_the_existing_checks();
    std::string reason;
    EXPECT_FALSE(verify_gateway_release_unlocks(f.tx, reason));
  }

  TEST(GatewayWithdrawal, release_rejects_a_payout_the_wallet_cannot_find)
  {
    release_fixture f;
    crypto::public_key other;
    crypto::secret_key other_secret;
    crypto::generate_keys(other, other_secret);
    ASSERT_TRUE(remove_field_from_tx_extra<tx_extra_pub_key>(f.tx.extra));
    add_tx_extra<tx_extra_pub_key>(f.tx, other);
    f.reprove(other_secret);
    f.passes_the_existing_checks();

    // The recipient's wallet derives from the public key in extra and finds nothing.
    crypto::key_derivation wallet_d;
    ASSERT_TRUE(crypto::generate_key_derivation(get_tx_pub_key_from_extra(f.tx),
                f.recipient.get_keys().m_view_secret_key, wallet_d));
    crypto::public_key wallet_expected;
    ASSERT_TRUE(crypto::derive_public_key(wallet_d, 0,
                f.recipient.get_keys().m_account_address.m_spend_public_key, wallet_expected));
    EXPECT_NE(wallet_expected, std::get<txout_to_key>(f.tx.vout[0].target).key);

    std::string reason;
    EXPECT_FALSE(verify_gateway_release_tx_key(f.tx, f.disclosed, reason));
  }

  TEST(GatewayWithdrawal, release_rejects_lock_and_type_variants)
  {
    release_fixture f;
    std::string reason;
    for (uint64_t lock : {uint64_t{1}, uint64_t{4102444800}})
    {
      auto tx = f.tx;
      tx.unlock_time = lock;
      EXPECT_FALSE(verify_gateway_release_unlocks(tx, reason));
      tx = f.tx;
      tx.output_unlock_times.back() = lock;
      EXPECT_FALSE(verify_gateway_release_unlocks(tx, reason));
    }
    auto tx = f.tx;
    tx.output_unlock_times.pop_back();
    EXPECT_FALSE(verify_gateway_release_unlocks(tx, reason));
    tx = f.tx;
    tx.version = txversion::v2_ringct;
    EXPECT_FALSE(verify_gateway_release_unlocks(tx, reason));
    tx = f.tx;
    tx.type = txtype::stake;
    EXPECT_FALSE(verify_gateway_release_unlocks(tx, reason));
  }

  TEST(GatewayWithdrawal, release_rejects_ambiguous_missing_and_invalid_keys)
  {
    release_fixture f;
    std::string reason;
    auto tx = f.tx;
    add_tx_extra<tx_extra_pub_key>(tx, get_tx_pub_key_from_extra(tx)); // duplicate
    EXPECT_FALSE(verify_gateway_release_tx_key(tx, f.disclosed, reason));
    tx = f.tx;
    ASSERT_TRUE(remove_field_from_tx_extra<tx_extra_pub_key>(tx.extra)); // none
    EXPECT_FALSE(verify_gateway_release_tx_key(tx, f.disclosed, reason));
    tx = f.tx;
    ASSERT_TRUE(add_additional_tx_pub_keys_to_extra(tx.extra, {}));
    EXPECT_FALSE(verify_gateway_release_tx_key(tx, f.disclosed, reason));
    tx = f.tx;
    tx.extra = {TX_EXTRA_TAG_PUBKEY}; // truncated
    EXPECT_FALSE(verify_gateway_release_tx_key(tx, f.disclosed, reason));

    EXPECT_FALSE(verify_gateway_release_tx_key(f.tx, crypto::null_skey, reason));
    rct::key not_a_scalar;
    std::memset(not_a_scalar.bytes, 0xff, sizeof(not_a_scalar.bytes));
    EXPECT_FALSE(verify_gateway_release_tx_key(f.tx, rct::rct2sk(not_a_scalar), reason));
  }

}
