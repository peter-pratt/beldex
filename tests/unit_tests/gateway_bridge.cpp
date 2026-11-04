// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF23 "Sovereign Bridge" Phase A additions layered on the
// HF22 gateway feature:
//   - governance freeze / re-point supermajority-evidence verification (A.1/A.2)
//   - per-window release-cap accounting + exact-inverse rewind (A.3, S9)
//   - deposit-routing memo encryption round-trip (A.5)
//   - governance-message domain separation (S6/S14 on the native leg)
//
// These exercise the novel consensus logic in isolation (a small in-memory DB
// stub drives append/rewind; a mock quorum resolver drives evidence checks), so
// no full chain or LMDB instance is required. End-to-end on-chain freeze/repoint
// acceptance (which needs a real checkpoint quorum) lives in the core tests.

#include <gtest/gtest.h>

#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "checkpoints/checkpoints.h" // complete checkpoint_t for BaseTestDB's checkpoint vectors
#include "blockchain_db/testdb.h"
#include "cryptonote_core/uptime_proof.h" // complete uptime_proof::Proof for BaseTestDB's proof_info map
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_core/master_node_list.h"     // state_t + bridge_committee_resolver (Phase F consensus action)
#include "cryptonote_core/master_node_quorum_cop.h" // quorum / quorum_manager
#include "cryptonote_core/uptime_proof.h"          // complete uptime_proof::Proof for master_node_info's proof dtor
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/eddsa_signature.h"

#include <limits>
#include <memory>
#include <set>
#include <algorithm>
#include <optional>
#include <unordered_set>
#include <sodium/crypto_sign.h> // ed25519 keypair/sign for the slash-evidence test

using namespace cryptonote;

namespace
{
  constexpr network_type NET = network_type::MAINNET;

  // Minimal in-memory gateway DB: only the gateway-account table is backed, which
  // is all append/rewind/validation touch here.
  class MemGatewayDB : public BaseTestDB
  {
  public:
    std::map<crypto::public_key, std::string> store;
    uint64_t chain_height = 1;
    uint64_t height() const override { return chain_height; }
    // Each block its own hash, so a message bound to one block cannot pass for another.
    crypto::hash get_block_hash_from_height(const uint64_t& h) const override
    {
      return crypto::cn_fast_hash(&h, sizeof(h));
    }

    void set_gateway_account(const crypto::public_key& id, const std::string& data) override { store[id] = data; }
    bool get_gateway_account(const crypto::public_key& id, std::string& data) const override
    {
      auto it = store.find(id);
      if (it == store.end()) return false;
      data = it->second;
      return true;
    }
    bool remove_gateway_account(const crypto::public_key& id) override { return store.erase(id) > 0; }
    bool gateway_exists(const crypto::public_key& id) const override { return store.count(id) > 0; }

    std::map<std::pair<crypto::public_key, crypto::hash>, uint64_t> release_refs;
    void add_gateway_release_ref(const crypto::public_key& gw, const crypto::hash& ref, uint64_t h) override
    {
      release_refs.emplace(std::make_pair(gw, ref), h);
    }
    void remove_gateway_release_ref(const crypto::public_key& gw, const crypto::hash& ref) override
    {
      release_refs.erase({gw, ref});
    }
    bool has_gateway_release_ref(const crypto::public_key& gw, const crypto::hash& ref) const override
    {
      return release_refs.count({gw, ref}) > 0;
    }
    std::vector<crypto::public_key> get_all_gateway_ids() const override
    {
      std::vector<crypto::public_key> ids;
      for (auto& [k, v] : store) ids.push_back(k);
      return ids;
    }
  };

  crypto::public_key rand_pubkey()
  {
    crypto::public_key pk; crypto::secret_key sk;
    crypto::generate_keys(pk, sk);
    return pk;
  }

  // Register a gateway directly in the DB with a native-Schnorr owner key.
  // `bridge_reserve` sets the HF23 sticky flag that makes release refs mandatory.
  crypto::public_key seed_gateway(MemGatewayDB& db, uint64_t balance = 0, bool bridge_reserve = false)
  {
    const crypto::public_key id = rand_pubkey();
    gateway_account_data acct{};
    gateway_descriptor_base d{};
    d.owner_key = rand_pubkey(); // Schnorr owner (identity only for these tests)
    if (bridge_reserve)
    {
      d.version = 1;
      d.flags |= GATEWAY_FLAG_BRIDGE_RESERVE;
    }
    acct.descriptor_history.push_back(d);
    if (balance)
      acct.balances.push_back(gateway_balance_entry{crypto::null_aid, balance});
    store_gateway_account(db, id, acct);
    return id;
  }

  std::string blob_of(const crypto::public_key& id, MemGatewayDB& db)
  {
    std::string s; EXPECT_TRUE(db.get_gateway_account(id, s)); return s;
  }
}

// --------------------------------------------------------------------------
// Phase F — bridge accountability slash evidence verification (ed25519 quorum).

TEST(GatewayBridgeSlash, verify_evidence_threshold_and_binding)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4; // devnet-shape committee + threshold

  // Per-member bridge-signer ed25519 keypairs (the committee's signer_ed25519).
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  // An attributed FROST fault against committee index 2.
  tx_extra_bridge_slash slash{};
  slash.version = 1;
  slash.scheme = 1;         // Pgw
  slash.failing_check = 0;  // InvalidSignatureShare (attributed)
  slash.accused_index = 2;
  slash.epoch = 2;
  slash.height = 240;
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;

  const std::string msg = bridge_slash_message(NET, slash);
  auto accuse = [&](uint16_t idx) {
    bridge_slash_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    slash.accusers.push_back(s);
  };

  std::string reason;

  // Below threshold → rejected.
  accuse(0); accuse(1); accuse(3);
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason));

  // The 4th distinct ascending accuser → admissible.
  accuse(4);
  EXPECT_TRUE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason)) << reason;

  // Genesis binding: verifying the same signatures on a different net fails (the
  // message — hence the required signatures — differs).
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, network_type::TESTNET, reason));

  // A forged accuser (member 5's key presented as member 5's slot but signing the
  // wrong bytes) is caught: sign a different message, keep the same index.
  tx_extra_bridge_slash forged = slash;
  bridge_slash_signature bad{};
  bad.voter_index = 5;
  const std::string other = bridge_slash_message(NET, forged) + "x"; // wrong bytes
  crypto_sign_detached(bad.signature.data, nullptr,
                       reinterpret_cast<const unsigned char*>(other.data()), other.size(), secs[5].data);
  forged.accusers.push_back(bad);
  EXPECT_FALSE(verify_bridge_slash_evidence(forged, pubs, t_plus_1 + 1, NET, reason));
}

TEST(GatewayBridgeSlash, non_ascending_and_unattributed_rejected)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_slash slash{};
  slash.version = 1; slash.scheme = 1; slash.failing_check = 0;
  slash.accused_index = 1; slash.epoch = 2; slash.height = 240;
  const std::string msg = bridge_slash_message(NET, slash);
  auto sig_of = [&](uint16_t idx) {
    bridge_slash_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    return s;
  };
  std::string reason;

  // Duplicate / non-ascending indices are rejected even with enough signatures.
  slash.accusers = {sig_of(0), sig_of(2), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, 4, NET, reason));

  // The accused (member 1) cannot be one of its own accusers: with it, four signatures
  // would pass where only three honest members accuse.
  slash.accusers = {sig_of(0), sig_of(1), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, 4, NET, reason));
  EXPECT_NE(reason.find("its own accusers"), std::string::npos) << reason;
  slash.accusers = {sig_of(0), sig_of(2), sig_of(3), sig_of(4)};
  EXPECT_TRUE(verify_bridge_slash_evidence(slash, pubs, 4, NET, reason)) << reason;

  // A coarse/unattributed fault is never slashable, however many sign it.
  tx_extra_bridge_slash coarse{};
  coarse.version = 1; coarse.scheme = 0; coarse.failing_check = 3; // InvalidAggregateUnattributed
  coarse.accused_index = 0; coarse.epoch = 2; coarse.height = 240;
  const std::string cmsg = bridge_slash_message(NET, coarse);
  for (uint16_t i = 0; i < 5; ++i) {
    bridge_slash_signature s{}; s.voter_index = i;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(cmsg.data()), cmsg.size(), secs[i].data);
    coarse.accusers.push_back(s);
  }
  EXPECT_FALSE(verify_bridge_slash_evidence(coarse, pubs, 4, NET, reason));
}

// --------------------------------------------------------------------------
// H.6.3 — rotation-ack evidence (the mirror of the slash evidence gate; used to
// advance L1's per-chain observed key epoch, which releases an outgoing seat's bond).
// --------------------------------------------------------------------------
static std::vector<uint8_t> addr20(uint8_t fill) { return std::vector<uint8_t>(20, fill); }

TEST(GatewayBridgeRotation, verify_evidence_threshold_and_binding)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id  = 42;
  ack.contract  = addr20(0x22);
  ack.key_epoch = 8;
  ack.new_signer = addr20(0xCD);
  ack.epoch     = 7;

  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  auto observe = [&](uint16_t idx) {
    bridge_rotation_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    ack.observers.push_back(s);
  };
  std::string reason;

  // Below threshold → rejected.
  observe(0); observe(1); observe(3);
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason));

  // The 4th distinct ascending observer → admissible.
  observe(4);
  EXPECT_TRUE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason)) << reason;

  // Genesis binding: the same signatures verified on a different net fail (the message,
  // hence the required signatures, differs).
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, network_type::TESTNET, reason));

  // A forged observer (member 5's key signing the wrong bytes) is caught.
  tx_extra_bridge_rotation_ack forged = ack;
  bridge_rotation_signature bad{};
  bad.voter_index = 5;
  const std::string other = bridge_rotation_ack_message(NET_R, forged) + "x";
  crypto_sign_detached(bad.signature.data, nullptr,
                       reinterpret_cast<const unsigned char*>(other.data()), other.size(), secs[5].data);
  forged.observers.push_back(bad);
  EXPECT_FALSE(verify_bridge_rotation_evidence(forged, pubs, t_plus_1 + 1, NET_R, reason));
}

TEST(GatewayBridgeRotation, non_ascending_and_bad_length_rejected)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id = 1; ack.key_epoch = 2; ack.new_signer = addr20(0x11); ack.epoch = 3;
  ack.contract = addr20(0x22);
  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  auto sig_of = [&](uint16_t idx) {
    bridge_rotation_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    return s;
  };
  std::string reason;

  // Duplicate / non-ascending indices are rejected even with enough signatures.
  ack.observers = {sig_of(0), sig_of(2), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, 4, NET_R, reason));

  // A malformed new_signer (not 20 bytes) is rejected outright.
  tx_extra_bridge_rotation_ack bad_len = ack;
  bad_len.new_signer = std::vector<uint8_t>(19, 0x11);
  bad_len.observers  = {sig_of(0), sig_of(1), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_rotation_evidence(bad_len, pubs, 4, NET_R, reason));
}

// The ack must survive the tx_extra round trip byte-for-byte (the observer signatures
// cover the field values), and a rotation-ack tx must be recognised as such — not as a
// slash, unbond, or registration (all four ride txtype::bridge_registration).
TEST(GatewayBridgeRotation, tx_extra_round_trip_and_dispatch)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id = 42; ack.key_epoch = 8; ack.new_signer = addr20(0xCD); ack.epoch = 7;
  ack.contract = addr20(0x22); ack.log_index = 3; ack.evm_txid.data[0] = 0xEE;
  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  for (uint16_t idx : {0, 1, 3, 4})
  {
    bridge_rotation_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    ack.observers.push_back(s);
  }
  std::string reason;
  ASSERT_TRUE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason)) << reason;

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_rotation_ack_to_tx_extra(extra, ack));

  tx_extra_bridge_rotation_ack back{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, back));
  EXPECT_EQ(back.version, ack.version);
  EXPECT_EQ(back.chain_id, ack.chain_id);
  EXPECT_EQ(back.key_epoch, ack.key_epoch);
  EXPECT_EQ(back.epoch, ack.epoch);
  EXPECT_EQ(back.new_signer, ack.new_signer);
  EXPECT_EQ(back.contract, ack.contract);
  EXPECT_EQ(back.evm_txid, ack.evm_txid);
  EXPECT_EQ(back.log_index, ack.log_index);
  ASSERT_EQ(back.observers.size(), ack.observers.size());
  for (size_t i = 0; i < back.observers.size(); ++i)
  {
    EXPECT_EQ(back.observers[i].voter_index, ack.observers[i].voter_index);
    EXPECT_EQ(0, std::memcmp(back.observers[i].signature.data, ack.observers[i].signature.data,
                             sizeof(back.observers[i].signature.data)));
  }
  EXPECT_TRUE(verify_bridge_rotation_evidence(back, pubs, t_plus_1, NET_R, reason)) << reason;

  tx_extra_bridge_slash        as_slash{};
  tx_extra_bridge_unbond       as_unbond{};
  tx_extra_bridge_registration as_reg{};
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_slash));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_unbond));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_reg));
}

// The slash report has to survive the tx_extra round trip byte-for-byte, because
// the signatures cover the *field values* — any serialization drift would make an
// otherwise valid accusation unverifiable at block-processing time. This also
// pins the dispatch probe used by state_t::update_from_block and the tx pool:
// a slash-carrying tx must be recognised as a slash and not as an unbond or a
// registration (all three ride txtype::bridge_registration).
TEST(GatewayBridgeSlash, tx_extra_round_trip_and_dispatch)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;

  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_slash slash{};
  slash.version = 1;
  slash.scheme = 1;
  slash.failing_check = 0;
  slash.accused_index = 2;
  slash.epoch = 42;
  slash.height = 123456;
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;

  const std::string msg = bridge_slash_message(NET, slash);
  for (uint16_t idx : {0, 1, 3, 4})
  {
    bridge_slash_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    slash.accusers.push_back(s);
  }
  std::string reason;
  ASSERT_TRUE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason)) << reason;

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_slash_to_tx_extra(extra, slash));

  tx_extra_bridge_slash back{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, back));

  EXPECT_EQ(back.version, slash.version);
  EXPECT_EQ(back.scheme, slash.scheme);
  EXPECT_EQ(back.failing_check, slash.failing_check);
  EXPECT_EQ(back.accused_index, slash.accused_index);
  EXPECT_EQ(back.epoch, slash.epoch);
  EXPECT_EQ(back.height, slash.height);
  EXPECT_EQ(back.transcript_root, slash.transcript_root);
  ASSERT_EQ(back.accusers.size(), slash.accusers.size());
  for (size_t i = 0; i < back.accusers.size(); ++i)
  {
    EXPECT_EQ(back.accusers[i].voter_index, slash.accusers[i].voter_index);
    EXPECT_EQ(0, std::memcmp(back.accusers[i].signature.data, slash.accusers[i].signature.data,
                             sizeof(back.accusers[i].signature.data)));
  }

  // The signatures still verify against the *deserialized* report — the round trip
  // preserved every byte the message is built from.
  EXPECT_TRUE(verify_bridge_slash_evidence(back, pubs, t_plus_1, NET, reason)) << reason;

  // Dispatch: this extra is a slash, and neither of the operator-driven ops.
  tx_extra_bridge_unbond       as_unbond{};
  tx_extra_bridge_registration as_reg{};
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_unbond));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_reg));
}

// --------------------------------------------------------------------------
// Phase F — the slash as a *consensus action* on state_t. The evidence-verify
// tests above pin the cryptographic gate; these drive process_bridge_slash_tx
// end to end against constructed master-node state, exercising the bond-forfeit
// mechanics, the history-backed committee resolver (the piece update_from_block
// builds against state_history/state_archive), finalize-skip, idempotency, and
// the queue-head promotion into the freed seat. Uses FAKECHAIN, whose bridge
// committee is the devnet-shape 6-of-4.
// --------------------------------------------------------------------------
namespace
{
  using master_nodes::bridge_chain_epoch;
  using master_nodes::master_node_info;
  using master_nodes::master_node_list;
  using master_nodes::quorum;

  constexpr network_type NET_FC = network_type::FAKECHAIN; // 6-member committee, t+1 = 4

  struct committee_keys
  {
    std::vector<crypto::public_key>         mn;     // committee member masternode pubkeys, by index
    std::vector<crypto::ed25519_public_key> ed_pub; // parallel bridge-signer pubs
    std::vector<crypto::ed25519_secret_key> ed_sec; // parallel bridge-signer secrets
  };

  committee_keys make_committee(size_t n)
  {
    committee_keys c;
    for (size_t i = 0; i < n; ++i)
    {
      crypto::public_key pk; crypto::secret_key sk; crypto::generate_keys(pk, sk);
      c.mn.push_back(pk);
      crypto::ed25519_public_key ep; crypto::ed25519_secret_key es;
      crypto_sign_ed25519_keypair(ep.data, es.data);
      c.ed_pub.push_back(ep); c.ed_sec.push_back(es);
    }
    return c;
  }

  // Insert a registered (optionally seated) bridge seat into `st`.
  void seat_member(master_node_list::state_t& st, const crypto::public_key& pk,
                   const crypto::ed25519_public_key& signer, uint64_t reg_height, bool seated = true)
  {
    auto info = std::make_shared<master_node_info>();
    info->version = master_node_info::version_t::v8_bridge;
    auto& bs = info->bridge_seat;
    bs.registered              = true;
    bs.seated                  = seated;
    bs.bond_amount             = cryptonote::BRIDGE_BOND;
    bs.signer_ed25519          = signer;
    bs.registration_height     = reg_height;
    bs.requested_unbond_height = 0;
    bs.bond_unlock_height      = 0;
    st.master_nodes_infos[pk]  = info;
  }

  // Build + committee-sign an attributed FROST slash report.
  tx_extra_bridge_slash sign_slash(const committee_keys& c, uint16_t accused_index,
                                   const std::vector<uint16_t>& accusers, uint64_t epoch, uint64_t height)
  {
    tx_extra_bridge_slash slash{};
    slash.version = 1; slash.scheme = 1; slash.failing_check = 0; // Pgw / InvalidSignatureShare (attributed)
    slash.accused_index = accused_index; slash.epoch = epoch; slash.height = height;
    for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;
    const std::string msg = bridge_slash_message(NET_FC, slash);
    for (uint16_t idx : accusers)
    {
      bridge_slash_signature s{}; s.voter_index = idx;
      crypto_sign_detached(s.signature.data, nullptr,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), c.ed_sec[idx].data);
      slash.accusers.push_back(s);
    }
    return slash;
  }

  // Run process_bridge_slash_tx with a resolver that mirrors state_t::update_from_block
  // *exactly*: validators come from the historical bridge quorum for the report's
  // epoch, signer keys come from the current state's infos, and a member that can no
  // longer be keyed gets a zero (small-order) ed25519 key.
  bool run_slash(master_node_list::state_t& cur, const committee_keys& c,
                 const tx_extra_bridge_slash& slash, uint64_t block_height)
  {
    const uint64_t epoch_height = slash.epoch * cryptonote::bridge_epoch_blocks(NET_FC);

    master_node_list::state_t hist(nullptr);
    hist.height = epoch_height;
    auto q = std::make_shared<quorum>();
    q->validators = c.mn;
    hist.quorums.bridge = q;

    std::set<master_node_list::state_t, std::less<>> history;
    history.insert(std::move(hist));

    // The resolver is only invoked synchronously inside process_bridge_slash_tx
    // below, so `history`/`cur` outlive every call to it.
    master_nodes::bridge_committee_resolver resolver =
      [&](uint64_t eh, std::vector<crypto::public_key>& members,
          std::vector<crypto::ed25519_public_key>& signer_keys, size_t& threshold) -> bool {
        auto it = history.find(eh);
        if (it == history.end() || !it->quorums.bridge || it->quorums.bridge->validators.empty())
          return false;
        members = it->quorums.bridge->validators;
        signer_keys.clear();
        for (const auto& pk : members)
        {
          auto mit = cur.master_nodes_infos.find(pk);
          // Mirrors the daemon's resolver: a released or slashed seat counts for nothing.
          signer_keys.push_back(mit != cur.master_nodes_infos.end() && mit->second->bridge_seat.registered
                                        && !mit->second->bridge_seat.is_forfeited()
                                    ? mit->second->bridge_seat.signer_ed25519
                                    : crypto::ed25519_public_key::null());
        }
        threshold = cryptonote::bridge_committee_threshold(NET_FC);
        return true;
      };

    cryptonote::block blk{};
    blk.major_version = cryptonote::hf::hf23_bridge;
    blk.miner_tx.vin.push_back(cryptonote::txin_gen{block_height});

    cryptonote::transaction tx{};
    tx.type = cryptonote::txtype::bridge_registration;
    add_bridge_slash_to_tx_extra(tx.extra, slash);

    return cur.process_bridge_slash_tx(NET_FC, blk, tx, resolver);
  }

  size_t count_seated(const master_node_list::state_t& st)
  {
    size_t s = 0;
    for (const auto& [pk, info] : st.master_nodes_infos)
      if (info->bridge_seat.seated) ++s;
    return s;
  }

  // ---- H.6.3 rotation helpers -------------------------------------------------------
  bridge_chain_epoch chain_ep(uint64_t chain_id, uint64_t key_epoch)
  {
    bridge_chain_epoch e; e.chain_id = chain_id; e.key_epoch = key_epoch; return e;
  }

  uint64_t observed_epoch(const master_node_list::state_t& st, uint64_t chain_id)
  {
    for (const auto& e : st.observed_key_epoch)
      if (e.chain_id == chain_id) return e.key_epoch;
    return 0;
  }

  // Build + committee-sign a rotation ack for (chain_id, key_epoch), observed by `epoch`.
  tx_extra_bridge_rotation_ack sign_rotation_ack(const committee_keys& c, uint64_t chain_id,
                                                 uint64_t key_epoch, const std::vector<uint16_t>& observers,
                                                 uint64_t epoch)
  {
    tx_extra_bridge_rotation_ack ack{};
    ack.chain_id = chain_id; ack.key_epoch = key_epoch; ack.epoch = epoch;
    ack.new_signer = std::vector<uint8_t>(20, 0xCD);
    // Each chain's wBDX contract, and a distinct cited log per rotation.
    ack.contract = std::vector<uint8_t>(20, static_cast<uint8_t>(0x20 + chain_id));
    ack.evm_txid.data[0] = static_cast<char>(key_epoch);
    ack.log_index = static_cast<uint32_t>(key_epoch);
    const std::string msg = bridge_rotation_ack_message(NET_FC, ack);
    for (uint16_t idx : observers)
    {
      bridge_rotation_signature s{}; s.voter_index = idx;
      crypto_sign_detached(s.signature.data, nullptr,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), c.ed_sec[idx].data);
      ack.observers.push_back(s);
    }
    return ack;
  }

  // Run process_bridge_rotation_ack_tx with the same history-backed resolver as run_slash.
  bool run_rotation_ack(master_node_list::state_t& cur, const committee_keys& c,
                        const tx_extra_bridge_rotation_ack& ack, uint64_t block_height)
  {
    const uint64_t epoch_height = ack.epoch * cryptonote::bridge_epoch_blocks(NET_FC);
    master_node_list::state_t hist(nullptr);
    hist.height = epoch_height;
    auto q = std::make_shared<quorum>();
    q->validators = c.mn;
    hist.quorums.bridge = q;
    std::set<master_node_list::state_t, std::less<>> history;
    history.insert(std::move(hist));

    master_nodes::bridge_committee_resolver resolver =
      [&](uint64_t eh, std::vector<crypto::public_key>& members,
          std::vector<crypto::ed25519_public_key>& signer_keys, size_t& threshold) -> bool {
        auto it = history.find(eh);
        if (it == history.end() || !it->quorums.bridge || it->quorums.bridge->validators.empty())
          return false;
        members = it->quorums.bridge->validators;
        signer_keys.clear();
        for (const auto& pk : members)
        {
          auto mit = cur.master_nodes_infos.find(pk);
          // Mirrors the daemon's resolver: a released or slashed seat counts for nothing.
          signer_keys.push_back(mit != cur.master_nodes_infos.end() && mit->second->bridge_seat.registered
                                        && !mit->second->bridge_seat.is_forfeited()
                                    ? mit->second->bridge_seat.signer_ed25519
                                    : crypto::ed25519_public_key::null());
        }
        threshold = cryptonote::bridge_committee_threshold(NET_FC);
        return true;
      };

    cryptonote::block blk{};
    blk.major_version = cryptonote::hf::hf23_bridge;
    blk.miner_tx.vin.push_back(cryptonote::txin_gen{block_height});
    cryptonote::transaction tx{};
    tx.type = cryptonote::txtype::bridge_registration;
    add_bridge_rotation_ack_to_tx_extra(tx.extra, ack);
    return cur.process_bridge_rotation_ack_tx(NET_FC, blk, tx, resolver);
  }

  // Put a seat into the unbonding state with a given per-chain baseline (bypasses the
  // MN-signature path of process_bridge_unbond_tx; this exercises the gate, not the sig).
  void set_unbonding(master_node_list::state_t& cur, const crypto::public_key& pk,
                     uint64_t unbond_height, uint64_t unlock_height,
                     const std::vector<bridge_chain_epoch>& serving)
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(pk));
    info->bridge_seat.requested_unbond_height = unbond_height;
    info->bridge_seat.bond_unlock_height      = unlock_height;
    info->bridge_seat.seated                  = false;
    info->bridge_seat.version                 = 1;
    info->bridge_seat.serving_key_epoch       = serving;
    cur.master_nodes_infos[pk] = info;
  }

  // A seat asks to leave through the real, MN-signed unbond path.
  bool run_unbond(master_node_list::state_t& cur, const crypto::public_key& pk,
                  const crypto::secret_key& sk, uint64_t block_height)
  {
    tx_extra_bridge_unbond op{};
    op.master_node_pubkey = pk;
    crypto::generate_signature(master_nodes::bridge_unbond_message(op), pk, sk, op.signature);
    transaction tx{};
    tx.type = txtype::bridge_registration;
    add_bridge_unbond_to_tx_extra(tx.extra, op);
    block blk{};
    blk.major_version = hf::hf23_bridge;
    blk.miner_tx.vin.push_back(txin_gen{block_height});
    return cur.process_bridge_unbond_tx(NET_FC, blk, tx);
  }
} // namespace

TEST(GatewayBridgeSlash, consensus_action_forfeits_bond_and_survives_finalize)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);

  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  const uint16_t accused = 2;
  const uint64_t epoch = 3, block_height = 5000;

  // Below threshold (3 < 4) → rejected, no state change.
  {
    auto slash = sign_slash(c, accused, {0, 1, 3}, epoch, block_height);
    EXPECT_FALSE(run_slash(cur, c, slash, block_height));
    EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[accused])->bridge_seat.is_active_seat());
  }

  // t+1 distinct ascending accusers → accepted; the bond is forfeited.
  {
    auto slash = sign_slash(c, accused, {0, 1, 3, 4}, epoch, block_height);
    EXPECT_TRUE(run_slash(cur, c, slash, block_height));
    const auto& bs = cur.master_nodes_infos.at(c.mn[accused])->bridge_seat;
    EXPECT_TRUE(bs.is_forfeited());
    EXPECT_EQ(bs.bond_unlock_height, std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(bs.requested_unbond_height, block_height);
    EXPECT_FALSE(bs.seated);
    EXPECT_TRUE(bs.registered); // still registered → bond key images stay blacklisted = burned
  }

  // Idempotent: a second identical report is a no-op (already slashed).
  {
    auto slash = sign_slash(c, accused, {0, 1, 3, 4}, epoch, block_height);
    EXPECT_FALSE(run_slash(cur, c, slash, block_height + 1));
  }

  // The forfeited bond is NEVER released — not even eons past any real unbond window.
  cur.finalize_bridge_unbonds(block_height + cryptonote::bridge_bond_unlock_blocks(NET_FC) + 1000000);
  const auto& bs = cur.master_nodes_infos.at(c.mn[accused])->bridge_seat;
  EXPECT_TRUE(bs.is_forfeited());
  EXPECT_TRUE(bs.registered);
  EXPECT_EQ(bs.bond_amount, cryptonote::BRIDGE_BOND); // bond record intact, locked forever

  // An honest committee member is untouched.
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[0])->bridge_seat.is_active_seat());
}

TEST(GatewayBridgeSlash, deregistered_accuser_gets_zero_key_and_is_not_counted)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Member 4's seat has since been released: in the current state it is no longer a
  // registered bridge seat. The resolver keys it with a zero ed25519 key (a
  // small-order point libsodium rejects), so its otherwise-valid signature cannot
  // verify — with exactly t+1 accusers, the report is rejected.
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(c.mn[4]));
    info->bridge_seat = master_node_info::bridge_seat_info{}; // unregistered default
    cur.master_nodes_infos[c.mn[4]] = info;
  }

  auto slash = sign_slash(c, /*accused=*/2, {0, 1, 3, 4}, /*epoch=*/3, /*height=*/5000);
  EXPECT_FALSE(run_slash(cur, c, slash, 5000)) << "an accuser under a zero key must not count";
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.is_forfeited());

  // Re-key member 4 back: the same accuser set now clears threshold and slashes.
  seat_member(cur, c.mn[4], c.ed_pub[4], 104);
  auto slash2 = sign_slash(c, 2, {0, 1, 3, 4}, 3, 5000);
  EXPECT_TRUE(run_slash(cur, c, slash2, 5000));
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.is_forfeited());
}

TEST(GatewayBridgeSlash, forfeit_frees_seat_for_queue_head)
{
  const size_t N   = cryptonote::bridge_committee_size(NET_FC); // 6 committee members
  const size_t CAP = cryptonote::BRIDGE_SEAT_CAP;               // 100 seats
  auto c = make_committee(N);

  master_node_list::state_t cur(nullptr);
  cur.height = 6000;

  // Seat the 6 committee members (FIFO heights 100..105), then fill the remaining
  // seats up to exactly CAP, then one extra registered-but-queued node (FIFO tail).
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  for (size_t i = N; i < CAP; ++i)
  {
    crypto::public_key pk; crypto::secret_key sk; crypto::generate_keys(pk, sk);
    seat_member(cur, pk, crypto::ed25519_public_key::null(), 100 + i, /*seated=*/true);
  }
  crypto::public_key queued; { crypto::secret_key sk; crypto::generate_keys(queued, sk); }
  seat_member(cur, queued, crypto::ed25519_public_key::null(), 100 + CAP, /*seated=*/false);

  ASSERT_EQ(count_seated(cur), CAP);
  ASSERT_FALSE(cur.master_nodes_infos.at(queued)->bridge_seat.seated);

  // Forfeit a seated committee member.
  auto slash = sign_slash(c, /*accused=*/2, {0, 1, 3, 4}, /*epoch=*/3, /*height=*/6000);
  ASSERT_TRUE(run_slash(cur, c, slash, 6000));
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.seated);

  // Deterministic re-assignment promotes the queue head into the freed seat.
  cur.refresh_bridge_seats();
  EXPECT_TRUE(cur.master_nodes_infos.at(queued)->bridge_seat.seated)  << "queue head must fill the freed seat";
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.seated) << "an exiting (forfeited) seat is never re-seated";
  EXPECT_EQ(count_seated(cur), CAP); // still exactly CAP seats occupied
}

// A voluntary leaver gives its slot to the queue head at once, and is never a committee
// candidate again: the next committee generates the next key, and a member that asked to
// leave must hold no share of it. It keeps serving the key it already holds — from that
// key's saved committee, which needs no slot — until the key is retired.
TEST(GatewayBridgeSlash, exiting_seat_frees_its_slot_and_is_not_a_candidate)
{
  const size_t CAP = cryptonote::BRIDGE_SEAT_CAP;
  master_node_list::state_t cur(nullptr);
  cur.height = 6000;

  std::vector<crypto::public_key> seats;
  for (size_t i = 0; i < CAP; ++i)
  {
    crypto::public_key pk; crypto::secret_key sk; crypto::generate_keys(pk, sk);
    seat_member(cur, pk, crypto::ed25519_public_key::null(), 100 + i, /*seated=*/true);
    seats.push_back(pk);
  }
  crypto::public_key queued; { crypto::secret_key sk; crypto::generate_keys(queued, sk); }
  seat_member(cur, queued, crypto::ed25519_public_key::null(), 100 + CAP, /*seated=*/false);

  // seats[0] asks to leave: the state process_bridge_unbond_tx leaves it in — still
  // `seated` (serving its key), with an unbond requested.
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(seats[0]));
    info->bridge_seat.requested_unbond_height = 6000;
    info->bridge_seat.bond_unlock_height      = 6000 + cryptonote::bridge_bond_unlock_blocks(NET_FC);
    cur.master_nodes_infos[seats[0]] = info;
  }
  const auto& leaver = cur.master_nodes_infos.at(seats[0])->bridge_seat;
  EXPECT_TRUE(leaver.is_exiting_seat()) << "it still serves the key it holds";
  EXPECT_FALSE(leaver.is_active_seat()) << "but it is no longer a committee candidate";

  cur.refresh_bridge_seats();
  EXPECT_TRUE(cur.master_nodes_infos.at(queued)->bridge_seat.seated)
      << "the queue head takes the leaver's slot at once, not when its key retires";
  EXPECT_TRUE(cur.master_nodes_infos.at(seats[0])->bridge_seat.registered)
      << "the leaver's bond stays locked";
}

// --------------------------------------------------------------------------
// H.6.3 — the rotation gate as a consensus action on state_t: rotation-acks advance
// observed_key_epoch; finalize_bridge_unbonds withholds a bond until every chain in the
// seat's baseline has rotated past it; grandfathering exempts later-added chains.
// --------------------------------------------------------------------------
// The exact bytes a rotation ack signs, pinned. The Rust signer's
// `rotation_ack::tests::canonical_bytes_match_the_daemon` asserts the same hex, so the two
// cannot drift apart without one of them failing.
TEST(GatewayBridgeRotation, rotation_ack_message_is_pinned)
{
  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id = 56; ack.key_epoch = 7; ack.log_index = 0x01020304;
  ack.contract = addr20(0x22); ack.new_signer = addr20(0xCD);
  for (size_t i = 0; i < sizeof(ack.evm_txid.data); ++i) ack.evm_txid.data[i] = static_cast<char>(i);
  const std::string msg = bridge_rotation_ack_message(network_type::MAINNET, ack);
  EXPECT_EQ(oxenc::to_hex(msg.begin(), msg.end()),
            "6272696467655f726f746174696f6e5f61636b5f76326ea477622339f61c5fba036dc75c08b6efcf9ee09c108e5c5591fcc233d17b2001380000000000000022222222222222222222222222222222222222220700000000000000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04030201");
}

// H-06 / L-03: only the current ack layout is accepted, and it must name the contract.
TEST(GatewayBridgeRotation, only_the_current_ack_version_with_a_contract_verifies)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  auto signed_ack = [&](uint8_t version, std::vector<uint8_t> contract) {
    tx_extra_bridge_rotation_ack ack{};
    ack.version = version; ack.chain_id = 56; ack.key_epoch = 2; ack.epoch = 3;
    ack.new_signer = addr20(0x11); ack.contract = std::move(contract);
    const std::string msg = bridge_rotation_ack_message(NET_R, ack);
    for (uint16_t idx : {0, 1, 2, 3})
    {
      bridge_rotation_signature s{}; s.voter_index = idx;
      crypto_sign_detached(s.signature.data, nullptr,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
      ack.observers.push_back(s);
    }
    return ack;
  };
  std::string reason;
  EXPECT_TRUE(verify_bridge_rotation_evidence(signed_ack(1, addr20(0x22)), pubs, t_plus_1, NET_R, reason)) << reason;
  for (uint8_t v : {0, 2, 255})
  {
    EXPECT_FALSE(verify_bridge_rotation_evidence(signed_ack(v, addr20(0x22)), pubs, t_plus_1, NET_R, reason));
    EXPECT_NE(reason.find("unsupported version"), std::string::npos) << reason;
  }
  EXPECT_FALSE(verify_bridge_rotation_evidence(signed_ack(1, {}), pubs, t_plus_1, NET_R, reason));
  EXPECT_FALSE(verify_bridge_rotation_evidence(signed_ack(1, std::vector<uint8_t>(19, 0x22)), pubs, t_plus_1, NET_R, reason));

  // The contract and the cited log are signed: changing either breaks every signature.
  auto ack = signed_ack(1, addr20(0x22));
  auto moved = ack; moved.contract = addr20(0x33);
  EXPECT_FALSE(verify_bridge_rotation_evidence(moved, pubs, t_plus_1, NET_R, reason));
  auto relog = ack; relog.log_index = 9;
  EXPECT_FALSE(verify_bridge_rotation_evidence(relog, pubs, t_plus_1, NET_R, reason));
  auto retx = ack; retx.evm_txid.data[5] = 1;
  EXPECT_FALSE(verify_bridge_rotation_evidence(retx, pubs, t_plus_1, NET_R, reason));
}

// The first accepted ack binds the chain to its contract; acks about any other contract
// on that chain are refused and move nothing.
TEST(GatewayBridgeRotation, a_chain_is_bound_to_the_contract_of_its_first_ack)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  ASSERT_EQ(cur.bridge_chain_contracts.size(), 1u);
  EXPECT_EQ(cur.bridge_chain_contracts[0].contract, std::vector<uint8_t>(20, 0x21));

  // Re-sign the next rotation over a different contract on the same chain.
  auto other = sign_rotation_ack(c, 1, 2, {}, 3);
  other.contract = std::vector<uint8_t>(20, 0x99);
  const std::string msg = bridge_rotation_ack_message(NET_FC, other);
  for (uint16_t idx : {0, 1, 2, 3})
  {
    bridge_rotation_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), c.ed_sec[idx].data);
    other.observers.push_back(s);
  }
  std::string reason;
  EXPECT_FALSE(cur.check_bridge_rotation_ack(other, NET_FC, reason));
  EXPECT_NE(reason.find("bound to"), std::string::npos) << reason;
  EXPECT_FALSE(run_rotation_ack(cur, c, other, 5001));
  EXPECT_EQ(observed_epoch(cur, 1), 1u) << "an ack about another contract moves nothing";

  // The real contract's next rotation is accepted, and another chain gets its own binding.
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5002));
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 5002));
  EXPECT_EQ(cur.bridge_chain_contracts.size(), 2u);
}

// The contract moves its key epoch by exactly one, and the bond gate counts hand-overs by
// it, so an ack that skips an epoch would count one hand-over as several.
TEST(GatewayBridgeRotation, an_ack_must_name_exactly_the_next_key_epoch)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 4999));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5000));
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2, 3}, 3), 5001)) << "skips 3";
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001)) << "repeats 2";
  EXPECT_EQ(observed_epoch(cur, 1), 2u);
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2, 3}, 3), 5003)) << "now 4 is next";
  EXPECT_EQ(observed_epoch(cur, 1), 4u);
}

// A chain's first ack is its contract's initial key, epoch 1. Any other first epoch would
// set the count later hand-overs are measured from: a false high one leaves departing
// seats' baselines already passed, or never reachable.
TEST(GatewayBridgeRotation, a_chains_first_ack_must_be_epoch_1)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  std::string reason;
  for (uint64_t e : {0, 2, 9})
  {
    auto ack = sign_rotation_ack(c, 1, e, {0, 1, 2, 3}, 3);
    EXPECT_FALSE(cur.check_bridge_rotation_ack(ack, NET_FC, reason)) << e;
    EXPECT_NE(reason.find("first ack must be epoch 1"), std::string::npos) << reason;
    EXPECT_FALSE(run_rotation_ack(cur, c, ack, 5000)) << e;
  }
  EXPECT_EQ(observed_epoch(cur, 1), 0u);
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  EXPECT_EQ(observed_epoch(cur, 1), 1u);
  // Each chain starts on its own: chain 2 still needs its own epoch 1.
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 2, {0, 1, 2, 3}, 3), 5001));
}

// Only chains the bridge serves on this network, and never the gateway's reserved id
// (its epoch moves with its owner hand-over).
TEST(GatewayBridgeRotation, an_ack_must_be_for_a_bridge_chain_of_this_network)
{
  master_node_list::state_t st(nullptr);
  tx_extra_bridge_rotation_ack ack{};
  ack.key_epoch = 1; ack.contract = addr20(0x22); ack.new_signer = addr20(0x11);
  std::string reason;
  // A mainnet chain is on the list, but no contract is pinned for it yet: closed.
  ack.chain_id = 56;    EXPECT_FALSE(st.check_bridge_rotation_ack(ack, network_type::MAINNET, reason));
  EXPECT_NE(reason.find("no wBDX contract is pinned"), std::string::npos) << reason;
  ack.chain_id = 31337; EXPECT_FALSE(st.check_bridge_rotation_ack(ack, network_type::MAINNET, reason));
  EXPECT_NE(reason.find("not a bridge chain"), std::string::npos) << reason;
  ack.chain_id = 31337; EXPECT_TRUE(st.check_bridge_rotation_ack(ack, network_type::DEVNET, reason)) << reason;
  ack.chain_id = 56;    EXPECT_FALSE(st.check_bridge_rotation_ack(ack, network_type::TESTNET, reason));
  ack.chain_id = 999999; EXPECT_FALSE(st.check_bridge_rotation_ack(ack, network_type::MAINNET, reason));
  ack.chain_id = cryptonote::BRIDGE_GATEWAY_CHAIN_ID;
  EXPECT_FALSE(st.check_bridge_rotation_ack(ack, NET_FC, reason));
}

// A slashed seat has nothing left at stake, so its signature is no voucher: like a
// released one, it gets no key, cannot verify, and cannot make up the threshold.
TEST(GatewayBridgeRotation, a_slashed_member_cannot_vouch_for_an_ack)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(c.mn[3]));
    info->bridge_seat.requested_unbond_height = 5000;
    info->bridge_seat.bond_unlock_height = std::numeric_limits<uint64_t>::max(); // forfeited
    cur.master_nodes_infos[c.mn[3]] = info;
  }
  ASSERT_TRUE(cur.master_nodes_infos.at(c.mn[3])->bridge_seat.is_forfeited());

  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000))
      << "three bonded signers and a slashed one are not four";
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 4}, 3), 5000));
}

TEST(GatewayBridgeRotation, ack_advances_observed_key_epoch_monotonically)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // First ack for chain 1 (the contract's initial key, epoch 1), then epoch 2 advances.
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 4999));
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5000));
  EXPECT_EQ(observed_epoch(cur, 1), 2u);

  // A duplicate (same epoch) and a stale (lower epoch) both verify but are no-ops.
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001));
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5001));
  EXPECT_EQ(observed_epoch(cur, 1), 2u);

  // A newer epoch advances again.
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  EXPECT_EQ(observed_epoch(cur, 1), 3u);

  // Below-threshold evidence (3 < 4) is rejected outright.
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2}, 3), 5003));
  EXPECT_EQ(observed_epoch(cur, 1), 3u);
}

TEST(GatewayBridgeRotation, gate_withholds_bond_until_all_chains_rotate)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Two chains known, both at key epoch 1.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 5000));

  // Seat 5 unbonds with baseline {chain1: 1, chain2: 1}; timer unlock at height 5000.
  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(1, 1), chain_ep(2, 1)});
  auto seat_registered = [&]() { return cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered; };

  // Timer elapsed, but no chain rotated past baseline → withheld.
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(seat_registered()) << "bond must be withheld until both chains rotate";

  // Chain 1 rotates to 2 (chain 2 still 1) → still withheld (chain 2 not past baseline).
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(seat_registered()) << "one chain rotated is not enough";

  // Chain 2 rotates to 2 → every chain past its baseline → released.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered) << "bond released once all chains rotated";
}

TEST(GatewayBridgeRotation, gate_grandfathers_chain_added_after_unbond)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Only chain 1 known at unbond time; seat baseline = {chain1: 1}.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(1, 1)});

  // A brand-new chain 2 appears AFTER the seat unbonded (never in its snapshot).
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 6000));

  // Not gated on chain 2 (grandfathered). Still gated on chain 1 (not yet past 1).
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered);

  // Chain 1 rotates past baseline → released, even though chain 2 never rotated past 1.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered)
      << "a chain added after unbond must not gate the seat";
}

// A departing seat's bond waits for the GATEWAY to be handed over as well as the wBDX
// chains — a failed gateway hand-over leaves its Pgw share live — and for TWO hand-overs
// on each side: it may hold a share of the next key, if it asked to leave after its
// committee's DKG but before the hand-over to that key.
TEST(GatewayBridgeRotation, bond_waits_for_two_hand_overs_on_every_side_including_the_gateway)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  const crypto::public_key gw = rand_pubkey();
  auto gateway_tx = [&](gateway_descriptor_op_type type, const crypto::public_key& owner) {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type               = type;
    op.address_id            = gw;
    op.descriptor.version    = 1;
    op.descriptor.owner_key  = owner;
    op.descriptor.flags      = GATEWAY_FLAG_BRIDGE_RESERVE;
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    return tx;
  };
  const crypto::public_key key_a = rand_pubkey(), key_b = rand_pubkey(), key_c = rand_pubkey();

  // The bridge gateway registered under key A: tracked, nothing handed over yet.
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(gateway_descriptor_op_type::register_address, key_a)));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 0u);
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));

  // A seat asks to leave through the real unbond path.
  crypto::public_key leaver; crypto::secret_key leaver_sk;
  crypto::generate_keys(leaver, leaver_sk);
  seat_member(cur, leaver, crypto::ed25519_public_key::null(), 200);
  ASSERT_TRUE(run_unbond(cur, leaver, leaver_sk, 5000));
  const auto unlock = cur.master_nodes_infos.at(leaver)->bridge_seat.bond_unlock_height;
  auto released = [&] {
    cur.finalize_bridge_unbonds(unlock);
    return !cur.master_nodes_infos.at(leaver)->bridge_seat.registered;
  };

  // wBDX hands over twice, but the gateway hand-over failed: its Pgw share is still live.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  EXPECT_FALSE(released()) << "the gateway was never handed over — the bond must wait";

  // An update that keeps the owner is not a hand-over.
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(gateway_descriptor_op_type::update_address, key_a)));
  EXPECT_FALSE(released());

  // One gateway hand-over (A -> B): the seat may still hold a share of B.
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(gateway_descriptor_op_type::update_address, key_b)));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 1u);
  EXPECT_FALSE(released()) << "one hand-over can land on a key the seat still holds";

  // The second (B -> C) lands on a key generated without it.
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(gateway_descriptor_op_type::update_address, key_c)));
  EXPECT_TRUE(released()) << "two hand-overs on every side: the bond is released";
}

// With only ONE wBDX hand-over after the request the bond still waits — every side needs
// its second hand-over. (No bridge gateway is registered here, so only the wBDX side gates.)
TEST(GatewayBridgeRotation, one_wbdx_hand_over_is_not_enough)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));

  crypto::public_key leaver; crypto::secret_key leaver_sk;
  crypto::generate_keys(leaver, leaver_sk);
  seat_member(cur, leaver, crypto::ed25519_public_key::null(), 200);
  ASSERT_TRUE(run_unbond(cur, leaver, leaver_sk, 5000));
  const auto unlock = cur.master_nodes_infos.at(leaver)->bridge_seat.bond_unlock_height;

  // No bridge gateway registered: nothing on that side to wait for.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001));
  cur.finalize_bridge_unbonds(unlock);
  EXPECT_TRUE(cur.master_nodes_infos.at(leaver)->bridge_seat.registered) << "one hand-over is not enough";

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  cur.finalize_bridge_unbonds(unlock);
  EXPECT_FALSE(cur.master_nodes_infos.at(leaver)->bridge_seat.registered) << "the second releases it";
}

// Before any wBDX rotation is acknowledged, a seated member's bond would have no wBDX chain to
// wait on — so its leave request is refused until one has, rather than recorded unguarded.
TEST(GatewayBridgeRotation, seated_leave_waits_for_a_first_acknowledged_rotation)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  crypto::public_key leaver; crypto::secret_key leaver_sk;
  crypto::generate_keys(leaver, leaver_sk);
  seat_member(cur, leaver, crypto::ed25519_public_key::null(), 200);

  EXPECT_FALSE(run_unbond(cur, leaver, leaver_sk, 5000)) << "nothing acknowledged yet: refused";
  EXPECT_EQ(cur.master_nodes_infos.at(leaver)->bridge_seat.requested_unbond_height, 0u)
      << "and not recorded — the seat is untouched";

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  EXPECT_TRUE(run_unbond(cur, leaver, leaver_sk, 5001)) << "accepted once a rotation is acknowledged";
}

// A seat still in the QUEUE was never seated, so never selected and never given a share of
// any key. Its bond waits only for the unbonding window — no hand-over can concern it.
TEST(GatewayBridgeRotation, queued_seat_leaves_on_the_window_alone)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));

  crypto::public_key queued; crypto::secret_key queued_sk;
  crypto::generate_keys(queued, queued_sk);
  seat_member(cur, queued, crypto::ed25519_public_key::null(), 200, /*seated=*/false);
  ASSERT_TRUE(run_unbond(cur, queued, queued_sk, 5000));
  const auto& bs = cur.master_nodes_infos.at(queued)->bridge_seat;
  EXPECT_TRUE(bs.serving_key_epoch.empty()) << "no key to hand over, so no baseline";
  const auto unlock = bs.bond_unlock_height;

  cur.finalize_bridge_unbonds(unlock - 1);
  EXPECT_TRUE(cur.master_nodes_infos.at(queued)->bridge_seat.registered) << "still inside the window";
  cur.finalize_bridge_unbonds(unlock);
  EXPECT_FALSE(cur.master_nodes_infos.at(queued)->bridge_seat.registered)
      << "released when the window closes, with no rotation at all";
}

// Only THE bridge gateway counts. Anyone may register a bridge-reserve gateway of their own;
// handing THAT one over must not pass for the bridge's gateway hand-over, or a departing seat
// still holding the real gateway key could release its own bond.
TEST(GatewayBridgeRotation, only_the_bridge_gateway_counts_as_a_hand_over)
{
  master_node_list::state_t cur(nullptr);
  auto flagged = [](gateway_descriptor_op_type type, const crypto::public_key& id, const crypto::public_key& owner) {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type              = type;
    op.address_id           = id;
    op.descriptor.version   = 1;
    op.descriptor.owner_key = owner;
    op.descriptor.flags     = GATEWAY_FLAG_BRIDGE_RESERVE;
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    return tx;
  };
  const crypto::public_key bridge_gw = rand_pubkey(), other_gw = rand_pubkey();
  using op = gateway_descriptor_op_type;

  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, flagged(op::register_address, bridge_gw, rand_pubkey())));
  // Someone else registers a flagged gateway and hands it over twice.
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, flagged(op::register_address, other_gw, rand_pubkey())));
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, flagged(op::update_address, other_gw, rand_pubkey())));
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, flagged(op::update_address, other_gw, rand_pubkey())));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 0u) << "another gateway's owner changes do not count";
  EXPECT_EQ(cur.bridge_gateway_owners.size(), 1u) << "only the bridge gateway is tracked";

  // The bridge gateway's own hand-over still counts.
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, flagged(op::update_address, bridge_gw, rand_pubkey())));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 1u);
}

// No committee's word may move the gateway's count — consensus observes the gateway's owner
// changes itself. An ack naming the gateway's slot is refused however many members sign it.
TEST(GatewayBridgeRotation, an_ack_for_the_gateway_slot_is_refused)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  const auto ack = sign_rotation_ack(c, BRIDGE_GATEWAY_CHAIN_ID, 5, {0, 1, 2, 3, 4, 5}, 3);
  std::string reason;
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, c.ed_pub, 4, NET_FC, reason));
  EXPECT_NE(reason.find("gateway"), std::string::npos) << reason;
  EXPECT_FALSE(run_rotation_ack(cur, c, ack, 5000));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 0u);
}

// The tracked bridge gateway owner survives a daemon restart: the master node state is saved
// to and reloaded from the database as state_serialized. A state saved before the field
// existed still loads, with nothing tracked.
TEST(GatewayBridgeRotation, bridge_gateway_owner_survives_state_serialization)
{
  master_node_list::state_serialized s{};
  s.version = master_node_list::state_serialized::get_version(hf::hf23_bridge);
  s.height  = 7;
  master_nodes::bridge_gateway_owner g{};
  g.gateway_id = rand_pubkey();
  g.owner      = crypto::cn_fast_hash("owner", 5);
  s.bridge_gateway_owners.push_back(g);
  bridge_chain_epoch e{};
  e.chain_id  = BRIDGE_GATEWAY_CHAIN_ID;
  e.key_epoch = 2;
  s.observed_key_epoch.push_back(e);

  master_node_list::state_serialized got{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), got));
  ASSERT_EQ(got.bridge_gateway_owners.size(), 1u);
  EXPECT_EQ(got.bridge_gateway_owners[0].gateway_id, g.gateway_id);
  EXPECT_EQ(got.bridge_gateway_owners[0].owner, g.owner);
  ASSERT_EQ(got.observed_key_epoch.size(), 1u);
  EXPECT_EQ(got.observed_key_epoch[0].key_epoch, 2u);

  s.version = master_node_list::state_serialized::version_t::version_2_bridge_rotation;
  master_node_list::state_serialized older{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), older));
  EXPECT_TRUE(older.bridge_gateway_owners.empty());
  EXPECT_EQ(older.observed_key_epoch.size(), 1u);
}

TEST(GatewayBridgeRotation, gate_never_releases_a_seated_baseline_without_a_wbdx_chain)
{
  // A seat that unbonded while seated before any wBDX rotation was observed has nothing in
  // its baseline but (at most) the gateway entry. That records no hand-off of the wBDX key
  // its share still signs under, so the bond never comes back on it — unlike a queued
  // seat's empty baseline, which held no key.
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  set_unbonding(cur, c.mn[4], 4000, 5000, {});
  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(cryptonote::BRIDGE_GATEWAY_CHAIN_ID, 0)});
  // Still seated, as process_bridge_unbond_tx leaves a seat that asked to leave.
  for (const auto& pk : {c.mn[4], c.mn[5]})
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(pk));
    info->bridge_seat.seated = true;
    cur.master_nodes_infos[pk] = info;
  }

  // Chains rotate afterwards; neither seat recorded them, so neither may use them.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5999));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 6001));
  cur.finalize_bridge_unbonds(1000000);
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[4])->bridge_seat.registered) << "empty baseline";
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered) << "gateway-only baseline";
}

TEST(GatewayBridgeRotation, gate_treats_an_unobserved_chain_as_not_rotated)
{
  // Observations are only ever added, so a chain in the baseline that is missing from the
  // observed set has not been handed over; it is not a retired chain to skip.
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));

  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(1, 1), chain_ep(2, 0)});
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered)
      << "chain 2 was never observed, so it has not rotated";

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 6001));
  cur.finalize_bridge_unbonds(6001);
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered);
}

namespace
{
  // A seat's bond, locked by one contribution whose key image is returned.
  crypto::key_image give_bond(master_node_list::state_t& st, const crypto::public_key& pk)
  {
    auto info = std::make_shared<master_node_info>(*st.master_nodes_infos.at(pk));
    master_node_info::contribution_t contribution{};
    const crypto::public_key r = rand_pubkey();
    std::memcpy(contribution.key_image.data, r.data, sizeof(r.data));
    contribution.amount = cryptonote::BRIDGE_BOND;
    info->bridge_seat.bond_contributions = {contribution};
    st.master_nodes_infos[pk] = info;
    return contribution.key_image;
  }

  const master_nodes::key_image_blacklist_entry* blacklisted(const master_node_list::state_t& st, const crypto::key_image& ki)
  {
    for (const auto& e : st.key_image_blacklist)
      if (e.key_image == ki) return &e;
    return nullptr;
  }
}

// A seated member that is DEREGISTERED (say it went offline) still holds a share of the live
// keys. Its bond must wait for the same two hand-overs on every side as a leave request, not
// come back on the unbonding window alone.
TEST(GatewayBridgeRotation, deregistered_key_holder_bond_waits_for_two_hand_overs)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC);
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  const crypto::public_key gw = rand_pubkey();
  auto gateway_tx = [&](gateway_descriptor_op_type type, const crypto::public_key& owner) {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type              = type;
    op.address_id           = gw;
    op.descriptor.version   = 1;
    op.descriptor.owner_key = owner;
    op.descriptor.flags     = GATEWAY_FLAG_BRIDGE_RESERVE;
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    return tx;
  };
  using op = gateway_descriptor_op_type;
  cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(op::register_address, rand_pubkey()));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));

  const crypto::public_key gone = c.mn[2];
  const crypto::key_image ki = give_bond(cur, gone);
  const uint64_t dereg_height = 5000;
  cur.hold_bridge_bond_on_deregister(NET_FC, gone, *cur.master_nodes_infos.at(gone), dereg_height);
  cur.master_nodes_infos.erase(gone);
  const uint64_t unlock = dereg_height + cryptonote::bridge_bond_unlock_blocks(NET_FC);

  ASSERT_NE(blacklisted(cur, ki), nullptr);
  EXPECT_EQ(blacklisted(cur, ki)->unlock_height, std::numeric_limits<uint64_t>::max())
      << "a key holder's bond must not expire on a height alone";
  ASSERT_EQ(cur.bridge_departed_bonds.size(), 1u);
  EXPECT_EQ(cur.bridge_departed_bonds[0].unlock_height, unlock);

  // Long past the window, with no hand-over at all: still held.
  cur.finalize_bridge_unbonds(unlock + 100000);
  EXPECT_NE(blacklisted(cur, ki), nullptr) << "no hand-over yet: the share it holds is still live";

  // One hand-over on each side is not enough.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 3, 4}, 3), 5001));
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(op::update_address, rand_pubkey())));
  cur.finalize_bridge_unbonds(unlock);
  EXPECT_NE(blacklisted(cur, ki), nullptr);

  // The second on each side, but before the window ends: still held.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 3, 4}, 3), 5002));
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, gateway_tx(op::update_address, rand_pubkey())));
  cur.finalize_bridge_unbonds(unlock - 1);
  EXPECT_NE(blacklisted(cur, ki), nullptr) << "the window is the slashing horizon";

  // Both milestones: released.
  cur.finalize_bridge_unbonds(unlock);
  EXPECT_EQ(blacklisted(cur, ki), nullptr);
  EXPECT_TRUE(cur.bridge_departed_bonds.empty());
}

// A queued seat never held a key: deregistered, its bond keeps the plain unbonding window.
TEST(GatewayBridgeRotation, deregistered_queued_seat_keeps_the_window)
{
  master_node_list::state_t cur(nullptr);
  const crypto::public_key pk = rand_pubkey();
  seat_member(cur, pk, crypto::ed25519_public_key::null(), 100, /*seated=*/false);
  const crypto::key_image ki = give_bond(cur, pk);

  cur.hold_bridge_bond_on_deregister(NET_FC, pk, *cur.master_nodes_infos.at(pk), 5000);
  ASSERT_NE(blacklisted(cur, ki), nullptr);
  EXPECT_EQ(blacklisted(cur, ki)->unlock_height, 5000 + cryptonote::bridge_bond_unlock_blocks(NET_FC));
  EXPECT_TRUE(cur.bridge_departed_bonds.empty());
}

// A held bond survives a daemon restart, and a state saved before the field still loads.
TEST(GatewayBridgeRotation, departed_bond_survives_state_serialization)
{
  master_node_list::state_serialized s{};
  s.version = master_node_list::state_serialized::get_version(hf::hf23_bridge);
  s.height  = 7;
  master_nodes::bridge_departed_bond d{};
  d.master_node = rand_pubkey();
  const crypto::public_key r = rand_pubkey();
  crypto::key_image ki;
  std::memcpy(ki.data, r.data, sizeof(r.data));
  d.key_images.push_back(ki);
  d.serving_key_epoch.push_back(chain_ep(1, 4));
  d.unlock_height = 12345;
  s.bridge_departed_bonds.push_back(d);

  master_node_list::state_serialized got{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), got));
  ASSERT_EQ(got.bridge_departed_bonds.size(), 1u);
  EXPECT_EQ(got.bridge_departed_bonds[0].master_node, d.master_node);
  ASSERT_EQ(got.bridge_departed_bonds[0].key_images.size(), 1u);
  EXPECT_EQ(got.bridge_departed_bonds[0].key_images[0], ki);
  ASSERT_EQ(got.bridge_departed_bonds[0].serving_key_epoch.size(), 1u);
  EXPECT_EQ(got.bridge_departed_bonds[0].serving_key_epoch[0].key_epoch, 4u);
  EXPECT_EQ(got.bridge_departed_bonds[0].unlock_height, 12345u);

  s.version = master_node_list::state_serialized::version_t::version_4_bridge_chain_contract;
  master_node_list::state_serialized older{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), older));
  EXPECT_TRUE(older.bridge_departed_bonds.empty());
}

// --------------------------------------------------------------------------
// Governance message domain separation (S6/S14 on the native leg).
// --------------------------------------------------------------------------
TEST(GatewayBridgeMessages, domain_separation)
{
  const crypto::public_key gw = rand_pubkey();
  gateway_descriptor_base d{}; d.owner_key = rand_pubkey();

  const crypto::hash f0 = gateway_freeze_message(NET, gw, true,  /*seq=*/0, /*epoch=*/100);
  const crypto::hash f1 = gateway_freeze_message(NET, gw, false, 0, 100);          // freeze flag changes hash
  const crypto::hash f2 = gateway_freeze_message(NET, gw, true,  1, 100);          // nonce changes hash
  const crypto::hash f3 = gateway_freeze_message(NET, gw, true,  0, 101);          // epoch changes hash
  const crypto::hash r0 = gateway_repoint_message(NET, gw, d, 0, 100);

  EXPECT_NE(f0, f1);
  EXPECT_NE(f0, f2);
  EXPECT_NE(f0, f3);
  EXPECT_NE(f0, r0); // freeze vs repoint are never interchangeable (distinct domain tags)

  // Determinism: same inputs → same message.
  EXPECT_EQ(f0, gateway_freeze_message(NET, gw, true, 0, 100));
}

// --------------------------------------------------------------------------
// A.1/A.2 governance evidence: supermajority verification against a mock quorum.
// --------------------------------------------------------------------------
TEST(GatewayBridgeEvidence, supermajority_rules)
{
  // Synthetic checkpoint quorum of N members.
  constexpr size_t N = 10;
  std::vector<crypto::public_key> vpk(N);
  std::vector<crypto::secret_key> vsk(N);
  for (size_t i = 0; i < N; ++i) crypto::generate_keys(vpk[i], vsk[i]);

  const uint64_t epoch = 500;
  auto resolver = [&](uint64_t h, std::vector<crypto::public_key>& out) -> bool {
    if (h != epoch) return false;
    out = vpk;
    return true;
  };

  const crypto::public_key gw = rand_pubkey();
  const crypto::hash msg = gateway_freeze_message(NET, gw, true, /*seq=*/0, epoch);

  auto sign_by = [&](uint16_t idx) {
    gateway_governance_signature s{};
    s.voter_index = idx;
    crypto::generate_signature(msg, vpk[idx], vsk[idx], s.signature);
    return s;
  };

  // required = ceil(4/5 * 10) = 8.
  const size_t required = (N * GATEWAY_GOVERNANCE_SUPERMAJORITY_NUM
                           + GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN - 1) / GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN;
  EXPECT_EQ(required, 8u);

  std::string reason;

  // Exactly the required number, ascending indices → valid.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    EXPECT_TRUE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason)) << reason;
  }

  // One short → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required - 1; ++i) ev.push_back(sign_by(i));
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Non-ascending / duplicate voter index → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    ev[required - 1].voter_index = ev[required - 2].voter_index; // duplicate
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Voter index out of range → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    ev.back().voter_index = N; // out of range
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Tampered signature (right count, wrong signer for that index) → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    crypto::generate_signature(msg, vpk[0], vsk[1], ev[0].signature); // signs slot 0 with key 1
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Evidence for a message the signatures don't cover (wrong nonce) → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    const crypto::hash other = gateway_freeze_message(NET, gw, true, /*seq=*/1, epoch);
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, other, resolver, reason));
  }

  // Resolver has no quorum for the epoch → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch + 1, msg, resolver, reason));
  }
}

// --------------------------------------------------------------------------
// A.3 release cap: per-window accounting, fixed-window reset, and exact-inverse
// rewind (S9), driven directly through append/rewind on the in-memory DB.
// --------------------------------------------------------------------------
namespace
{
  // Build a minimal pure-gateway withdrawal tx spending `amount` from `src`.
  transaction make_withdrawal(const crypto::public_key& src, uint64_t amount)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    txin_gateway in{};
    in.gateway_addr = src;
    in.asset_id     = crypto::null_aid;
    in.amount       = amount;
    tx.vin.push_back(in);
    return tx;
  }
}

TEST(GatewayBridgeCap, window_accounting_and_rewind)
{
  MemGatewayDB db;
  const uint64_t big = GATEWAY_RELEASE_CAP_PER_WINDOW * 4;
  const crypto::public_key gw = seed_gateway(db, big);

  const uint64_t W = GATEWAY_RELEASE_WINDOW_BLOCKS;
  const uint64_t h0 = 10 * W + 5; // some height inside window 10
  std::string reason;

  // A within-cap withdrawal is accepted and accounted.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.version, 1);
  }

  // A second withdrawal in the same window that would exceed the cap is rejected,
  // and (because append failed) the DB is untouched for that block.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason));
  }

  // The SAME amount in the NEXT window is fine (fixed-window reset, β=1).
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    const uint64_t h1 = 11 * W + 1;
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h1, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.released_in_window(11), GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
  }

  // Rewind the window-11 block: exact inverse restores the window-10-only state.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    const uint64_t h1 = 11 * W + 1;
    ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h1, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(11), 0u);
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.balance_for(crypto::null_aid), big - GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
  }
}

// Two releases that each fit the window can still overflow it together, and a block holding
// both is invalid. The block template runs this same simulation on each candidate against
// the ones already taken, so the second one waits for a later block instead of getting every
// block built from the pool rejected.
TEST(GatewayBridgeCap, releases_valid_alone_can_overflow_the_window_together)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, GATEWAY_RELEASE_CAP_PER_WINDOW * 4);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  const auto first  = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
  const auto second = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
  std::string reason;

  EXPECT_TRUE(simulate_gateways_from_transactions(db, {first}, h, /*bridge_active=*/true, &reason)) << reason;
  EXPECT_TRUE(simulate_gateways_from_transactions(db, {second}, h, /*bridge_active=*/true, &reason)) << reason;
  EXPECT_FALSE(simulate_gateways_from_transactions(db, {first, second}, h, /*bridge_active=*/true, &reason));
  EXPECT_NE(reason.find("cap"), std::string::npos) << reason;
  // The next window has room again.
  EXPECT_TRUE(simulate_gateways_from_transactions(db, {second}, h + GATEWAY_RELEASE_WINDOW_BLOCKS, true, &reason));
}

TEST(GatewayBridgeCap, rewind_is_byte_exact)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, GATEWAY_RELEASE_CAP_PER_WINDOW * 2);
  const std::string before = blob_of(gw, db);

  auto tx = make_withdrawal(gw, 1000);
  const uint64_t h = 7 * GATEWAY_RELEASE_WINDOW_BLOCKS + 3;
  std::string reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_NE(blob_of(gw, db), before); // state changed (balance + release window + version bump)

  ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "rewind must restore a byte-identical blob (S9)";
}

// --------------------------------------------------------------------------
// Release replay guard (GATEWAY_RELEASE_REPLAY_GUARD.md): a withdrawal carrying
// a tx_extra_gateway_release_ref records the discharged burn; a second release
// for the same burn is block-invalid; rewind is an exact inverse; refs are
// window-bucketed and lazily pruned like the release-cap windows.
// --------------------------------------------------------------------------
namespace
{
  transaction make_withdrawal_with_ref(const crypto::public_key& src, uint64_t amount,
                                       uint64_t chain_id, const crypto::hash& evm_txid,
                                       uint32_t log_index = 0)
  {
    transaction tx = make_withdrawal(src, amount);
    tx_extra_gateway_release_ref rf{};
    rf.chain_id  = chain_id;
    rf.evm_txid  = evm_txid;
    rf.log_index = log_index;
    add_gateway_release_ref_to_tx_extra(tx.extra, rf);
    return tx;
  }

  crypto::hash burn_txid(uint8_t b)
  {
    crypto::hash h{};
    memset(h.data, b, sizeof(h.data));
    return h;
  }
}

TEST(GatewayBridgeReleaseRef, ref_hash_is_input_sensitive)
{
  const crypto::hash a = gateway_release_ref_hash(1, burn_txid(0x11), 0);
  EXPECT_EQ(a, gateway_release_ref_hash(1, burn_txid(0x11), 0));
  EXPECT_NE(a, gateway_release_ref_hash(2, burn_txid(0x11), 0)) << "chain-sensitive";
  EXPECT_NE(a, gateway_release_ref_hash(1, burn_txid(0x12), 0)) << "txid-sensitive";
  EXPECT_NE(a, gateway_release_ref_hash(1, burn_txid(0x11), 1)) << "log-index-sensitive";
}

TEST(GatewayBridgeReleaseRef, first_release_records_and_replay_is_rejected)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t h0 = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // First release for burn 0x11: accepted + recorded (version bumps to 2).
  {
    auto tx = make_withdrawal_with_ref(gw, 1000, /*chain*/1, burn_txid(0x11));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.version, 2);
    EXPECT_TRUE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x11), 0)));
  }

  // A DIFFERENT tx (different amount → different txid) replaying the same burn
  // in a later block is rejected — the double-pay this guard exists to stop.
  {
    auto tx = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x11));
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h0 + 1, true, &reason));
    EXPECT_NE(reason.find("replays"), std::string::npos) << reason;
  }

  // A release for a different burn is fine.
  {
    auto tx = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x22));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0 + 1, true, &reason)) << reason;
  }

  // Same txid on a different chain is a different burn — fine.
  {
    auto tx = make_withdrawal_with_ref(gw, 998, 2, burn_txid(0x11));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0 + 2, true, &reason)) << reason;
  }
}

TEST(GatewayBridgeReleaseRef, same_block_double_discharge_is_rejected_atomically)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const std::string before = blob_of(gw, db);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  auto tx1 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x33));
  auto tx2 = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x33)); // same burn!
  EXPECT_FALSE(append_gateways_from_transactions(db, {tx1, tx2}, h, true, &reason));
  EXPECT_EQ(blob_of(gw, db), before) << "failed append must write nothing (atomic)";
}

TEST(GatewayBridgeReleaseRef, rewind_is_byte_exact_and_reallows_the_burn)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const std::string before = blob_of(gw, db);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  auto tx = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x44));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_NE(blob_of(gw, db), before);

  // Reorg the block out: the blob is byte-identical (S9) — so the same burn is
  // releasable again (nothing was permanently consumed by an orphaned block).
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "rewind must restore a byte-identical blob";
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
}

TEST(GatewayBridgeReleaseRef, a_burn_stays_discharged_after_its_window_is_pruned)
{
  // The account keeps refs for the current and previous window only. Before the
  // permanent index, a burn released three windows ago could be released again.
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t W = GATEWAY_RELEASE_WINDOW_BLOCKS;
  const crypto::hash old_ref = gateway_release_ref_hash(1, burn_txid(0x55), 0);
  std::string reason;

  auto old_release = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x55));
  ASSERT_TRUE(append_gateways_from_transactions(db, {old_release}, 10 * W + 1, true, &reason)) << reason;
  for (uint64_t w = 11; w <= 13; ++w)
  {
    auto tx = make_withdrawal_with_ref(gw, 10, 1, burn_txid(static_cast<uint8_t>(0x60 + w)));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, w * W + 1, true, &reason)) << reason;
  }
  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
  ASSERT_FALSE(a.release_ref_recorded(old_ref)) << "the window record has pruned it";
  EXPECT_TRUE(db.has_gateway_release_ref(gw, old_ref)) << "the permanent index has not";

  auto replay = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x55));
  EXPECT_FALSE(append_gateways_from_transactions(db, {replay}, 13 * W + 2, true, &reason));
  EXPECT_NE(reason.find("already-discharged"), std::string::npos) << reason;
  EXPECT_FALSE(simulate_gateways_from_transactions(db, {replay}, 13 * W + 2, true, &reason));
}

TEST(GatewayBridgeReleaseRef, permanent_index_follows_append_and_rewind_exactly)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  const crypto::hash ref = gateway_release_ref_hash(1, burn_txid(0x66), 0);
  std::string reason;

  auto tx = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x66));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  ASSERT_EQ(db.release_refs.size(), 1u);
  EXPECT_EQ(db.release_refs.at({gw, ref}), h) << "recorded with its inclusion height";

  // A block whose gateway changes fail writes nothing to the index either.
  auto again = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x66));
  EXPECT_FALSE(append_gateways_from_transactions(db, {again}, h + 1, true, &reason));
  EXPECT_EQ(db.release_refs.size(), 1u);

  // Orphaned by a reorg, the burn is releasable again, exactly as before.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_TRUE(db.release_refs.empty());

  // Before the bridge hard fork nothing is recorded, matching the window guard.
  auto pre = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x67));
  ASSERT_TRUE(append_gateways_from_transactions(db, {pre}, h + 2, /*bridge_active=*/false, &reason)) << reason;
  EXPECT_TRUE(db.release_refs.empty());
}

TEST(GatewayBridgeReleaseRef, refless_withdrawal_still_valid_and_untouched_by_guard)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // The ref is optional (hardened mandatory-ref mode is a follow-up): a plain
  // withdrawal applies as before and never creates v2 state.
  auto tx = make_withdrawal(gw, 1000);
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_EQ(a.version, 1);
  EXPECT_TRUE(a.release_ref_windows.empty());
}

// §3.6 mandatory-ref rule: a gateway flagged BRIDGE_RESERVE may not be withdrawn
// from without a release ref — closing the "omit the ref to skip the dedup" bypass.
TEST(GatewayBridgeReleaseRef, bridge_reserve_gateway_requires_a_ref)
{
  MemGatewayDB db;
  const crypto::public_key flagged = seed_gateway(db, 1'000'000, /*bridge_reserve=*/true);
  const crypto::public_key plain   = seed_gateway(db, 1'000'000, /*bridge_reserve=*/false);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // Flagged + no ref → the block is invalid (authoritative apply-time check).
  {
    auto tx = make_withdrawal(flagged, 1000);
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h, /*bridge_active=*/true, &reason));
    EXPECT_NE(reason.find("no release ref"), std::string::npos) << reason;
  }
  // Flagged + ref → accepted.
  {
    auto tx = make_withdrawal_with_ref(flagged, 1000, 1, burn_txid(0x81));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  }
  // Unflagged + no ref → still fine (the rule is opt-in per gateway).
  {
    auto tx = make_withdrawal(plain, 1000);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  }
  // Pre-HF23 (bridge inactive) the rule does not apply at all.
  {
    auto tx = make_withdrawal(flagged, 1000);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, /*bridge_active=*/false, &reason))
        << reason;
  }
}

TEST(GatewayBridgeReleaseRef, bridge_reserve_flag_serializes_and_is_version_gated)
{
  // A v1 descriptor round-trips its flags; a v0 one has no flags field at all, so an
  // old blob stays byte-identical (backward compatibility).
  gateway_descriptor_base v1{};
  v1.version = 1;
  v1.owner_key = rand_pubkey();
  v1.flags = GATEWAY_FLAG_BRIDGE_RESERVE;
  EXPECT_TRUE(v1.is_bridge_reserve());
  auto blob = serialization::dump_binary(v1);
  gateway_descriptor_base back{};
  // `parse_binary` returns void and throws on malformed input (see binary_utils.h).
  ASSERT_NO_THROW(serialization::parse_binary(blob, back));
  EXPECT_EQ(back.version, 1);
  EXPECT_TRUE(back.is_bridge_reserve());

  gateway_descriptor_base v0{};
  v0.owner_key = v1.owner_key;
  EXPECT_FALSE(v0.is_bridge_reserve());
  auto blob0 = serialization::dump_binary(v0);
  EXPECT_LT(blob0.size(), blob.size()) << "v0 carries no flags byte";
}

TEST(GatewayBridgeReleaseRef, ref_windows_prune_like_cap_windows)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 10'000'000);
  const uint64_t W = GATEWAY_RELEASE_WINDOW_BLOCKS;
  std::string reason;

  // Record in window 10, then in window 12: the window-10 bucket (older than
  // the immediately-previous window) is pruned — the retention horizon.
  auto tx10 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x55));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx10}, 10 * W + 1, true, &reason)) << reason;
  auto tx12 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x66));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx12}, 12 * W + 1, true, &reason)) << reason;

  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_FALSE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x55), 0)))
      << "window-10 refs pruned once window 12 is recorded";
  EXPECT_TRUE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x66), 0)));
  ASSERT_EQ(a.release_ref_windows.size(), 1u);
  EXPECT_EQ(a.release_ref_windows[0].window_id, 12u);
}

// --------------------------------------------------------------------------
// A.1/A.2 apply/rewind: freeze toggles the flag + nonce; repoint appends the
// descriptor + nonce; both are exact-inverse on rewind.
// --------------------------------------------------------------------------
namespace
{
  transaction make_freeze_tx(const crypto::public_key& gw, bool freeze, uint64_t seq)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_freeze op{};
    op.gateway_id     = gw;
    op.freeze         = freeze ? 1 : 0;
    op.governance_seq = seq;
    op.epoch_height   = 42;
    add_gateway_freeze_to_tx_extra(tx.extra, op);
    return tx;
  }

  transaction make_repoint_tx(const crypto::public_key& gw, const crypto::public_key& new_owner, uint64_t seq)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_repoint op{};
    op.gateway_id                     = gw;
    op.new_owner_descriptor.owner_key = new_owner;
    op.governance_seq                 = seq;
    op.epoch_height                   = 42;
    add_gateway_repoint_to_tx_extra(tx.extra, op);
    return tx;
  }
}

TEST(GatewayBridgeGovernanceApply, freeze_repoint_apply_and_rewind)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db);
  const std::string before = blob_of(gw, db);
  std::string reason;

  // Freeze: flag set, nonce 0 -> 1, version bumped.
  auto fz = make_freeze_tx(gw, true, 0);
  const uint64_t h = 3 * GATEWAY_RELEASE_WINDOW_BLOCKS;
  ASSERT_TRUE(append_gateways_from_transactions(db, {fz}, h, true, &reason)) << reason;
  {
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.frozen, 1);
    EXPECT_EQ(a.governance_seq, 1u);
    EXPECT_EQ(a.version, 1);
  }

  // Repoint (nonce now 1): owner changes, history grows, nonce 1 -> 2.
  const crypto::public_key new_owner = rand_pubkey();
  auto rp = make_repoint_tx(gw, new_owner, 1);
  ASSERT_TRUE(append_gateways_from_transactions(db, {rp}, h + 1, true, &reason)) << reason;
  {
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.descriptor_history.size(), 2u);
    auto* pk = std::get_if<crypto::public_key>(&a.latest_descriptor().owner_key);
    ASSERT_NE(pk, nullptr);
    EXPECT_EQ(*pk, new_owner);
    EXPECT_EQ(a.governance_seq, 2u);
  }

  // Rewind both, newest first — exact inverse back to the original HF22 blob.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {rp}, h + 1, true, &reason)) << reason;
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {fz}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "governance rewind must restore the byte-identical pre-bridge blob";
}

// On a public network the bridge's identities come only from pins. An unpinned reserve
// gateway is never "the" gateway, however early it registers, so its owner changes count
// for nothing; and a departing seat's bond still waits for a gateway hand-over, so the
// bonds stay locked until the gateway is pinned rather than coming back early.
TEST(GatewayBridgeRotation, a_public_network_takes_the_gateway_only_from_its_pin)
{
  static_assert(cryptonote::bridge_requires_pins(network_type::MAINNET));
  static_assert(cryptonote::bridge_requires_pins(network_type::TESTNET));
  static_assert(!cryptonote::bridge_requires_pins(network_type::DEVNET));
  static_assert(!cryptonote::bridge_requires_pins(network_type::FAKECHAIN));

  master_node_list::state_t cur(nullptr);
  const crypto::public_key gw = rand_pubkey();
  auto gateway_tx = [&](gateway_descriptor_op_type type, const crypto::public_key& owner) {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type               = type;
    op.address_id            = gw;
    op.descriptor.version    = 1;
    op.descriptor.owner_key  = owner;
    op.descriptor.flags      = GATEWAY_FLAG_BRIDGE_RESERVE;
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    return tx;
  };

  // Registered first, then its owner changed twice: on mainnet none of it counts.
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(network_type::MAINNET,
                                                   gateway_tx(gateway_descriptor_op_type::register_address, rand_pubkey())));
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(network_type::MAINNET,
                                                   gateway_tx(gateway_descriptor_op_type::update_address, rand_pubkey())));
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(network_type::MAINNET,
                                                   gateway_tx(gateway_descriptor_op_type::update_address, rand_pubkey())));
  EXPECT_TRUE(cur.bridge_gateway_owners.empty()) << "an unpinned gateway is never tracked on mainnet";
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 0u);

  // And a seat leaving now must still wait for the gateway's hand-over.
  const auto baseline = cur.bridge_exit_baseline(network_type::MAINNET);
  EXPECT_TRUE(std::any_of(baseline.begin(), baseline.end(),
                          [](const bridge_chain_epoch& e) { return e.chain_id == BRIDGE_GATEWAY_CHAIN_ID; }))
      << "with no gateway tracked yet, the bond still waits on it";

  // On a local network the same registration is tracked, as before.
  master_node_list::state_t local(nullptr);
  EXPECT_FALSE(local.process_bridge_gateway_owner_tx(NET_FC,
                                                     gateway_tx(gateway_descriptor_op_type::register_address, rand_pubkey())));
  EXPECT_EQ(local.bridge_gateway_owners.size(), 1u);
  EXPECT_TRUE(local.process_bridge_gateway_owner_tx(NET_FC,
                                                    gateway_tx(gateway_descriptor_op_type::update_address, rand_pubkey())));
}

// Every pin that exists has the form it is compared in.
TEST(GatewayBridgeRotation, contract_pins_are_well_formed)
{
  static_assert(cryptonote::bridge_contract_pins_well_formed());
  for (const auto& c : cryptonote::SUPPORTED_BRIDGE_CHAINS)
    if (!c.wbdx_contract.empty())
      EXPECT_EQ(c.wbdx_contract.size(), 40u) << c.name;
}

// --------------------------------------------------------------------------
// Standby owner takeover: a standby committee takes the bridge gateway over when the
// owner key has gone silent, after a delay in which a live owner can cancel it.
// --------------------------------------------------------------------------
namespace
{
  struct OwnerKeys { crypto::public_key pub; crypto::secret_key sec; };
  OwnerKeys new_owner_keys() { OwnerKeys k; crypto::generate_keys(k.pub, k.sec); return k; }

  constexpr network_type NET_TO = network_type::FAKECHAIN;

  crypto::public_key seed_with_standby(MemGatewayDB& db, const OwnerKeys& owner, const OwnerKeys& standby)
  {
    const crypto::public_key id = rand_pubkey();
    gateway_account_data acct{};
    gateway_descriptor_base d{};
    d.version = 2;
    d.flags |= GATEWAY_FLAG_BRIDGE_RESERVE;
    d.owner_key = owner.pub;
    d.has_standby = 1;
    d.standby_owner = standby.pub;
    acct.descriptor_history.push_back(d);
    acct.balances.push_back(gateway_balance_entry{crypto::null_aid, 1000});
    store_gateway_account(db, id, acct);
    return id;
  }

  transaction takeover_update(const crypto::public_key& gw, const gateway_descriptor_base& d,
                              std::optional<gateway_takeover_action> action, const OwnerKeys& signer)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::update_gateway_address;
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_descriptor_operation op{};
    op.op_type    = gateway_descriptor_op_type::update_address;
    op.address_id = gw;
    op.descriptor = d;
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    if (action)
    {
      tx_extra_gateway_takeover t{};
      t.gateway_id = gw;
      t.action     = *action;
      add_gateway_takeover_to_tx_extra(tx.extra, t);
    }
    crypto::signature sig;
    crypto::generate_signature(gateway_ownership_message(NET_TO, tx), signer.pub, signer.sec, sig);
    EXPECT_TRUE(attach_gateway_ownership_proof(NET_TO, tx, sig));
    return tx;
  }

  bool valid(MemGatewayDB& db, const transaction& tx, std::string& reason)
  {
    tx_extra_gateway_descriptor_operation op{};
    EXPECT_TRUE(get_field_from_tx_extra(tx.extra, op));
    return validate_gateway_descriptor_operation(db, NET_TO, tx, op, hf::hf23_bridge, reason);
  }

  gateway_descriptor_base current(MemGatewayDB& db, const crypto::public_key& gw)
  {
    gateway_account_data a; EXPECT_TRUE(load_gateway_account(db, gw, a)); return a.latest_descriptor();
  }
  uint64_t started(MemGatewayDB& db, const crypto::public_key& gw)
  {
    gateway_account_data a; EXPECT_TRUE(load_gateway_account(db, gw, a)); return a.takeover_started_height();
  }
}

TEST(GatewayStandbyTakeover, the_standby_takes_over_a_silent_owner_after_the_delay)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys(), stranger = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const std::string before = blob_of(gw, db);
  const uint64_t wait = gateway_standby_takeover_blocks(NET_TO);
  std::string reason;

  // Begin: signed by the standby, descriptor unchanged. Not by the owner, not by anyone else.
  const auto d0 = current(db, gw);
  EXPECT_FALSE(valid(db, takeover_update(gw, d0, gateway_takeover_action::begin, owner), reason));
  EXPECT_NE(reason.find("standby"), std::string::npos) << reason;
  EXPECT_FALSE(valid(db, takeover_update(gw, d0, gateway_takeover_action::begin, stranger), reason));
  auto changed = d0; changed.meta_info = "x";
  EXPECT_FALSE(valid(db, takeover_update(gw, changed, gateway_takeover_action::begin, standby), reason));
  EXPECT_NE(reason.find("unchanged"), std::string::npos) << reason;

  db.chain_height = 100;
  const auto begin = takeover_update(gw, d0, gateway_takeover_action::begin, standby);
  ASSERT_TRUE(valid(db, begin, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 100, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 100u);
  EXPECT_FALSE(valid(db, takeover_update(gw, d0, gateway_takeover_action::begin, standby), reason))
      << "one takeover at a time";

  // Complete: only after the delay, only to exactly the standby as owner.
  gateway_descriptor_base taken = d0;
  taken.owner_key = standby.pub; taken.has_standby = 0; taken.standby_owner = gateway_owner_key_v{};
  db.chain_height = 100 + wait - 1;
  EXPECT_FALSE(valid(db, takeover_update(gw, taken, gateway_takeover_action::complete, standby), reason));
  EXPECT_NE(reason.find("not ready"), std::string::npos) << reason;
  db.chain_height = 100 + wait;
  auto wrong = taken; wrong.owner_key = stranger.pub;
  EXPECT_FALSE(valid(db, takeover_update(gw, wrong, gateway_takeover_action::complete, standby), reason));
  const auto complete = takeover_update(gw, taken, gateway_takeover_action::complete, standby);
  ASSERT_TRUE(valid(db, complete, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {complete}, 100 + wait, true, &reason)) << reason;
  const auto after = current(db, gw);
  EXPECT_TRUE(after.owner_key == gateway_owner_key_v{standby.pub});
  EXPECT_EQ(after.has_standby, 0);
  EXPECT_TRUE(after.is_bridge_reserve()) << "the sticky flag is carried over";
  EXPECT_EQ(started(db, gw), 0u);

  // The old owner's key no longer controls the gateway.
  EXPECT_FALSE(valid(db, takeover_update(gw, after, std::nullopt, owner), reason));

  // Rewinding both blocks restores the exact prior state.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {complete}, 100 + wait, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 100u);
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {begin}, 100, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "byte-exact rewind";
}

TEST(GatewayStandbyTakeover, a_live_owner_cancels_by_signing_any_update)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  std::string reason;
  const auto d0 = current(db, gw);

  db.chain_height = 200;
  const auto begin = takeover_update(gw, d0, gateway_takeover_action::begin, standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 200, true, &reason)) << reason;
  ASSERT_EQ(started(db, gw), 200u);

  // The owner is alive: a no-change update it signs cancels the takeover.
  db.chain_height = 201;
  const auto cancel = takeover_update(gw, d0, std::nullopt, owner);
  ASSERT_TRUE(valid(db, cancel, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {cancel}, 201, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 0u);

  // After the delay, completing is refused: nothing is running any more.
  db.chain_height = 200 + gateway_standby_takeover_blocks(NET_TO);
  gateway_descriptor_base taken = d0;
  taken.owner_key = standby.pub; taken.has_standby = 0; taken.standby_owner = gateway_owner_key_v{};
  EXPECT_FALSE(valid(db, takeover_update(gw, taken, gateway_takeover_action::complete, standby), reason));
  EXPECT_NE(reason.find("no takeover"), std::string::npos) << reason;

  // Rewinding the cancel brings the running takeover back.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {cancel}, 201, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 200u);
}

TEST(GatewayStandbyTakeover, standby_rules)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  std::string reason;

  // A gateway without a standby cannot be taken over.
  const crypto::public_key plain = seed_gateway(db, 10, true);
  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, plain, a));
  EXPECT_FALSE(valid(db, takeover_update(plain, a.latest_descriptor(), gateway_takeover_action::begin, standby), reason));
  EXPECT_NE(reason.find("no standby"), std::string::npos) << reason;

  // A standby must differ from the owner.
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  auto d = current(db, gw);
  d.standby_owner = owner.pub;
  EXPECT_FALSE(valid(db, takeover_update(gw, d, std::nullopt, owner), reason));
  EXPECT_NE(reason.find("must differ"), std::string::npos) << reason;

  // A marker must ride with a descriptor update of the same gateway.
  transaction lone{};
  lone.version = txversion::v4_tx_types;
  lone.type    = txtype::standard;
  lone.vin.push_back(txin_gen{0});
  tx_extra_gateway_takeover t{}; t.gateway_id = gw; t.action = gateway_takeover_action::begin;
  add_gateway_takeover_to_tx_extra(lone.extra, t);
  EXPECT_FALSE(validate_tx_gateway_operations_against_db(db, NET_TO, lone, hf::hf23_bridge, nullptr, reason));
  EXPECT_NE(reason.find("takeover marker"), std::string::npos) << reason;

  // Descriptor v2 is HF23-only.
  EXPECT_FALSE(validate_gateway_descriptor_operation(
      db, NET_TO, takeover_update(gw, current(db, gw), std::nullopt, owner),
      [&] { tx_extra_gateway_descriptor_operation op{}; op.op_type = gateway_descriptor_op_type::update_address;
            op.address_id = gw; op.descriptor = current(db, gw); return op; }(),
      hf::hf22_gateway_addresses, reason));
}

// A standby belongs to the owner that named it. A member's bond comes back two owner
// hand-overs after it asks to leave, so a standby carried past a hand-over, or named again
// later, could leave a live failover key with holders who no longer have a bond.
TEST(GatewayStandbyTakeover, a_standby_is_bound_to_the_owner_that_named_it)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const OwnerKeys next = new_owner_keys(), fresh = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  std::string reason;

  // The owner may restate its own standby (any no-change update, a cancel among them).
  EXPECT_TRUE(valid(db, takeover_update(gw, current(db, gw), std::nullopt, owner), reason)) << reason;

  // A hand-over cannot carry the standby to the next owner.
  auto handover = current(db, gw);
  handover.owner_key = next.pub;
  EXPECT_FALSE(valid(db, takeover_update(gw, handover, std::nullopt, owner), reason));
  EXPECT_NE(reason.find("never had"), std::string::npos) << reason;

  // With a fresh standby (or none) it can.
  handover.standby_owner = fresh.pub;
  const auto tx = takeover_update(gw, handover, std::nullopt, owner);
  ASSERT_TRUE(valid(db, tx, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, 300, true, &reason)) << reason;

  // The next owner can name neither the old standby nor the old owner.
  for (const OwnerKeys* old : {&standby, &owner})
  {
    auto d = current(db, gw);
    d.standby_owner = old->pub;
    EXPECT_FALSE(valid(db, takeover_update(gw, d, std::nullopt, next), reason));
    EXPECT_NE(reason.find("never had"), std::string::npos) << reason;
  }

  // Nor can governance, re-pointing the gateway.
  tx_extra_gateway_repoint rp{};
  rp.gateway_id                         = gw;
  rp.new_owner_descriptor               = current(db, gw);
  rp.new_owner_descriptor.owner_key     = new_owner_keys().pub;
  rp.new_owner_descriptor.standby_owner = standby.pub;
  EXPECT_FALSE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, rp, {}, reason));
  EXPECT_NE(reason.find("never had"), std::string::npos) << reason;
  rp.new_owner_descriptor.standby_owner = rp.new_owner_descriptor.owner_key;
  EXPECT_FALSE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, rp, {}, reason));
  EXPECT_NE(reason.find("invalid standby"), std::string::npos) << reason;
}

// Governance's veto: freezing the gateway, or re-pointing it, ends a running takeover. A
// frozen gateway refuses every update, but the takeover's clock used to keep running, so
// it completed the moment the gateway was unfrozen.
TEST(GatewayStandbyTakeover, a_freeze_or_repoint_cancels_a_running_takeover)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const uint64_t wait = gateway_standby_takeover_blocks(NET_TO);
  std::string reason;

  const auto begin = takeover_update(gw, current(db, gw), gateway_takeover_action::begin, standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 400, true, &reason)) << reason;
  ASSERT_EQ(started(db, gw), 400u);
  const std::string running = blob_of(gw, db);

  const auto freeze = make_freeze_tx(gw, true, 0);
  ASSERT_TRUE(append_gateways_from_transactions(db, {freeze}, 401, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 0u) << "the freeze ended it";
  const auto unfreeze = make_freeze_tx(gw, false, 1);
  ASSERT_TRUE(append_gateways_from_transactions(db, {unfreeze}, 402, true, &reason)) << reason;

  // Unfrozen after the delay: nothing to complete.
  db.chain_height = 400 + wait + 5;
  gateway_descriptor_base taken = current(db, gw);
  taken.owner_key = standby.pub; taken.has_standby = 0; taken.standby_owner = gateway_owner_key_v{};
  EXPECT_FALSE(valid(db, takeover_update(gw, taken, gateway_takeover_action::complete, standby), reason));
  EXPECT_NE(reason.find("no takeover"), std::string::npos) << reason;

  // Rewinding the unfreeze and the freeze brings the running takeover back, byte for byte.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {unfreeze}, 402, true, &reason)) << reason;
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {freeze}, 401, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), running);

  // A re-point ends it too, and rewinds the same way.
  const auto repoint = make_repoint_tx(gw, new_owner_keys().pub, 0);
  ASSERT_TRUE(append_gateways_from_transactions(db, {repoint}, 403, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 0u);
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {repoint}, 403, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), running);
}

// After a takeover ends without completing, the standby waits a full delay before it may
// begin again, so it cannot make the owner sign a cancel on every block.
TEST(GatewayStandbyTakeover, a_cancelled_takeover_cools_down_for_a_delay)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const uint64_t wait = gateway_standby_takeover_blocks(NET_TO);
  std::string reason;

  const auto begin = takeover_update(gw, current(db, gw), gateway_takeover_action::begin, standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 500, true, &reason)) << reason;
  const auto cancel = takeover_update(gw, current(db, gw), std::nullopt, owner);
  ASSERT_TRUE(append_gateways_from_transactions(db, {cancel}, 501, true, &reason)) << reason;

  const auto again = takeover_update(gw, current(db, gw), gateway_takeover_action::begin, standby);
  db.chain_height = 501 + wait - 1;
  EXPECT_FALSE(valid(db, again, reason));
  EXPECT_NE(reason.find("cooling down: 1 more"), std::string::npos) << reason;
  db.chain_height = 501 + wait;
  EXPECT_TRUE(valid(db, again, reason)) << reason;

  // Rewinding the cancel brings the takeover back as it was, cooldown and all.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {cancel}, 501, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 500u);
}

// A deposit's EVM address decides who gets the minted wBDX, for good. Beyond the shape, the
// wallet refuses the zero address and any mixed-case address whose EIP-55 checksum fails.
TEST(GatewayBridgeMemo, evm_addresses_are_checked_before_a_deposit)
{
  crypto::eth_address a{};
  std::string reason;
  // The EIP-55 specification's own examples.
  for (const char* ok : {"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                         "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
                         "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"})
    EXPECT_TRUE(parse_bridge_evm_address(ok, a, reason)) << ok << ": " << reason;
  EXPECT_EQ(a.data[0], 0x5a);

  // No checksum to check: taken as written.
  EXPECT_TRUE(parse_bridge_evm_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", a, reason)) << reason;
  EXPECT_TRUE(parse_bridge_evm_address("0X5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED", a, reason)) << reason;

  // One letter's case flipped: a likely typo, caught.
  EXPECT_FALSE(parse_bridge_evm_address("0x5aaEb6053F3E94C9b9A09f33669435E7Ef1BeAed", a, reason));
  EXPECT_NE(reason.find("EIP-55"), std::string::npos) << reason;
  EXPECT_FALSE(parse_bridge_evm_address("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d35A", a, reason));

  // The zero address, and anything not 20 bytes of hex.
  EXPECT_FALSE(parse_bridge_evm_address("0x0000000000000000000000000000000000000000", a, reason));
  EXPECT_NE(reason.find("zero address"), std::string::npos) << reason;
  for (const char* bad : {"", "0x", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedd",
                          "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg"})
    EXPECT_FALSE(parse_bridge_evm_address(bad, a, reason)) << bad;
}

// The owner's standalone cancel (a version-1 takeover step): signed over the gateway and the
// takeover's start height, not over the carrying tx, so the owner committee signs it from
// chain state alone and any wallet carries it in a bridge_registration tx.
namespace
{
  transaction standalone_cancel(const crypto::public_key& gw, uint64_t started, const OwnerKeys& signer,
                                txtype type = txtype::bridge_registration)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = type;
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_takeover t{};
    t.version = 1;
    t.gateway_id = gw;
    t.action = gateway_takeover_action::cancel;
    t.started_height = started;
    crypto::signature sig;
    crypto::generate_signature(gateway_takeover_cancel_message(NET_TO, gw, started), signer.pub, signer.sec, sig);
    t.sig = sig;
    EXPECT_TRUE(add_gateway_takeover_to_tx_extra(tx.extra, t));
    return tx;
  }
  bool tx_valid(MemGatewayDB& db, const transaction& tx, std::string& reason)
  {
    return validate_tx_gateway_operations_against_db(db, NET_TO, tx, hf::hf23_bridge, {}, reason);
  }
}

TEST(GatewayStandbyTakeover, the_owner_cancels_with_a_standalone_signed_step)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys(), stranger = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  std::string reason;

  // Nothing to cancel yet.
  EXPECT_FALSE(tx_valid(db, standalone_cancel(gw, 700, owner), reason));
  EXPECT_NE(reason.find("no running takeover"), std::string::npos) << reason;

  const auto begin = takeover_update(gw, current(db, gw), gateway_takeover_action::begin, standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 700, true, &reason)) << reason;
  const std::string running = blob_of(gw, db);
  db.chain_height = 701;

  // Only the owner, and only for the takeover that is running.
  for (const OwnerKeys* who : {&standby, &stranger})
  {
    EXPECT_FALSE(tx_valid(db, standalone_cancel(gw, 700, *who), reason));
    EXPECT_NE(reason.find("not signed by the gateway's owner"), std::string::npos) << reason;
  }
  EXPECT_FALSE(tx_valid(db, standalone_cancel(gw, 699, owner), reason));
  EXPECT_NE(reason.find("no running takeover"), std::string::npos) << reason;

  // It stands alone, in a bridge_registration tx.
  EXPECT_FALSE(tx_valid(db, standalone_cancel(gw, 700, owner, txtype::standard), reason));
  EXPECT_NE(reason.find("bridge_registration"), std::string::npos) << reason;

  const auto cancel = standalone_cancel(gw, 700, owner);
  ASSERT_TRUE(tx_valid(db, cancel, reason)) << reason;

  // Two members' wallets carry the same cancel into one block: the first ends the takeover,
  // the second changes nothing.
  auto again = standalone_cancel(gw, 700, owner);
  again.vin.front() = txin_gen{1}; // another carrier tx
  ASSERT_TRUE(append_gateways_from_transactions(db, {cancel, again}, 701, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 0u);
  gateway_account_data a;
  ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_EQ(a.takeover_ended_height(), 701u) << "the cooldown runs from the cancel";
  EXPECT_EQ(a.takeover_log.size(), 2u) << "one begin, one cancel";

  // A reorg puts the takeover back exactly.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {cancel, again}, 701, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), running);
}

// A version-0 marker cannot be a cancel: the standalone form is the only one.
TEST(GatewayStandbyTakeover, a_cancel_is_never_a_descriptor_update_marker)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  std::string reason;
  const auto begin = takeover_update(gw, current(db, gw), gateway_takeover_action::begin, standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 800, true, &reason)) << reason;
  db.chain_height = 801;
  const auto marker = takeover_update(gw, current(db, gw), gateway_takeover_action::cancel, owner);
  EXPECT_FALSE(tx_valid(db, marker, reason));
  EXPECT_NE(reason.find("standalone"), std::string::npos) << reason;
}

// The standby's standalone begin and complete: signed over messages fixed by the chain, so
// the standby committee signs them from chain state alone and any wallet carries them.
namespace
{
  transaction standalone_step(const crypto::public_key& gw, gateway_takeover_action action, uint64_t started,
                              const crypto::hash& msg, const OwnerKeys& signer,
                              std::optional<crypto::public_key> new_owner = std::nullopt)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::bridge_registration;
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_takeover t{};
    t.version = 1;
    t.gateway_id = gw;
    t.action = action;
    t.started_height = started;
    crypto::signature sig;
    crypto::generate_signature(msg, signer.pub, signer.sec, sig);
    t.sig = sig;
    if (new_owner)
      t.new_owner = *new_owner;
    EXPECT_TRUE(add_gateway_takeover_to_tx_extra(tx.extra, t));
    return tx;
  }
}

TEST(GatewayStandbyTakeover, the_standby_begins_and_completes_with_standalone_steps)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys(), stranger = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const std::string before = blob_of(gw, db);
  const uint64_t wait = gateway_standby_takeover_blocks(NET_TO);
  std::string reason;
  db.chain_height = 900;

  // Begin: the standby signs over the current descriptor and the gateway's step count.
  const auto begin_msg = gateway_takeover_begin_message(NET_TO, gw, current(db, gw), 0);
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::begin, 0, begin_msg, owner), reason));
  EXPECT_NE(reason.find("standby owner"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::begin, 1, begin_msg, standby), reason));
  EXPECT_NE(reason.find("step"), std::string::npos) << reason;
  const auto begin = standalone_step(gw, gateway_takeover_action::begin, 0, begin_msg, standby);
  ASSERT_TRUE(tx_valid(db, begin, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 900, true, &reason)) << reason;
  EXPECT_EQ(started(db, gw), 900u);
  db.chain_height = 901;
  EXPECT_FALSE(tx_valid(db, begin, reason));
  EXPECT_NE(reason.find("already running"), std::string::npos) << reason;

  // Complete: only after the delay, only naming the standby as the new owner.
  const auto done_msg = gateway_takeover_complete_message(NET_TO, gw, 900);
  db.chain_height = 900 + wait - 1;
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::complete, 900, done_msg, standby, standby.pub), reason));
  EXPECT_NE(reason.find("not ready"), std::string::npos) << reason;
  db.chain_height = 900 + wait;
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::complete, 900, done_msg, standby, stranger.pub), reason));
  EXPECT_NE(reason.find("standby owner as the new owner"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::complete, 900, done_msg, owner, standby.pub), reason));
  const auto complete = standalone_step(gw, gateway_takeover_action::complete, 900, done_msg, standby, standby.pub);
  ASSERT_TRUE(tx_valid(db, complete, reason)) << reason;
  const std::string running = blob_of(gw, db);
  ASSERT_TRUE(append_gateways_from_transactions(db, {complete}, 900 + wait, true, &reason)) << reason;

  const auto after = current(db, gw);
  EXPECT_TRUE(after.owner_key == gateway_owner_key_v{standby.pub});
  EXPECT_EQ(after.has_standby, 0);
  EXPECT_EQ(started(db, gw), 0u);

  // A reorg undoes the complete, then the begin, byte for byte.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {complete}, 900 + wait, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), running);
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {begin}, 900, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before);
}

// A begin the owner cancelled can never be replayed: it was signed for the step count at the
// time, and the cancel moved it on.
TEST(GatewayStandbyTakeover, a_cancelled_begin_cannot_be_replayed)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const uint64_t wait = gateway_standby_takeover_blocks(NET_TO);
  std::string reason;
  db.chain_height = 1000;
  const auto begin = standalone_step(gw, gateway_takeover_action::begin, 0,
                                     gateway_takeover_begin_message(NET_TO, gw, current(db, gw), 0), standby);
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 1000, true, &reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {standalone_cancel(gw, 1000, owner)}, 1001, true, &reason)) << reason;
  db.chain_height = 1001 + wait; // past the cooldown
  EXPECT_FALSE(tx_valid(db, begin, reason));
  EXPECT_NE(reason.find("gateway is at step 2"), std::string::npos) << reason;
}

// The bond gate counts a standalone complete as the gateway's hand-over, once.
TEST(GatewayBridgeRotation, a_standalone_takeover_complete_counts_as_a_hand_over)
{
  master_node_list::state_t cur(nullptr);
  const crypto::public_key gw = rand_pubkey();
  tx_extra_gateway_descriptor_operation op{};
  op.op_type = gateway_descriptor_op_type::register_address;
  op.address_id = gw;
  op.descriptor.version = 2;
  op.descriptor.owner_key = rand_pubkey();
  op.descriptor.flags = GATEWAY_FLAG_BRIDGE_RESERVE;
  transaction reg{};
  add_gateway_descriptor_operation_to_tx_extra(reg.extra, op);
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, reg));

  const OwnerKeys standby = new_owner_keys();
  const auto complete = standalone_step(gw, gateway_takeover_action::complete, 5, crypto::hash{}, standby, standby.pub);
  EXPECT_TRUE(cur.process_bridge_gateway_owner_tx(NET_FC, complete));
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 1u);
  EXPECT_FALSE(cur.process_bridge_gateway_owner_tx(NET_FC, complete)) << "a second copy counts nothing";
  EXPECT_EQ(observed_epoch(cur, BRIDGE_GATEWAY_CHAIN_ID), 1u);
}

// The owner names its next standby with a standalone step, signed over the gateway and its
// descriptor count, so the live committee signs it from chain state alone.
TEST(GatewayStandbyTakeover, the_owner_names_a_standby_with_a_standalone_step)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys(), fresh = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const std::string before = blob_of(gw, db);
  std::string reason;
  db.chain_height = 1100;
  auto name = [&](uint64_t count, const OwnerKeys& signer, const crypto::public_key& who) {
    return standalone_step(gw, gateway_takeover_action::name_standby, count,
                           gateway_standby_name_message(NET_TO, gw, count, who), signer, who);
  };

  // Only the owner, for the gateway's current descriptor count, and never the owner itself.
  EXPECT_FALSE(tx_valid(db, name(1, standby, fresh.pub), reason));
  EXPECT_NE(reason.find("not signed by the gateway's owner"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, name(0, owner, fresh.pub), reason));
  EXPECT_NE(reason.find("the gateway has 1"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, name(1, owner, owner.pub), reason));
  EXPECT_NE(reason.find("differs from its owner"), std::string::npos) << reason;

  // Two wallets carry the same naming into one block: the first applies, the second finds
  // the count moved on.
  const auto named = name(1, owner, fresh.pub);
  ASSERT_TRUE(tx_valid(db, named, reason)) << reason;
  auto copy = named;
  copy.vin.front() = txin_gen{1};
  ASSERT_TRUE(append_gateways_from_transactions(db, {named, copy}, 1100, true, &reason)) << reason;
  gateway_account_data a;
  ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_EQ(a.descriptor_history.size(), 2u);
  EXPECT_TRUE(a.latest_descriptor().standby_owner == gateway_owner_key_v{fresh.pub});
  EXPECT_TRUE(a.latest_descriptor().owner_key == gateway_owner_key_v{owner.pub});
  EXPECT_TRUE(a.latest_descriptor().is_bridge_reserve());
  db.chain_height = 1101;
  EXPECT_FALSE(tx_valid(db, named, reason)) << "spent: the count moved on";

  // The old standby can no longer begin; the new one can, and once it runs no standby is named.
  EXPECT_FALSE(tx_valid(db, standalone_step(gw, gateway_takeover_action::begin, 0,
      gateway_takeover_begin_message(NET_TO, gw, current(db, gw), 0), standby), reason));
  const auto begin = standalone_step(gw, gateway_takeover_action::begin, 0,
      gateway_takeover_begin_message(NET_TO, gw, current(db, gw), 0), fresh);
  ASSERT_TRUE(tx_valid(db, begin, reason)) << reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {begin}, 1101, true, &reason)) << reason;
  db.chain_height = 1102;
  EXPECT_FALSE(tx_valid(db, name(2, owner, new_owner_keys().pub), reason));
  EXPECT_NE(reason.find("takeover of this gateway is running"), std::string::npos) << reason;

  // A reorg undoes it all, byte for byte.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {begin}, 1101, true, &reason)) << reason;
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {named, copy}, 1100, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before);
}

// Key attestations: each committee member says, in its own tx, that its committee generated a
// key; the key is attested once the epoch's threshold have.
namespace
{
  using master_nodes::bridge_key_attestation_record;
  using master_nodes::check_bridge_standby_naming;
  using master_nodes::find_attested_bridge_key;
  using master_nodes::bridge_committee_operator_overlap;

  tx_extra_bridge_key_attestation sign_attestation(const committee_keys& c, uint16_t voter, uint64_t epoch,
                                                   const crypto::eddsa_public_key& vk, uint8_t pevm_fill = 0x77)
  {
    tx_extra_bridge_key_attestation att{};
    att.epoch = epoch;
    att.pgw_vk = vk;
    std::memset(att.pevm_address.data, pevm_fill, sizeof(att.pevm_address.data));
    att.voter_index = voter;
    const std::string msg = bridge_key_attestation_message(NET_FC, att);
    crypto_sign_detached(att.signature.data, nullptr, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                         c.ed_sec[voter].data);
    return att;
  }

  bool run_attestation(master_node_list::state_t& cur, const committee_keys& c,
                       const tx_extra_bridge_key_attestation& att, uint64_t block_height,
                       uint64_t committee_epoch = 3)
  {
    master_nodes::bridge_committee_resolver resolver =
      [&](uint64_t eh, std::vector<crypto::public_key>& members,
          std::vector<crypto::ed25519_public_key>& signer_keys, size_t& threshold) -> bool {
        if (eh != committee_epoch * cryptonote::bridge_epoch_blocks(NET_FC))
          return false;
        members = c.mn;
        signer_keys = c.ed_pub;
        threshold = cryptonote::bridge_committee_threshold(NET_FC);
        return true;
      };
    block blk{};
    blk.major_version = hf::hf23_bridge;
    blk.miner_tx.vin.push_back(txin_gen{block_height});
    transaction tx{};
    tx.type = txtype::bridge_registration;
    EXPECT_TRUE(add_bridge_key_attestation_to_tx_extra(tx.extra, att));
    return cur.process_bridge_key_attestation_tx(NET_FC, blk, tx, resolver);
  }

  crypto::eddsa_public_key new_vk()
  {
    crypto::eddsa_public_key pub; crypto::eddsa_secret_key sec;
    crypto::generate_eddsa_keypair(pub, sec);
    return pub;
  }
}

TEST(GatewayBridgeKeyAttestation, a_key_is_attested_once_the_threshold_of_its_committee_say_so)
{
  master_node_list::state_t cur(nullptr);
  const committee_keys c = make_committee(cryptonote::bridge_committee_size(NET_FC));
  const size_t threshold = cryptonote::bridge_committee_threshold(NET_FC);
  const crypto::eddsa_public_key vk = new_vk();

  for (uint16_t i = 0; i + 1 < threshold; ++i)
    ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, i, 3, vk), 50 + i));
  ASSERT_EQ(cur.bridge_key_attestations.size(), 1u);
  EXPECT_EQ(cur.bridge_key_attestations[0].attested_height, 0u) << "one short of the threshold";
  EXPECT_FALSE(find_attested_bridge_key(cur.bridge_key_attestations, vk));

  // A member counts once; a forged or foreign signature not at all.
  EXPECT_FALSE(run_attestation(cur, c, sign_attestation(c, 0, 3, vk), 60));
  auto forged = sign_attestation(c, 0, 3, vk);
  forged.voter_index = static_cast<uint16_t>(threshold - 1);
  EXPECT_FALSE(run_attestation(cur, c, forged, 60));
  auto outsider = sign_attestation(c, 0, 3, vk);
  outsider.voter_index = static_cast<uint16_t>(c.mn.size());
  EXPECT_FALSE(run_attestation(cur, c, outsider, 60));
  EXPECT_FALSE(run_attestation(cur, c, sign_attestation(c, 5, 99, vk), 60)) << "no committee for that epoch";
  // A different wBDX address is a different claim, collected apart.
  ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, 0, 3, vk, 0x55), 61));
  EXPECT_EQ(cur.bridge_key_attestations.size(), 2u);

  ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, static_cast<uint16_t>(threshold - 1), 3, vk), 70));
  const auto rec = find_attested_bridge_key(cur.bridge_key_attestations, vk);
  ASSERT_TRUE(rec);
  EXPECT_EQ(rec->epoch, 3u);
  EXPECT_EQ(rec->attested_height, 70u);
  EXPECT_EQ(rec->voters.size(), threshold);

  // Later members still count, but the attested height stays the first.
  ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, static_cast<uint16_t>(threshold), 3, vk), 80));
  EXPECT_EQ(find_attested_bridge_key(cur.bridge_key_attestations, vk)->attested_height, 70u);
}

TEST(GatewayBridgeKeyAttestation, attestations_survive_state_serialization)
{
  master_node_list::state_serialized s{};
  s.version = master_node_list::state_serialized::get_version(hf::hf23_bridge);
  bridge_key_attestation_record r{};
  r.pgw_vk = new_vk();
  r.epoch = 4;
  r.voters = {0, 2, 5};
  r.attested_height = 90;
  s.bridge_key_attestations.push_back(r);

  master_node_list::state_serialized got{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), got));
  ASSERT_EQ(got.bridge_key_attestations.size(), 1u);
  EXPECT_EQ(got.bridge_key_attestations[0].pgw_vk, r.pgw_vk);
  EXPECT_EQ(got.bridge_key_attestations[0].voters, r.voters);
  EXPECT_EQ(got.bridge_key_attestations[0].attested_height, 90u);

  // A state saved before the field loads with none.
  s.version = master_node_list::state_serialized::version_t::version_5_bridge_departed_bond;
  master_node_list::state_serialized older{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), older));
  EXPECT_TRUE(older.bridge_key_attestations.empty());
}

// A standby may be named only when both keys are attested and their committees share at most
// size - threshold members: losing enough holders to silence the live key then never also
// silences the standby.
TEST(GatewayBridgeKeyAttestation, a_standby_needs_attested_keys_from_committees_that_barely_overlap)
{
  const size_t limit = cryptonote::bridge_committee_size(NET_FC) - cryptonote::bridge_committee_threshold(NET_FC);
  const crypto::eddsa_public_key live = new_vk(), next = new_vk();
  auto rec = [](const crypto::eddsa_public_key& vk, uint64_t epoch, uint64_t height) {
    bridge_key_attestation_record r{};
    r.pgw_vk = vk; r.epoch = epoch; r.attested_height = height;
    return r;
  };
  std::map<std::pair<uint64_t, uint64_t>, size_t> shared{{{1, 2}, limit}, {{1, 3}, limit + 1}};
  auto overlap = [&](const bridge_key_attestation_record& a, const bridge_key_attestation_record& b) -> std::optional<size_t> {
    auto it = shared.find({a.epoch, b.epoch});
    return it == shared.end() ? std::nullopt : std::optional<size_t>{it->second};
  };
  std::string reason;

  std::vector<bridge_key_attestation_record> records{rec(live, 1, 10)};
  EXPECT_FALSE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason));
  EXPECT_NE(reason.find("standby key has no committee attestation"), std::string::npos) << reason;
  EXPECT_FALSE(check_bridge_standby_naming(records, next, live, NET_FC, overlap, {}, 0, reason));
  EXPECT_NE(reason.find("owner key has no committee attestation"), std::string::npos) << reason;

  // Collecting is not attested.
  records.push_back(rec(next, 2, 0));
  EXPECT_FALSE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason));

  records.back().attested_height = 20;
  EXPECT_TRUE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason)) << reason;

  // One member too many in common.
  records.back().epoch = 3;
  EXPECT_FALSE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason));
  EXPECT_NE(reason.find("at most " + std::to_string(limit)), std::string::npos) << reason;

  // Unknown committee; and a key that is not a committee key at all.
  records.back().epoch = 4;
  EXPECT_FALSE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason));
  EXPECT_NE(reason.find("unknown"), std::string::npos) << reason;
  EXPECT_FALSE(check_bridge_standby_naming(records, live, rand_pubkey(), NET_FC, overlap, {}, 0, reason));
  EXPECT_NE(reason.find("eddsa"), std::string::npos) << reason;

  // A key attested by two committees belongs to the first that reached its threshold.
  records.back().epoch = 2;
  records.push_back(rec(next, 3, 15));
  EXPECT_EQ(find_attested_bridge_key(records, next)->epoch, 3u);
  EXPECT_FALSE(check_bridge_standby_naming(records, live, next, NET_FC, overlap, {}, 0, reason));
}

// The signer builds this message itself (bridge/signer/src/key_attestation.rs): pin its layout.
TEST(GatewayBridgeKeyAttestation, the_message_layout_is_pinned)
{
  tx_extra_bridge_key_attestation att{};
  att.epoch = 0x0102;
  std::memset(att.pgw_vk.data, 2, sizeof(att.pgw_vk.data));
  std::memset(att.pevm_address.data, 3, sizeof(att.pevm_address.data));
  att.voter_index = 9; // not in the message: every member signs the same statement
  block genesis_block{};
  ASSERT_TRUE(generate_genesis_block(genesis_block, NET_FC));
  const crypto::hash genesis = get_block_hash(genesis_block);
  std::string want = "bridge_key_attestation_v1";
  want.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  want.append(std::string("\x00\x02\x01\x00\x00\x00\x00\x00\x00", 9));
  want.append(std::string(32, '\x02'));
  want.append(std::string(20, '\x03'));
  EXPECT_EQ(bridge_key_attestation_message(NET_FC, att), want);
}

// The standby proves it can still sign: over a recent slot-boundary block, whose hash the
// message binds, signed by the standby and naming it. It changes no gateway state.
TEST(GatewayStandbyTakeover, the_standby_proves_it_can_still_sign)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  const std::string before = blob_of(gw, db);
  const uint64_t slot = gateway_standby_alive_slot_blocks(NET_TO), window = gateway_standby_alive_window_blocks(NET_TO);
  std::string reason;
  db.chain_height = 100 * slot;
  const uint64_t h = gateway_standby_alive_height(NET_TO, db.chain_height);
  ASSERT_EQ(h % slot, 0u);
  ASSERT_LT(h, db.chain_height);
  auto proof = [&](uint64_t at, const OwnerKeys& signer, const crypto::public_key& named, const crypto::hash& block) {
    return standalone_step(gw, gateway_takeover_action::standby_alive, at,
                           gateway_standby_alive_message(NET_TO, gw, gateway_owner_key_v{named}, at, block), signer, named);
  };
  const auto hash_at = [&](uint64_t at) { return db.get_block_hash_from_height(at); };

  const auto ok = proof(h, standby, standby.pub, hash_at(h));
  ASSERT_TRUE(tx_valid(db, ok, reason)) << reason;

  // Only the standby, naming itself, over that very block.
  EXPECT_FALSE(tx_valid(db, proof(h, owner, standby.pub, hash_at(h)), reason));
  EXPECT_NE(reason.find("not signed by the gateway's standby"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, proof(h, owner, owner.pub, hash_at(h)), reason));
  EXPECT_NE(reason.find("current standby"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, proof(h, standby, standby.pub, hash_at(h + 1)), reason)) << "signed for another block";

  // A recent slot boundary only: not in between, not the future, not older than the window.
  EXPECT_FALSE(tx_valid(db, proof(h + 1, standby, standby.pub, hash_at(h + 1)), reason));
  EXPECT_NE(reason.find("recent slot boundary"), std::string::npos) << reason;
  EXPECT_FALSE(tx_valid(db, proof(db.chain_height, standby, standby.pub, hash_at(db.chain_height)), reason));
  const uint64_t old = (db.chain_height - window - 1) / slot * slot;
  EXPECT_FALSE(tx_valid(db, proof(old, standby, standby.pub, hash_at(old)), reason));

  // It records nothing in the gateway, and rewinds to nothing.
  ASSERT_TRUE(append_gateways_from_transactions(db, {ok}, db.chain_height, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before);
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {ok}, db.chain_height, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before);

  // No standby, no proof.
  const crypto::public_key plain = seed_gateway(db, 10, true);
  EXPECT_FALSE(tx_valid(db, standalone_step(plain, gateway_takeover_action::standby_alive, h,
      gateway_standby_alive_message(NET_TO, plain, gateway_owner_key_v{standby.pub}, h, hash_at(h)), standby, standby.pub), reason));
}

// Only a begin or a complete may ride a descriptor update as a marker.
TEST(GatewayStandbyTakeover, only_begin_and_complete_are_descriptor_update_markers)
{
  MemGatewayDB db;
  const OwnerKeys owner = new_owner_keys(), standby = new_owner_keys();
  const crypto::public_key gw = seed_with_standby(db, owner, standby);
  std::string reason;
  for (auto action : {gateway_takeover_action::name_standby, gateway_takeover_action::standby_alive})
  {
    EXPECT_FALSE(tx_valid(db, takeover_update(gw, current(db, gw), action, owner), reason));
    EXPECT_NE(reason.find("standalone"), std::string::npos) << reason;
  }
}

// The master-node state follows the bridge gateway's standby and when it last showed it could
// sign: named, restated, proved, renamed, taken over.
TEST(GatewayBridgeRotation, the_standbys_last_sign_of_life_is_tracked)
{
  master_node_list::state_t cur(nullptr);
  const crypto::public_key gw = rand_pubkey();
  crypto::eddsa_public_key a, b; crypto::eddsa_secret_key sk;
  crypto::generate_eddsa_keypair(a, sk);
  crypto::generate_eddsa_keypair(b, sk);
  auto descriptor_tx = [&](const crypto::public_key& id, gateway_descriptor_op_type type, std::optional<crypto::eddsa_public_key> sb) {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type = type;
    op.address_id = id;
    op.descriptor.version = 2;
    op.descriptor.owner_key = crypto::eddsa_public_key{};
    op.descriptor.flags = GATEWAY_FLAG_BRIDGE_RESERVE;
    if (sb) { op.descriptor.has_standby = 1; op.descriptor.standby_owner = *sb; }
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    return tx;
  };
  auto step_tx = [&](gateway_takeover_action action, uint64_t at, const crypto::eddsa_public_key& key) {
    tx_extra_gateway_takeover t{};
    t.version = 1; t.gateway_id = gw; t.action = action; t.started_height = at; t.new_owner = key;
    t.sig = crypto::signature{};
    transaction tx{};
    EXPECT_TRUE(add_gateway_takeover_to_tx_extra(tx.extra, t));
    return tx;
  };
  auto rec = [&]() { return cur.bridge_standby_liveness; };

  const auto reg = descriptor_tx(gw, gateway_descriptor_op_type::register_address, a);
  cur.process_bridge_gateway_owner_tx(NET_FC, reg);
  cur.process_bridge_standby_liveness_tx(reg, 100);
  ASSERT_EQ(rec().size(), 1u);
  EXPECT_EQ(rec()[0].standby, a);
  EXPECT_EQ(rec()[0].last_seen(), 100u);

  cur.process_bridge_standby_liveness_tx(step_tx(gateway_takeover_action::standby_alive, 190, a), 200);
  EXPECT_EQ(rec()[0].alive_height, 190u);
  cur.process_bridge_standby_liveness_tx(step_tx(gateway_takeover_action::standby_alive, 180, a), 201);
  EXPECT_EQ(rec()[0].alive_height, 190u) << "never moves back";

  // Restating the same standby keeps its clock; another gateway's changes are ignored.
  cur.process_bridge_standby_liveness_tx(descriptor_tx(gw, gateway_descriptor_op_type::update_address, a), 300);
  EXPECT_EQ(rec()[0].named_height, 100u);
  cur.process_bridge_standby_liveness_tx(descriptor_tx(rand_pubkey(), gateway_descriptor_op_type::update_address, b), 310);
  EXPECT_EQ(rec()[0].standby, a);

  // A new standby starts its own clock; a takeover leaves none.
  cur.process_bridge_standby_liveness_tx(step_tx(gateway_takeover_action::name_standby, 2, b), 400);
  EXPECT_EQ(rec()[0].standby, b);
  EXPECT_EQ(rec()[0].last_seen(), 400u);
  cur.process_bridge_standby_liveness_tx(step_tx(gateway_takeover_action::complete, 450, b), 500);
  EXPECT_TRUE(rec().empty());

  // A proof for a standby the state lost track of puts it right.
  cur.process_bridge_standby_liveness_tx(step_tx(gateway_takeover_action::standby_alive, 590, a), 600);
  ASSERT_EQ(rec().size(), 1u);
  EXPECT_EQ(rec()[0].standby, a);
  EXPECT_EQ(rec()[0].last_seen(), 600u);

  // It survives the state's serialization; older states load with none.
  master_node_list::state_serialized s{};
  s.version = master_node_list::state_serialized::get_version(hf::hf23_bridge);
  s.bridge_standby_liveness = rec();
  master_node_list::state_serialized got{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), got));
  ASSERT_EQ(got.bridge_standby_liveness.size(), 1u);
  EXPECT_EQ(got.bridge_standby_liveness[0].alive_height, 590u);
  s.version = master_node_list::state_serialized::version_t::version_6_bridge_key_attestation;
  master_node_list::state_serialized older{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), older));
  EXPECT_TRUE(older.bridge_standby_liveness.empty());
}

// Overlap counts operators, not nodes: one operator's trouble takes all its nodes at once, so a
// standby member whose operator also runs a live member is exposed even if the nodes differ.
TEST(GatewayBridgeKeyAttestation, overlap_counts_the_standbys_members_run_by_the_live_committees_operators)
{
  std::vector<crypto::public_key> a, b;
  std::map<crypto::public_key, std::string> op;
  auto node = [&](std::vector<crypto::public_key>& c, const std::string& who) {
    const crypto::public_key pk = rand_pubkey();
    c.push_back(pk);
    op[pk] = who;
    return pk;
  };
  const auto operator_of = [&](const crypto::public_key& pk) { return op.at(pk); };
  for (const char* who : {"alpha", "alpha", "beta", "gamma", "delta", "epsilon"})
    node(a, who);
  // No node in common, but alpha runs two of b's and beta one: three exposed.
  for (const char* who : {"alpha", "alpha", "beta", "zeta", "eta", "theta"})
    node(b, who);
  EXPECT_EQ(bridge_committee_operator_overlap(a, b, operator_of), 3u);
  // A node in both committees counts once, as before.
  b.push_back(a[3]);
  EXPECT_EQ(bridge_committee_operator_overlap(a, b, operator_of), 4u);
  // Operators only on one side expose nothing.
  EXPECT_EQ(bridge_committee_operator_overlap({a[4], a[5]}, {b[3], b[4]}, operator_of), 0u);
  // Counted from b's side: alpha's two nodes in a do not double what b exposes.
  EXPECT_EQ(bridge_committee_operator_overlap({a[0], a[1]}, {b[0]}, operator_of), 1u);
}

// A governance re-point keeps the bridge-reserve flag, and both governance ops must be signed
// by the checkpoint quorum of a recent block: an old quorum, whose operators may since have
// left, cannot be dug up to move a gateway.
TEST(GatewayBridgeGovernanceApply, governance_keeps_the_reserve_flag_and_needs_a_recent_quorum)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 10, /*bridge_reserve=*/true);
  db.chain_height = 1000;
  const uint64_t max_age = gateway_governance_max_age_blocks(NET_TO);

  std::vector<crypto::public_key> pubs;
  std::vector<crypto::secret_key> secs;
  for (int i = 0; i < 20; ++i)
  {
    crypto::public_key p; crypto::secret_key k; crypto::generate_keys(p, k);
    pubs.push_back(p); secs.push_back(k);
  }
  const checkpoint_quorum_resolver resolver = [&](uint64_t, std::vector<crypto::public_key>& v) { v = pubs; return true; };
  const size_t required = (20 * GATEWAY_GOVERNANCE_SUPERMAJORITY_NUM + GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN - 1)
                          / GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN;

  gateway_account_data acct;
  ASSERT_TRUE(load_gateway_account(db, gw, acct));
  auto repoint = [&](uint64_t epoch, bool keep_flag, size_t signers) {
    tx_extra_gateway_repoint op{};
    op.gateway_id = gw;
    op.new_owner_descriptor = acct.latest_descriptor();
    op.new_owner_descriptor.owner_key = rand_pubkey();
    if (!keep_flag)
      op.new_owner_descriptor.flags &= ~GATEWAY_FLAG_BRIDGE_RESERVE;
    op.governance_seq = acct.governance_seq;
    op.epoch_height = epoch;
    const crypto::hash msg = gateway_repoint_message(NET_TO, gw, op.new_owner_descriptor, op.governance_seq, epoch);
    for (size_t i = 0; i < signers; ++i)
    {
      gateway_governance_signature s{};
      s.voter_index = static_cast<uint16_t>(i);
      crypto::generate_signature(msg, pubs[i], secs[i], s.signature);
      op.evidence.push_back(s);
    }
    return op;
  };
  std::string reason;
  EXPECT_TRUE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, repoint(990, true, required), resolver, reason)) << reason;
  EXPECT_FALSE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, repoint(990, true, required - 1), resolver, reason));
  EXPECT_NE(reason.find("insufficient governance evidence"), std::string::npos) << reason;

  EXPECT_FALSE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, repoint(990, false, required), resolver, reason));
  EXPECT_NE(reason.find("bridge-reserve flag cannot be cleared"), std::string::npos) << reason;

  for (uint64_t epoch : {uint64_t{1000}, uint64_t{1005}, 1000 - max_age - 1})
  {
    EXPECT_FALSE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, repoint(epoch, true, required), resolver, reason)) << epoch;
    EXPECT_NE(reason.find("not a recent block"), std::string::npos) << reason;
  }
  EXPECT_TRUE(validate_gateway_repoint_operation(db, NET_TO, transaction{}, repoint(1000 - max_age, true, required), resolver, reason)) << reason;

  // A freeze too.
  tx_extra_gateway_freeze fz{};
  fz.gateway_id = gw; fz.freeze = 1; fz.governance_seq = acct.governance_seq; fz.epoch_height = 1000 - max_age - 1;
  EXPECT_FALSE(validate_gateway_freeze_operation(db, NET_TO, transaction{}, fz, resolver, reason));
  EXPECT_NE(reason.find("not a recent block"), std::string::npos) << reason;
}

// Standby rounds (HF23): while the gateway has no working standby, consensus draws a fresh
// standby committee at the start of every round, from operators that run none of the owner's
// committee, so a committee that cannot generate the key costs a round instead of an epoch.
namespace
{
  using master_nodes::bridge_standby_candidate;
  using master_nodes::bridge_standby_round_at;
  using master_nodes::bridge_standby_round_seed;
  using master_nodes::draw_bridge_standby_committee;

  // A seated bridge seat run by operator `who` (any nonzero byte); `leaving` asks to unbond.
  crypto::public_key seat_run_by(master_node_list::state_t& st, uint8_t who, bool leaving = false)
  {
    const crypto::public_key pk = rand_pubkey();
    seat_member(st, pk, crypto::ed25519_public_key{}, 1);
    auto info = std::make_shared<master_node_info>(*st.master_nodes_infos[pk]);
    info->operator_address.m_spend_public_key.data[0] = who;
    if (leaving)
      info->bridge_seat.requested_unbond_height = 5;
    st.master_nodes_infos[pk] = info;
    return pk;
  }

  // The bridge gateway, registered with `owner` as its owner key.
  void track_gateway(master_node_list::state_t& st, const crypto::eddsa_public_key& owner)
  {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type = gateway_descriptor_op_type::register_address;
    op.address_id = rand_pubkey();
    op.descriptor.version = 2;
    op.descriptor.owner_key = owner;
    op.descriptor.flags = GATEWAY_FLAG_BRIDGE_RESERVE;
    transaction tx{};
    add_gateway_descriptor_operation_to_tx_extra(tx.extra, op);
    st.process_bridge_gateway_owner_tx(NET_FC, tx);
  }

  bridge_key_attestation_record attested(const crypto::eddsa_public_key& vk, uint64_t round_height,
                                         const std::vector<crypto::public_key>& members, uint64_t at = 50)
  {
    bridge_key_attestation_record r{};
    r.pgw_vk = vk;
    r.epoch = 1;
    r.round_height = round_height;
    r.members = members;
    r.attested_height = at;
    return r;
  }

  const master_nodes::bridge_committee_resolver no_resolver{};
}

TEST(GatewayStandbyRounds, rounds_start_every_round_length_up_to_the_cap)
{
  // Local networks: 120-block epochs, 10-block rounds, so 12 rounds an epoch.
  ASSERT_EQ(bridge_standby_round_blocks(NET_FC), 10u);
  ASSERT_EQ(bridge_standby_max_rounds(NET_FC), 12u);
  EXPECT_EQ(bridge_standby_round_at(NET_FC, 0), std::optional<uint64_t>{0});
  EXPECT_EQ(bridge_standby_round_at(NET_FC, 10), std::optional<uint64_t>{1});
  EXPECT_EQ(bridge_standby_round_at(NET_FC, 110), std::optional<uint64_t>{11});
  EXPECT_EQ(bridge_standby_round_at(NET_FC, 120), std::optional<uint64_t>{0}) << "a new epoch starts again at 0";
  EXPECT_FALSE(bridge_standby_round_at(NET_FC, 125));

  // Mainnet: 60-block rounds, at most 24 an epoch (half of its 2,880 blocks).
  const auto MAIN = network_type::MAINNET;
  const uint64_t epoch = bridge_epoch_blocks(MAIN);
  EXPECT_EQ(bridge_standby_round_blocks(MAIN), 60u);
  EXPECT_EQ(bridge_standby_max_rounds(MAIN), 24u);
  EXPECT_EQ(bridge_standby_round_at(MAIN, 3 * epoch + 23 * 60), std::optional<uint64_t>{23});
  EXPECT_FALSE(bridge_standby_round_at(MAIN, 3 * epoch + 24 * 60)) << "past the cap: wait for the next epoch";
  EXPECT_FALSE(bridge_standby_round_at(MAIN, 3 * epoch + 30));
}

TEST(GatewayStandbyRounds, the_seed_is_apart_from_the_epoch_committees)
{
  const crypto::hash block = crypto::cn_fast_hash("block", 5);
  EXPECT_NE(bridge_standby_round_seed(block), block);
  EXPECT_EQ(bridge_standby_round_seed(block), bridge_standby_round_seed(block));
  EXPECT_NE(bridge_standby_round_seed(block), bridge_standby_round_seed(crypto::cn_fast_hash("other", 5)));
}

TEST(GatewayStandbyRounds, the_draw_leaves_out_the_owners_operators)
{
  const size_t size = bridge_committee_size(NET_FC);
  std::vector<bridge_standby_candidate> candidates;
  std::map<crypto::public_key, std::string> op_of;
  auto add = [&](const std::string& op) {
    candidates.push_back({rand_pubkey(), op});
    op_of[candidates.back().mn] = op;
  };
  const std::unordered_set<std::string> owners{"o1", "o2", "o3", "o4", "o5", "o6"};
  for (const auto& o : owners)
    add(o);
  for (int i = 0; i < 10; ++i)
    add("n" + std::to_string(i));
  add("n0"); add("n0"); // an operator with three seats still gets one slot

  const crypto::hash seed = crypto::cn_fast_hash("seed", 4);
  const auto members = draw_bridge_standby_committee(candidates, owners, seed, hf::hf23_bridge, NET_FC);
  ASSERT_EQ(members.size(), size);
  EXPECT_TRUE(std::is_sorted(members.begin(), members.end()));
  std::set<std::string> ops;
  for (const auto& m : members)
  {
    EXPECT_EQ(owners.count(op_of.at(m)), 0u) << "an owner operator was drawn though enough others were seated";
    ops.insert(op_of.at(m));
  }
  EXPECT_EQ(ops.size(), size) << "one seat per operator";

  // Every node draws the same committee, whatever order it lists the seats in.
  auto reversed = candidates;
  std::reverse(reversed.begin(), reversed.end());
  EXPECT_EQ(draw_bridge_standby_committee(reversed, owners, seed, hf::hf23_bridge, NET_FC), members);

  // Another round's seed draws another committee.
  bool differs = false;
  for (int i = 0; i < 8 && !differs; ++i)
    differs = draw_bridge_standby_committee(candidates, owners, crypto::cn_fast_hash(&i, sizeof(i)), hf::hf23_bridge,
                                            NET_FC) != members;
  EXPECT_TRUE(differs);
}

TEST(GatewayStandbyRounds, the_draw_tops_up_from_the_owners_operators_only_within_the_overlap_limit)
{
  const size_t size = bridge_committee_size(NET_FC);
  const size_t limit = size - bridge_committee_threshold(NET_FC);
  const std::unordered_set<std::string> owners{"o1", "o2", "o3", "o4", "o5", "o6"};
  const crypto::hash seed = crypto::cn_fast_hash("seed", 4);
  auto draw = [&](size_t others) {
    std::vector<bridge_standby_candidate> candidates;
    for (const auto& o : owners)
      candidates.push_back({rand_pubkey(), o});
    for (size_t i = 0; i < others; ++i)
      candidates.push_back({rand_pubkey(), "n" + std::to_string(i)});
    std::set<std::string> from_owners;
    const auto members = draw_bridge_standby_committee(candidates, owners, seed, hf::hf23_bridge, NET_FC);
    for (const auto& m : members)
      for (const auto& c : candidates)
        if (c.mn == m && owners.count(c.op))
          from_owners.insert(c.op);
    return std::make_pair(members.size(), from_owners.size());
  };
  // Exactly enough room in the overlap limit: topped up to a full committee.
  EXPECT_EQ(draw(size - limit), std::make_pair(size, limit));
  // One short: a committee with more of the owner's operators could not be named, so none.
  EXPECT_EQ(draw(size - limit - 1), std::make_pair(size_t{0}, size_t{0}));
}

TEST(GatewayStandbyRounds, a_round_draws_a_committee_only_while_a_standby_is_due)
{
  master_node_list::state_t cur(nullptr);
  cur.block_hash = crypto::cn_fast_hash("tip", 3);
  std::vector<crypto::public_key> owner_committee, others;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  for (uint8_t who = 11; who <= 18; ++who)
    others.push_back(seat_run_by(cur, who));
  const crypto::public_key leaving = seat_run_by(cur, 30, /*leaving=*/true);

  const crypto::eddsa_public_key owner = new_vk();
  track_gateway(cur, owner);
  std::vector<crypto::public_key> owner_members;
  std::string reason;
  EXPECT_FALSE(cur.bridge_standby_due(NET_FC, 130, no_resolver, owner_members, reason));
  EXPECT_NE(reason.find("owner's key has no committee attestation"), std::string::npos) << reason;

  cur.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));
  ASSERT_TRUE(cur.bridge_standby_due(NET_FC, 130, no_resolver, owner_members, reason)) << reason;
  EXPECT_EQ(owner_members, owner_committee);

  // Not a round's start: nothing. A round's start: a committee with none of the owner's operators
  // and never a seat that asked to leave.
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 125, no_resolver);
  EXPECT_TRUE(cur.bridge_standby_rounds.empty());
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 130, no_resolver);
  ASSERT_EQ(cur.bridge_standby_rounds.size(), 1u);
  const auto& round = cur.bridge_standby_rounds[0];
  EXPECT_EQ(round.round_height, 130u);
  ASSERT_EQ(round.members.size(), bridge_committee_size(NET_FC));
  for (const auto& m : round.members)
  {
    EXPECT_EQ(std::count(owner_committee.begin(), owner_committee.end(), m), 0);
    EXPECT_NE(m, leaving);
  }

  // A round stays for its attestation window, then goes; the next round draws its own.
  cur.block_hash = crypto::cn_fast_hash("next", 4);
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 140, no_resolver);
  ASSERT_EQ(cur.bridge_standby_rounds.size(), 2u);
  EXPECT_NE(cur.bridge_standby_rounds[1].members, cur.bridge_standby_rounds[0].members)
      << "a different block seeds a different draw";
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 141, no_resolver);
  ASSERT_EQ(cur.bridge_standby_rounds.size(), 1u);
  EXPECT_EQ(cur.bridge_standby_rounds[0].round_height, 140u);
}

TEST(GatewayStandbyRounds, what_makes_a_standby_due)
{
  master_node_list::state_t cur(nullptr);
  std::vector<crypto::public_key> owner_committee, others, mixed;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  for (uint8_t who = 11; who <= 16; ++who)
    others.push_back(seat_run_by(cur, who));
  // Three of the owner's operators: one past the overlap limit of 2.
  for (uint8_t who : {1, 2, 3, 21, 22, 23})
    mixed.push_back(seat_run_by(cur, who));
  const crypto::eddsa_public_key owner = new_vk(), named = new_vk(), waiting = new_vk(), older = new_vk();
  track_gateway(cur, owner);
  cur.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));
  std::vector<crypto::public_key> owner_members;
  std::string reason;
  const uint64_t stale = gateway_standby_stale_blocks(NET_FC);

  // A working standby: not due. Gone stale: due.
  master_nodes::bridge_standby_liveness_record live{};
  live.standby = named;
  live.named_height = 1000;
  cur.bridge_standby_liveness.push_back(live);
  EXPECT_FALSE(cur.bridge_standby_due(NET_FC, 1000 + stale, no_resolver, owner_members, reason));
  EXPECT_NE(reason.find("a standby is named"), std::string::npos) << reason;
  ASSERT_TRUE(cur.bridge_standby_due(NET_FC, 1001 + stale, no_resolver, owner_members, reason)) << reason;

  // An attested key a round generated after the named one is waiting to be named: not due...
  cur.bridge_key_attestations.push_back(attested(named, 900, others));
  cur.bridge_key_attestations.push_back(attested(waiting, 1100, others, 1110));
  EXPECT_FALSE(cur.bridge_standby_due(NET_FC, 1001 + stale, no_resolver, owner_members, reason));
  EXPECT_NE(reason.find("waiting to be named"), std::string::npos) << reason;
  // ...unless its committee shares too many operators with the owner's: it could never be named.
  cur.bridge_key_attestations.back().members = mixed;
  ASSERT_TRUE(cur.bridge_standby_due(NET_FC, 1001 + stale, no_resolver, owner_members, reason)) << reason;
  cur.bridge_key_attestations.pop_back();

  // A key from before the named standby can never be named (a gateway never names a key twice),
  // so it waits for nothing, however well it would fit.
  cur.bridge_key_attestations.push_back(attested(older, 800, others));
  ASSERT_TRUE(cur.bridge_standby_due(NET_FC, 1001 + stale, no_resolver, owner_members, reason)) << reason;

  // A key still collecting is not waiting either.
  cur.bridge_key_attestations.push_back(attested(waiting, 1100, others, 0));
  ASSERT_TRUE(cur.bridge_standby_due(NET_FC, 1001 + stale, no_resolver, owner_members, reason)) << reason;
}

TEST(GatewayStandbyRounds, too_few_seats_draw_no_committee)
{
  master_node_list::state_t cur(nullptr);
  cur.block_hash = crypto::cn_fast_hash("tip", 3);
  std::vector<crypto::public_key> owner_committee;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  const crypto::eddsa_public_key owner = new_vk();
  track_gateway(cur, owner);
  cur.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));

  // Only the owner's operators are seated: the overlap limit allows two of them, short of six.
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 130, no_resolver);
  EXPECT_TRUE(cur.bridge_standby_rounds.empty());
  // Four more operators make exactly enough.
  for (uint8_t who = 11; who <= 14; ++who)
    seat_run_by(cur, who);
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 140, no_resolver);
  EXPECT_EQ(cur.bridge_standby_rounds.size(), 1u);
}

TEST(GatewayStandbyRounds, an_attestation_record_keeps_its_committee)
{
  master_node_list::state_t cur(nullptr);
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  const crypto::eddsa_public_key vk = new_vk();
  ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, 0, 3, vk), 50));
  ASSERT_EQ(cur.bridge_key_attestations.size(), 1u);
  EXPECT_EQ(cur.bridge_key_attestations[0].members, c.mn);
  EXPECT_EQ(cur.bridge_key_attestations[0].round_height, 0u);
  EXPECT_EQ(cur.bridge_key_attestations[0].committee_height(NET_FC), 3 * bridge_epoch_blocks(NET_FC));
}

TEST(GatewayStandbyRounds, rounds_and_record_committees_survive_state_serialization)
{
  master_node_list::state_serialized s{};
  s.version = master_node_list::state_serialized::get_version(hf::hf23_bridge);
  ASSERT_EQ(s.version, master_node_list::state_serialized::version_t::version_8_bridge_standby_rounds);
  master_nodes::bridge_standby_round round{};
  round.round_height = 130;
  round.members = {rand_pubkey(), rand_pubkey()};
  s.bridge_standby_rounds.push_back(round);
  bridge_key_attestation_record r{};
  r.pgw_vk = new_vk();
  s.bridge_key_attestations.push_back(r);
  s.bridge_key_attestation_committees.push_back({130, round.members});

  master_node_list::state_serialized got{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), got));
  ASSERT_EQ(got.bridge_standby_rounds.size(), 1u);
  EXPECT_EQ(got.bridge_standby_rounds[0].round_height, 130u);
  EXPECT_EQ(got.bridge_standby_rounds[0].members, round.members);
  ASSERT_EQ(got.bridge_key_attestation_committees.size(), 1u);
  EXPECT_EQ(got.bridge_key_attestation_committees[0].round_height, 130u);
  EXPECT_EQ(got.bridge_key_attestation_committees[0].members, round.members);
  ASSERT_EQ(got.bridge_key_attestations.size(), 1u);

  // A state saved before rounds loads with none, and its records keep their old layout.
  s.version = master_node_list::state_serialized::version_t::version_7_bridge_standby_liveness;
  master_node_list::state_serialized older{};
  ASSERT_NO_THROW(serialization::parse_binary(serialization::dump_binary(s), older));
  EXPECT_TRUE(older.bridge_standby_rounds.empty());
  EXPECT_TRUE(older.bridge_key_attestation_committees.empty());
  EXPECT_EQ(older.bridge_key_attestations.size(), 1u);
}

// Attestation version 1: a standby round's committee says what it generated, only within the
// round's window, and the first round key attested is the one that may be named.
namespace
{
  tx_extra_bridge_key_attestation sign_round_attestation(const committee_keys& c, uint16_t voter, uint64_t round_height,
                                                         const crypto::eddsa_public_key& vk, uint8_t pevm_fill = 0x77)
  {
    tx_extra_bridge_key_attestation att{};
    att.version = 1;
    att.round_height = round_height;
    att.epoch = round_height / bridge_epoch_blocks(NET_FC);
    att.pgw_vk = vk;
    std::memset(att.pevm_address.data, pevm_fill, sizeof(att.pevm_address.data));
    att.voter_index = voter;
    const std::string msg = bridge_key_attestation_message(NET_FC, att);
    crypto_sign_detached(att.signature.data, nullptr, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                         c.ed_sec[voter].data);
    return att;
  }

  bool run_round_attestation(master_node_list::state_t& cur, const tx_extra_bridge_key_attestation& att, uint64_t block_height)
  {
    // A round's attestation never uses the epoch resolver: one that finds nothing proves it.
    const master_nodes::bridge_committee_resolver none = [](uint64_t, std::vector<crypto::public_key>&,
                                                            std::vector<crypto::ed25519_public_key>&, size_t&) { return false; };
    block blk{};
    blk.major_version = hf::hf23_bridge;
    blk.miner_tx.vin.push_back(txin_gen{block_height});
    transaction tx{};
    tx.type = txtype::bridge_registration;
    EXPECT_TRUE(add_bridge_key_attestation_to_tx_extra(tx.extra, att));
    return cur.process_bridge_key_attestation_tx(NET_FC, blk, tx, none);
  }

  // A state where `c` are seated and are the committee of the standby round at `round_height`.
  void open_round(master_node_list::state_t& cur, const committee_keys& c, uint64_t round_height)
  {
    for (size_t i = 0; i < c.mn.size(); ++i)
      seat_member(cur, c.mn[i], c.ed_pub[i], 1);
    cur.bridge_standby_rounds.push_back(master_nodes::bridge_standby_round{round_height, c.mn});
  }

  master_nodes::bridge_record_overlap_fn overlap_of(const master_node_list::state_t& cur)
  {
    // Counted by operator from the seats, as consensus does; a seat without one is its own.
    return [&cur](const bridge_key_attestation_record& a, const bridge_key_attestation_record& b) -> std::optional<size_t> {
      if (a.members.empty() || b.members.empty())
        return std::nullopt;
      const auto op = [&cur](const crypto::public_key& pk) {
        const auto it = cur.master_nodes_infos.find(pk);
        if (it == cur.master_nodes_infos.end() || it->second->operator_address == account_public_address{})
          return std::string(reinterpret_cast<const char*>(&pk), sizeof(pk));
        return std::string(1, static_cast<char>(it->second->operator_address.m_spend_public_key.data[0]));
      };
      return bridge_committee_operator_overlap(a.members, b.members, op);
    };
  }
}

TEST(GatewayStandbyRounds, the_attestation_format_and_message_carry_the_round)
{
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  const crypto::eddsa_public_key vk = new_vk();
  const auto att = sign_round_attestation(c, 2, 130, vk);

  transaction tx{};
  ASSERT_TRUE(add_bridge_key_attestation_to_tx_extra(tx.extra, att));
  tx_extra_bridge_key_attestation got{};
  ASSERT_TRUE(get_field_from_tx_extra(tx.extra, got));
  EXPECT_EQ(got.version, 1);
  EXPECT_EQ(got.round_height, 130u);
  EXPECT_EQ(got.voter_index, 2);

  // The round is signed: version 0's bytes are unchanged, version 1 adds it (u64 LE) at the end.
  tx_extra_bridge_key_attestation v0 = att;
  v0.version = 0;
  const std::string m0 = bridge_key_attestation_message(NET_FC, v0), m1 = bridge_key_attestation_message(NET_FC, att);
  ASSERT_EQ(m1.size(), m0.size() + 8);
  EXPECT_EQ(static_cast<unsigned char>(m1[m0.size()]), 130);
  auto other_round = att;
  other_round.round_height = 140;
  EXPECT_NE(bridge_key_attestation_message(NET_FC, other_round), m1);

  std::string reason;
  EXPECT_TRUE(verify_bridge_key_attestation(att, c.ed_pub, NET_FC, reason)) << reason;
  EXPECT_FALSE(verify_bridge_key_attestation(other_round, c.ed_pub, NET_FC, reason)) << "signed for another round";
  auto wrong_epoch = sign_round_attestation(c, 2, 130, vk);
  wrong_epoch.epoch = 9;
  EXPECT_FALSE(verify_bridge_key_attestation(wrong_epoch, c.ed_pub, NET_FC, reason));
  EXPECT_NE(reason.find("names epoch"), std::string::npos) << reason;
  auto no_round = att;
  no_round.round_height = 0;
  EXPECT_FALSE(verify_bridge_key_attestation(no_round, c.ed_pub, NET_FC, reason));
  auto future = att;
  future.version = 2;
  EXPECT_FALSE(verify_bridge_key_attestation(future, c.ed_pub, NET_FC, reason));
  EXPECT_NE(reason.find("unknown key attestation version"), std::string::npos) << reason;
}

TEST(GatewayStandbyRounds, a_round_is_attested_only_within_its_window)
{
  const uint64_t window = bridge_standby_round_window_blocks(NET_FC);
  const size_t threshold = bridge_committee_threshold(NET_FC);
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  master_node_list::state_t cur(nullptr);
  open_round(cur, c, 130);
  const crypto::eddsa_public_key vk = new_vk();

  // Too early, too late: the edges of the window.
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk), 130)) << "before the round's block is on chain";
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk), 130 + window + 1));
  EXPECT_TRUE(cur.bridge_key_attestations.empty());
  EXPECT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk), 131));
  EXPECT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 1, 130, vk), 130 + window));

  // A round that never opened, however well signed; a non-member; a forged signature; twice.
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 120, vk), 125));
  auto outsider = sign_round_attestation(c, 2, 130, vk);
  outsider.voter_index = static_cast<uint16_t>(c.mn.size());
  EXPECT_FALSE(run_round_attestation(cur, outsider, 135));
  auto forged = sign_round_attestation(c, 2, 130, vk);
  forged.voter_index = 3;
  EXPECT_FALSE(run_round_attestation(cur, forged, 135));
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk), 135)) << "a member counts once";

  ASSERT_EQ(cur.bridge_key_attestations.size(), 1u);
  for (uint16_t i = 2; i + 1 < threshold; ++i)
    ASSERT_TRUE(run_round_attestation(cur, sign_round_attestation(c, i, 130, vk), 136));
  EXPECT_EQ(cur.bridge_key_attestations[0].attested_height, 0u) << "one short of the threshold";
  ASSERT_TRUE(run_round_attestation(cur, sign_round_attestation(c, static_cast<uint16_t>(threshold - 1), 130, vk), 137));

  const auto rec = find_attested_bridge_key(cur.bridge_key_attestations, vk);
  ASSERT_TRUE(rec);
  EXPECT_EQ(rec->attested_height, 137u);
  EXPECT_EQ(rec->round_height, 130u);
  EXPECT_EQ(rec->members, c.mn);
  EXPECT_EQ(rec->committee_height(NET_FC), 130u);
}

TEST(GatewayStandbyRounds, a_member_attests_one_key_a_round)
{
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  master_node_list::state_t cur(nullptr);
  open_round(cur, c, 130);
  cur.bridge_standby_rounds.push_back(master_nodes::bridge_standby_round{140, c.mn});
  const crypto::eddsa_public_key vk = new_vk();

  ASSERT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk), 131));
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, new_vk()), 132)) << "another key";
  EXPECT_FALSE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, vk, 0x55), 132)) << "another wBDX address";
  EXPECT_EQ(cur.bridge_key_attestations.size(), 1u);
  // Another member of the round may, and so may this one in another round.
  EXPECT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 1, 130, new_vk()), 132));
  EXPECT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 0, 140, new_vk()), 141));
  EXPECT_EQ(cur.bridge_key_attestations.size(), 3u);
}

TEST(GatewayStandbyRounds, epoch_attestations_still_work_and_stay_apart)
{
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  master_node_list::state_t cur(nullptr);
  open_round(cur, c, 130);
  const crypto::eddsa_public_key vk = new_vk();
  ASSERT_TRUE(run_attestation(cur, c, sign_attestation(c, 0, 3, vk), 131));
  auto same_epoch = sign_round_attestation(c, 0, 130, vk);
  ASSERT_EQ(same_epoch.epoch, 1u);
  ASSERT_TRUE(run_round_attestation(cur, same_epoch, 131));
  ASSERT_EQ(cur.bridge_key_attestations.size(), 2u);
  EXPECT_EQ(cur.bridge_key_attestations[0].round_height, 0u);
  EXPECT_EQ(cur.bridge_key_attestations[1].round_height, 130u);
}

TEST(GatewayStandbyRounds, the_first_round_key_attested_is_the_one_that_may_be_named)
{
  master_node_list::state_t cur(nullptr);
  std::vector<crypto::public_key> owner_committee, others;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  for (uint8_t who = 11; who <= 16; ++who)
    others.push_back(seat_run_by(cur, who));
  const crypto::eddsa_public_key owner = new_vk(), first = new_vk(), second = new_vk(), old_standby = new_vk();
  std::vector<bridge_key_attestation_record> records{attested(owner, 0, owner_committee)};
  const auto overlap = overlap_of(cur);
  const std::vector<master_nodes::bridge_standby_liveness_record> none;
  std::string reason;
  auto may_name = [&](const crypto::eddsa_public_key& k, const std::vector<master_nodes::bridge_standby_liveness_record>& live, uint64_t at) {
    return check_bridge_standby_naming(records, owner, k, NET_FC, overlap, live, at, reason);
  };

  // A later round's key attested first holds the place: round order is not what counts.
  records.push_back(attested(second, 150, others, 160));
  records.push_back(attested(first, 140, others, 165));
  EXPECT_TRUE(may_name(second, none, 170)) << reason;
  EXPECT_FALSE(may_name(first, none, 170));
  EXPECT_NE(reason.find("attested first"), std::string::npos) << reason;

  // Unnamed for too long, its holders are presumed gone: it stops holding the place.
  const uint64_t recent = gateway_standby_stale_blocks(NET_FC);
  EXPECT_FALSE(may_name(first, none, 160 + recent));
  EXPECT_TRUE(may_name(first, none, 161 + recent)) << reason;

  // A standby named before does not hold it either, though it was attested earlier still.
  records.push_back(attested(old_standby, 130, others, 140));
  master_nodes::bridge_standby_liveness_record live{};
  live.standby = old_standby;
  live.named_height = 145;
  EXPECT_TRUE(may_name(second, {live}, 170)) << reason;
  // And a key from before the last named standby's committee is no candidate at all: it cannot
  // hold the place of a newer one, though it was attested first.
  const crypto::eddsa_public_key earlier = new_vk(), named_now = new_vk(), later = new_vk();
  records = {attested(owner, 0, owner_committee), attested(earlier, 140, others, 150),
             attested(named_now, 145, others, 155), attested(later, 150, others, 160)};
  live.standby = named_now;
  EXPECT_TRUE(may_name(later, {live}, 170)) << reason;

  // The overlap rule is judged on the round's own members.
  std::vector<crypto::public_key> mixed;
  for (uint8_t who : {1, 2, 3, 21, 22, 23})
    mixed.push_back(seat_run_by(cur, who));
  const crypto::eddsa_public_key too_close = new_vk();
  records = {attested(owner, 0, owner_committee), attested(too_close, 150, mixed, 155)};
  EXPECT_FALSE(may_name(too_close, none, 170));
  EXPECT_NE(reason.find("at most"), std::string::npos) << reason;
  // ...and a key that could never be named holds no place.
  records.push_back(attested(second, 160, others, 165));
  EXPECT_TRUE(may_name(second, none, 170)) << reason;
}

TEST(GatewayStandbyRounds, a_key_left_unnamed_stops_holding_up_new_rounds)
{
  master_node_list::state_t cur(nullptr);
  std::vector<crypto::public_key> owner_committee, others;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  for (uint8_t who = 11; who <= 16; ++who)
    others.push_back(seat_run_by(cur, who));
  const crypto::eddsa_public_key owner = new_vk();
  track_gateway(cur, owner);
  cur.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));
  cur.bridge_key_attestations.push_back(attested(new_vk(), 150, others, 160));
  std::vector<crypto::public_key> owner_members;
  std::string reason;
  const uint64_t recent = gateway_standby_stale_blocks(NET_FC);
  EXPECT_FALSE(cur.bridge_standby_due(NET_FC, 160 + recent, no_resolver, owner_members, reason));
  EXPECT_NE(reason.find("waiting to be named"), std::string::npos) << reason;
  EXPECT_TRUE(cur.bridge_standby_due(NET_FC, 161 + recent, no_resolver, owner_members, reason)) << reason;
}

TEST(GatewayStandbyRounds, the_record_cap_never_drops_the_owner_or_the_named_standby)
{
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  master_node_list::state_t cur(nullptr);
  open_round(cur, c, 130);
  const crypto::eddsa_public_key owner = new_vk(), standby = new_vk();
  track_gateway(cur, owner);
  master_nodes::bridge_standby_liveness_record live{};
  live.standby = standby;
  cur.bridge_standby_liveness.push_back(live);

  // Both are the oldest, and everything is attested: they would be the first to go.
  cur.bridge_key_attestations.push_back(attested(owner, 0, c.mn));
  cur.bridge_key_attestations.push_back(attested(standby, 0, c.mn));
  const crypto::eddsa_public_key oldest_other = new_vk();
  cur.bridge_key_attestations.push_back(attested(oldest_other, 0, c.mn));
  while (cur.bridge_key_attestations.size() < 64)
    cur.bridge_key_attestations.push_back(attested(new_vk(), 0, c.mn));

  ASSERT_TRUE(run_round_attestation(cur, sign_round_attestation(c, 0, 130, new_vk()), 131));
  EXPECT_EQ(cur.bridge_key_attestations.size(), 64u);
  EXPECT_TRUE(find_attested_bridge_key(cur.bridge_key_attestations, owner));
  EXPECT_TRUE(find_attested_bridge_key(cur.bridge_key_attestations, standby));
  EXPECT_FALSE(find_attested_bridge_key(cur.bridge_key_attestations, oldest_other)) << "the oldest of the rest goes";
}

TEST(GatewayStandbyRounds, from_a_round_to_a_named_standby)
{
  const size_t size = bridge_committee_size(NET_FC), threshold = bridge_committee_threshold(NET_FC);
  master_node_list::state_t cur(nullptr);
  std::vector<crypto::public_key> owner_committee;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(cur, who));
  // The candidates, with real signer keys.
  const committee_keys pool = make_committee(8);
  std::map<crypto::public_key, crypto::ed25519_secret_key> secret;
  for (size_t i = 0; i < pool.mn.size(); ++i)
  {
    seat_member(cur, pool.mn[i], pool.ed_pub[i], 1);
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos[pool.mn[i]]);
    info->operator_address.m_spend_public_key.data[0] = static_cast<uint8_t>(40 + i);
    cur.master_nodes_infos[pool.mn[i]] = info;
    secret[pool.mn[i]] = pool.ed_sec[i];
  }
  const crypto::eddsa_public_key owner = new_vk(), key = new_vk();
  track_gateway(cur, owner);
  cur.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));

  // The round draws a committee from the others...
  cur.block_hash = crypto::cn_fast_hash("round", 5);
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 130, no_resolver);
  ASSERT_EQ(cur.bridge_standby_rounds.size(), 1u);
  const auto members = cur.bridge_standby_rounds[0].members;
  ASSERT_EQ(members.size(), size);

  // ...whose members attest their key, by their place in it...
  committee_keys drawn;
  for (const auto& m : members)
    drawn.ed_sec.push_back(secret.at(m));
  drawn.mn = members;
  for (uint16_t i = 0; i < threshold; ++i)
    ASSERT_TRUE(run_round_attestation(cur, sign_round_attestation(drawn, i, 130, key), 135));
  const auto rec = find_attested_bridge_key(cur.bridge_key_attestations, key);
  ASSERT_TRUE(rec);

  // ...so the next round draws nothing, the key may be named, and once its round is gone the
  // record still knows the committee.
  cur.block_hash = crypto::cn_fast_hash("next", 4);
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 140, no_resolver);
  EXPECT_EQ(cur.bridge_standby_rounds.size(), 1u) << "only the old round, still in its window";
  cur.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 141, no_resolver);
  EXPECT_TRUE(cur.bridge_standby_rounds.empty());
  std::string reason;
  EXPECT_TRUE(check_bridge_standby_naming(cur.bridge_key_attestations, owner, key, NET_FC, overlap_of(cur), {}, 142, reason)) << reason;
  std::vector<crypto::public_key> got;
  std::vector<crypto::ed25519_public_key> keys;
  ASSERT_TRUE(cur.bridge_round_committee(130, got, keys));
  EXPECT_EQ(got, members);
}

TEST(GatewayStandbyRounds, a_slash_report_is_judged_against_the_rounds_committee)
{
  const size_t threshold = bridge_committee_threshold(NET_FC);
  const committee_keys c = make_committee(bridge_committee_size(NET_FC));
  master_node_list::state_t cur(nullptr);
  for (size_t i = 0; i < c.mn.size(); ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 1);
  cur.bridge_key_attestations.push_back(attested(new_vk(), 130, c.mn, 135));

  auto report = [&](uint64_t round_height, uint8_t version) {
    tx_extra_bridge_slash slash{};
    slash.version = version; slash.scheme = 1; slash.failing_check = 0;
    slash.accused_index = 5; slash.epoch = 1; slash.height = 200; slash.round_height = round_height;
    std::memset(&slash.transcript_root, 0xab, sizeof(slash.transcript_root));
    const std::string msg = bridge_slash_message(NET_FC, slash);
    for (uint16_t i = 0; i < threshold; ++i)
    {
      bridge_slash_signature s{}; s.voter_index = i;
      crypto_sign_detached(s.signature.data, nullptr, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                           c.ed_sec[i].data);
      slash.accusers.push_back(s);
    }
    return slash;
  };
  auto run = [&](const tx_extra_bridge_slash& slash) {
    const master_nodes::bridge_committee_resolver none = [](uint64_t, std::vector<crypto::public_key>&,
                                                            std::vector<crypto::ed25519_public_key>&, size_t&) { return false; };
    block blk{};
    blk.major_version = hf::hf23_bridge;
    blk.miner_tx.vin.push_back(txin_gen{uint64_t{200}});
    transaction tx{};
    tx.type = txtype::bridge_registration;
    EXPECT_TRUE(add_bridge_slash_to_tx_extra(tx.extra, slash));
    return cur.process_bridge_slash_tx(NET_FC, blk, tx, none);
  };

  // The format carries the round, and the signature covers it.
  transaction tx{};
  ASSERT_TRUE(add_bridge_slash_to_tx_extra(tx.extra, report(130, 2)));
  tx_extra_bridge_slash got{};
  ASSERT_TRUE(get_field_from_tx_extra(tx.extra, got));
  EXPECT_EQ(got.round_height, 130u);
  auto other = report(130, 2);
  other.round_height = 140;
  EXPECT_NE(bridge_slash_message(NET_FC, other), bridge_slash_message(NET_FC, report(130, 2)));

  // Version and round must agree, and old reports keep their exact bytes.
  std::string reason;
  EXPECT_FALSE(verify_bridge_slash_evidence(report(0, 2), c.ed_pub, threshold, NET_FC, reason));
  EXPECT_FALSE(verify_bridge_slash_evidence(report(130, 1), c.ed_pub, threshold, NET_FC, reason));
  EXPECT_NE(reason.find("disagree"), std::string::npos) << reason;
  EXPECT_TRUE(verify_bridge_slash_evidence(report(130, 2), c.ed_pub, threshold, NET_FC, reason)) << reason;
  EXPECT_EQ(bridge_slash_message(NET_FC, report(0, 0)), bridge_slash_message(NET_FC, report(0, 1)));

  // A round with no attested key has no committee; the real one convicts its member.
  EXPECT_FALSE(run(report(140, 2)));
  EXPECT_FALSE(cur.master_nodes_infos[c.mn[5]]->bridge_seat.is_forfeited());
  ASSERT_TRUE(run(report(130, 2)));
  EXPECT_TRUE(cur.master_nodes_infos[c.mn[5]]->bridge_seat.is_forfeited());
}

// Each chain has its own round: after a reorg across a round's start the committee comes from the
// new block, so what the orphaned round's members signed does not carry over.
TEST(GatewayStandbyRounds, a_reorg_across_a_rounds_start_draws_another_committee)
{
  const size_t size = bridge_committee_size(NET_FC);
  master_node_list::state_t base(nullptr);
  std::vector<crypto::public_key> owner_committee;
  for (uint8_t who = 1; who <= 6; ++who)
    owner_committee.push_back(seat_run_by(base, who));
  const committee_keys pool = make_committee(10);
  std::map<crypto::public_key, crypto::ed25519_secret_key> secret;
  for (size_t i = 0; i < pool.mn.size(); ++i)
  {
    seat_member(base, pool.mn[i], pool.ed_pub[i], 1);
    auto info = std::make_shared<master_node_info>(*base.master_nodes_infos[pool.mn[i]]);
    info->operator_address.m_spend_public_key.data[0] = static_cast<uint8_t>(40 + i);
    base.master_nodes_infos[pool.mn[i]] = info;
    secret[pool.mn[i]] = pool.ed_sec[i];
  }
  const crypto::eddsa_public_key owner = new_vk();
  track_gateway(base, owner);
  base.bridge_key_attestations.push_back(attested(owner, 0, owner_committee));

  master_node_list::state_t chain_a = base, chain_b = base;
  chain_a.block_hash = crypto::cn_fast_hash("a", 1);
  chain_a.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 130, no_resolver);
  ASSERT_EQ(chain_a.bridge_standby_rounds.size(), 1u);
  const auto a_members = chain_a.bridge_standby_rounds[0].members;

  // Find another chain whose block draws a committee differing at some index.
  size_t differs_at = size;
  for (int i = 0; i < 16 && differs_at == size; ++i)
  {
    chain_b = base;
    chain_b.block_hash = crypto::cn_fast_hash(&i, sizeof(i));
    chain_b.update_bridge_standby_rounds(NET_FC, hf::hf23_bridge, 130, no_resolver);
    ASSERT_EQ(chain_b.bridge_standby_rounds.size(), 1u);
    for (size_t k = 0; k < size && differs_at == size; ++k)
      if (chain_b.bridge_standby_rounds[0].members[k] != a_members[k])
        differs_at = k;
  }
  ASSERT_LT(differs_at, size);

  committee_keys a;
  a.mn = a_members;
  for (const auto& m : a_members)
    a.ed_sec.push_back(secret.at(m));
  const auto att = sign_round_attestation(a, static_cast<uint16_t>(differs_at), 130, new_vk());
  EXPECT_TRUE(run_round_attestation(chain_a, att, 131));
  EXPECT_FALSE(run_round_attestation(chain_b, att, 131)) << "another member holds that place on this chain";
}
