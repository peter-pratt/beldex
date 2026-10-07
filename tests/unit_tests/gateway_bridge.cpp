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
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_core/master_node_list.h"     // state_t + bridge_committee_resolver (Phase F consensus action)
#include "cryptonote_core/master_node_quorum_cop.h" // quorum / quorum_manager
#include "cryptonote_core/uptime_proof.h"          // complete uptime_proof::Proof for master_node_info's proof dtor
#include "cryptonote_config.h"
#include "crypto/crypto.h"

#include <limits>
#include <memory>
#include <set>
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

  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5000));
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2, 3}, 3), 5001)) << "skips 3";
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001)) << "repeats 2";
  EXPECT_EQ(observed_epoch(cur, 1), 2u);
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2, 3}, 3), 5003)) << "now 4 is next";
  EXPECT_EQ(observed_epoch(cur, 1), 4u);
}

// Only chains the bridge serves on this network, and never the gateway's reserved id
// (its epoch moves with its owner hand-over).
TEST(GatewayBridgeRotation, an_ack_must_be_for_a_bridge_chain_of_this_network)
{
  master_node_list::state_t st(nullptr);
  tx_extra_bridge_rotation_ack ack{};
  ack.key_epoch = 2; ack.contract = addr20(0x22); ack.new_signer = addr20(0x11);
  std::string reason;
  ack.chain_id = 56;    EXPECT_TRUE(st.check_bridge_rotation_ack(ack, network_type::MAINNET, reason)) << reason;
  ack.chain_id = 31337; EXPECT_FALSE(st.check_bridge_rotation_ack(ack, network_type::MAINNET, reason));
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

  // First ack for chain 1 → epoch 2 advances.
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
