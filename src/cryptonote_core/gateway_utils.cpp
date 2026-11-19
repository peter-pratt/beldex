// Copyright (c) 2024, The Beldex Project
//
// Gateway address (HF22) consensus-state helpers. See gateway_utils.h.

#include "gateway_utils.h"

#include <algorithm>
#include <cstring>
#include <oxenc/endian.h>
#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h" // generate_genesis_block
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/eth_signature.h"
#include "crypto/eddsa_signature.h"
#include "serialization/binary_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h" // verRctSemanticsSimple (range-proof + balance)
#include "beldex_economy.h"

#include <sodium/crypto_sign.h> // crypto_sign_verify_detached (bridge slash ed25519 evidence)

namespace cryptonote
{

namespace
{
  void set_reason(std::string* reason, std::string value)
  {
    if (reason) *reason = std::move(value);
  }

  // Authoritative genesis block hash for a network, cached (computed once per
  // process). Used to bind gateway signatures to a specific chain: unlike a
  // bare network-type byte, the genesis hash differs even between two chains
  // that share a nettype enum (e.g. a fork), so a signature can never be
  // replayed across chains. Both signer and verifier derive it from the same
  // network config, so they agree.
  const crypto::hash& gateway_chain_binding(network_type nettype)
  {
    static std::mutex mtx;
    static std::unordered_map<uint8_t, crypto::hash> cache;
    std::lock_guard<std::mutex> lk(mtx);
    auto it = cache.find(static_cast<uint8_t>(nettype));
    if (it == cache.end())
    {
      block genesis{};
      // Hard-fail rather than fall back to null_hash. The genesis hash is the
      // SOLE anti-cross-chain-replay binding for keyless gateway signatures; an
      // all-zero fallback would make every signature on this network share the
      // same (zero) binding and become replayable across chains. A failure here
      // means a misconfigured network and must not be silently papered over.
      // See docs/GATEWAY_SECURITY_FIXES.md (F4).
      CHECK_AND_ASSERT_THROW_MES(generate_genesis_block(genesis, nettype),
          "gateway: failed to generate genesis block for chain binding");
      it = cache.emplace(static_cast<uint8_t>(nettype), get_block_hash(genesis)).first;
    }
    return it->second;
  }

  // Enumerate every gateway descriptor operation carried in tx.extra.
  std::vector<tx_extra_gateway_descriptor_operation> extract_gateway_ops(const transaction& tx)
  {
    std::vector<tx_extra_gateway_descriptor_operation> ops;
    size_t skip = 0;
    tx_extra_gateway_descriptor_operation op{};
    while (get_field_from_tx_extra(tx.extra, op, skip++))
      ops.push_back(op);
    return ops;
  }

  // Enumerate HF23 governance / routing fields carried in tx.extra.
  std::vector<tx_extra_gateway_freeze> extract_gateway_freezes(const transaction& tx)
  {
    std::vector<tx_extra_gateway_freeze> v;
    size_t skip = 0;
    tx_extra_gateway_freeze op{};
    while (get_field_from_tx_extra(tx.extra, op, skip++))
      v.push_back(op);
    return v;
  }

  std::vector<tx_extra_gateway_takeover> extract_gateway_takeovers(const transaction& tx)
  {
    std::vector<tx_extra_gateway_takeover> v;
    size_t skip = 0;
    tx_extra_gateway_takeover op{};
    while (get_field_from_tx_extra(tx.extra, op, skip++))
      v.push_back(op);
    return v;
  }

  // The descriptor a completed takeover leaves: the current one with its standby as owner
  // and no standby left.
  gateway_descriptor_base taken_over_descriptor(const gateway_descriptor_base& current)
  {
    gateway_descriptor_base d = current;
    d.owner_key   = current.standby_owner;
    d.has_standby = 0;
    d.standby_owner = gateway_owner_key_v{};
    return d;
  }

  // A standby is bound to the owner that named it. Its holders are the committee that
  // generated it, and a member's bond comes back two owner hand-overs after it asks to
  // leave; a standby carried past a hand-over, or named again later, would leave a live
  // failover key with holders who may have no bond. So a descriptor may keep the current
  // standby only under the current owner, and may never name a key this gateway has had
  // as owner or standby before.
  bool standby_is_fresh(const gateway_account_data& acct, const gateway_descriptor_base& next, std::string& reason)
  {
    if (!next.has_standby)
      return true;
    const gateway_descriptor_base& current = acct.latest_descriptor();
    if (current.has_standby && current.standby_owner == next.standby_owner && current.owner_key == next.owner_key)
      return true; // the same standby, restated by the owner that named it
    for (const auto& d : acct.descriptor_history)
    {
      if (d.owner_key == next.standby_owner || (d.has_standby && d.standby_owner == next.standby_owner))
      {
        reason = "a gateway's standby owner must be a key it has never had as owner or standby";
        return false;
      }
    }
    return true;
  }

  std::vector<tx_extra_gateway_repoint> extract_gateway_repoints(const transaction& tx)
  {
    std::vector<tx_extra_gateway_repoint> v;
    size_t skip = 0;
    tx_extra_gateway_repoint op{};
    while (get_field_from_tx_extra(tx.extra, op, skip++))
      v.push_back(op);
    return v;
  }

}

std::vector<tx_extra_gateway_release_ref> extract_gateway_release_refs(const transaction& tx)
{
  std::vector<tx_extra_gateway_release_ref> v;
  size_t skip = 0;
  tx_extra_gateway_release_ref r{};
  while (get_field_from_tx_extra(tx.extra, r, skip++))
    v.push_back(r);
  return v;
}

std::vector<std::pair<crypto::public_key, crypto::hash>> gateway_release_ref_records(const transaction& tx)
{
  std::vector<std::pair<crypto::public_key, crypto::hash>> out;
  std::set<crypto::public_key> gws;
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
      gws.insert(g->gateway_addr);
  for (const auto& rf : extract_gateway_release_refs(tx))
  {
    const crypto::hash ref = gateway_release_ref_hash(rf.chain_id, rf.evm_txid, rf.log_index);
    for (const auto& gw : gws)
      out.emplace_back(gw, ref);
  }
  return out;
}

std::string bridge_mint_publish_message(network_type nettype, std::string_view payload)
{
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.reserve(hashkey::BRIDGE_MINT_PUBLISH.size() + sizeof(genesis) + payload.size());
  buf.append(hashkey::BRIDGE_MINT_PUBLISH);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.append(payload);
  return buf;
}

crypto::hash gateway_release_ref_hash(uint64_t chain_id, const crypto::hash& evm_txid, uint32_t log_index)
{
  std::string buf;
  buf.reserve(hashkey::GW_RELEASE_REF.size() + 8 + sizeof(evm_txid) + 4);
  buf.append(hashkey::GW_RELEASE_REF);
  for (int i = 0; i < 8; ++i)
    buf.push_back(static_cast<char>((chain_id >> (8 * i)) & 0xff)); // u64 LE
  buf.append(reinterpret_cast<const char*>(&evm_txid), sizeof(evm_txid));
  for (int i = 0; i < 4; ++i)
    buf.push_back(static_cast<char>((log_index >> (8 * i)) & 0xff)); // u32 LE
  return crypto::cn_fast_hash(buf.data(), buf.size());
}

namespace
{

  bool same_descriptor(const gateway_descriptor_base& a, const gateway_descriptor_base& b)
  {
    auto ca = a, cb = b; // dump_binary needs non-const
    return serialization::dump_binary(ca) == serialization::dump_binary(cb);
  }

  // Ordered gateway_input_sig entries (one per txin_gateway).
  std::vector<const gateway_input_sig*> input_sigs(const transaction& tx)
  {
    std::vector<const gateway_input_sig*> sigs;
    for (const auto& p : tx.gateway_proofs)
      if (const auto* s = std::get_if<gateway_input_sig>(&p))
        sigs.push_back(s);
    return sigs;
  }

  // Mutate a materialized balance for one asset. Overflow on increase and
  // underflow on decrease both fail (block-invalidating at apply time).
  bool change_gateway_balance(gateway_account_data& acct, const crypto::asset_id& aid,
                              uint64_t amount, bool increase, std::string* reason)
  {
    for (auto& b : acct.balances)
    {
      if (b.asset_id == aid)
      {
        if (increase)
        {
          if (b.amount > std::numeric_limits<uint64_t>::max() - amount)
          {
            set_reason(reason, "gateway balance overflow on increase");
            return false;
          }
          b.amount += amount;
        }
        else
        {
          if (b.amount < amount)
          {
            set_reason(reason, "gateway balance underflow on decrease (insufficient funds)");
            return false;
          }
          b.amount -= amount;
        }
        return true;
      }
    }
    // No existing entry.
    if (!increase)
    {
      set_reason(reason, "gateway balance underflow on decrease (no balance for asset)");
      return false;
    }
    acct.balances.push_back(gateway_balance_entry{aid, amount});
    return true;
  }
}

namespace
{
  // Common shape for every gateway signature/proof message:
  //   H(domain || genesis_hash || tx_prefix_hash).
  // The genesis hash binds the message to a specific chain (gateway constructs
  // carry no key image, so without a chain binding a signature would replay on
  // any chain where the same gateway/owner exists — including a fork sharing a
  // nettype enum). It is a consensus rule: signer and verifier must agree on
  // nettype, and both derive the genesis hash from the same network config.
  crypto::hash gateway_message(std::string_view domain, network_type nettype, const transaction& tx)
  {
    const crypto::hash prefix_hash = get_transaction_prefix_hash(tx);
    const crypto::hash& genesis    = gateway_chain_binding(nettype);
    std::string buf;
    buf.reserve(domain.size() + sizeof(genesis) + sizeof(prefix_hash));
    buf.append(domain);
    buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
    buf.append(reinterpret_cast<const char*>(&prefix_hash), sizeof(prefix_hash));
    return crypto::cn_fast_hash(buf.data(), buf.size());
  }

  // Governance attestation message (HF23): H(domain || genesis_hash || fields).
  // Unlike gateway_message this does NOT hash a tx prefix — a freeze/re-point
  // supermajority is collected off-chain over explicit fields, not over the tx
  // that carries the evidence (the same evidence blob can be attached to any
  // carrier tx). genesis binding still prevents cross-chain/fork replay.
  crypto::hash gateway_governance_message(std::string_view domain, network_type nettype, const std::string& fields)
  {
    const crypto::hash& genesis = gateway_chain_binding(nettype);
    std::string buf;
    buf.reserve(domain.size() + sizeof(genesis) + fields.size());
    buf.append(domain);
    buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
    buf.append(fields);
    return crypto::cn_fast_hash(buf.data(), buf.size());
  }

  // Little-endian byte append of a u64 (explicit, so the message is
  // endianness-independent across signer/verifier platforms).
  void append_u64_le(std::string& buf, uint64_t v)
  {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
  }
}

crypto::hash gateway_input_message(network_type nettype, const transaction& tx)
{
  return gateway_message(hashkey::GW_INPUT_SIG, nettype, tx);
}

crypto::hash gateway_freeze_message(network_type nettype, const crypto::public_key& gateway_id,
                                    bool freeze, uint64_t governance_seq, uint64_t epoch_height)
{
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  fields.push_back(freeze ? 1 : 0);
  append_u64_le(fields, governance_seq);
  append_u64_le(fields, epoch_height);
  return gateway_governance_message(hashkey::GW_FREEZE, nettype, fields);
}

crypto::hash gateway_takeover_cancel_message(network_type nettype, const crypto::public_key& gateway_id,
                                             uint64_t started_height)
{
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  append_u64_le(fields, started_height);
  return gateway_governance_message(hashkey::GW_TAKEOVER_CANCEL, nettype, fields);
}

crypto::hash gateway_takeover_begin_message(network_type nettype, const crypto::public_key& gateway_id,
                                            const gateway_descriptor_base& current, uint64_t step_count)
{
  auto desc_copy = current; // dump_binary needs non-const
  const std::string desc_blob = serialization::dump_binary(desc_copy);
  const crypto::hash desc_hash = crypto::cn_fast_hash(desc_blob.data(), desc_blob.size());
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  fields.append(reinterpret_cast<const char*>(&desc_hash), sizeof(desc_hash));
  append_u64_le(fields, step_count);
  return gateway_governance_message(hashkey::GW_TAKEOVER_BEGIN, nettype, fields);
}

crypto::hash gateway_standby_name_message(network_type nettype, const crypto::public_key& gateway_id,
                                          uint64_t descriptor_count, const gateway_owner_key_v& standby)
{
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  append_u64_le(fields, descriptor_count);
  fields.push_back(static_cast<char>(standby.index()));
  std::visit([&fields](const auto& k) { fields.append(reinterpret_cast<const char*>(&k), sizeof(k)); }, standby);
  return gateway_governance_message(hashkey::GW_STANDBY_NAME, nettype, fields);
}

crypto::hash gateway_standby_alive_message(network_type nettype, const crypto::public_key& gateway_id,
                                           const gateway_owner_key_v& standby, uint64_t proof_height,
                                           const crypto::hash& block_hash)
{
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  fields.push_back(static_cast<char>(standby.index()));
  std::visit([&fields](const auto& k) { fields.append(reinterpret_cast<const char*>(&k), sizeof(k)); }, standby);
  append_u64_le(fields, proof_height);
  fields.append(reinterpret_cast<const char*>(&block_hash), sizeof(block_hash));
  return gateway_governance_message(hashkey::GW_STANDBY_ALIVE, nettype, fields);
}

uint64_t gateway_standby_alive_height(network_type nettype, uint64_t chain_height)
{
  constexpr uint64_t LAG = 3;
  const uint64_t slot = gateway_standby_alive_slot_blocks(nettype);
  if (chain_height < LAG + 1)
    return 0;
  return (chain_height - 1 - LAG) / slot * slot;
}

std::string bridge_key_attestation_message(network_type nettype, const tx_extra_bridge_key_attestation& att)
{
  // DOMAIN || genesis(32) || version(u8) || epoch(u64 LE) || pgw_vk(32) || pevm_address(20),
  // and for version >= 1 || round_height(u64 LE). A check-in (version 2) has empty keys; its
  // version byte keeps it from ever reading as an attestation.
  // The voter is not in it: every member signs the same statement.
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.append(hashkey::BRIDGE_KEY_ATTESTATION);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.push_back(static_cast<char>(att.version));
  append_u64_le(buf, att.epoch);
  buf.append(reinterpret_cast<const char*>(att.pgw_vk.data), sizeof(att.pgw_vk.data));
  buf.append(reinterpret_cast<const char*>(att.pevm_address.data), sizeof(att.pevm_address.data));
  if (att.version >= 1)
    append_u64_le(buf, att.round_height);
  return buf;
}

bool verify_bridge_key_attestation(const tx_extra_bridge_key_attestation& att,
                                   const std::vector<crypto::ed25519_public_key>& signer_keys,
                                   network_type nettype, std::string& reason)
{
  if (att.version > BRIDGE_STANDBY_CHECKIN_VERSION)
  {
    reason = "unknown key attestation version";
    return false;
  }
  // A round's attestation or check-in names the epoch its round is in, so the two can never
  // disagree.
  if (att.version >= 1 && (att.round_height == 0 || att.epoch != att.round_height / bridge_epoch_blocks(nettype)))
  {
    reason = "key attestation of standby round " + std::to_string(att.round_height) + " names epoch "
             + std::to_string(att.epoch);
    return false;
  }
  if (att.voter_index >= signer_keys.size() || signer_keys[att.voter_index] == crypto::ed25519_public_key::null())
  {
    reason = "key attestation voter " + std::to_string(att.voter_index) + " is not a member of committee epoch "
             + std::to_string(att.epoch);
    return false;
  }
  // A check-in comes before any key: it names none. Anything else must name one.
  const bool checkin = att.version == BRIDGE_STANDBY_CHECKIN_VERSION;
  if (checkin ? (att.pgw_vk || att.pevm_address) : (!att.pgw_vk || !att.pevm_address))
  {
    reason = checkin ? "a standby round check-in names a key" : "key attestation names an empty key";
    return false;
  }
  const std::string msg = bridge_key_attestation_message(nettype, att);
  if (crypto_sign_verify_detached(att.signature.data, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                  signer_keys[att.voter_index].data) != 0)
  {
    reason = "key attestation signature does not verify for voter " + std::to_string(att.voter_index);
    return false;
  }
  return true;
}

std::string bridge_absence_message(network_type nettype, const tx_extra_bridge_absence& report)
{
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.append(hashkey::BRIDGE_ABSENCE);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.push_back(static_cast<char>(report.version));
  append_u64_le(buf, report.epoch);
  const auto u16 = [&](uint16_t v) {
    buf.push_back(static_cast<char>(v & 0xff));
    buf.push_back(static_cast<char>((v >> 8) & 0xff));
  };
  u16(static_cast<uint16_t>(report.absent.size()));
  for (const auto i : report.absent)
    u16(i);
  return buf;
}

bool verify_bridge_absence_report(const tx_extra_bridge_absence& report,
                                  const std::vector<crypto::ed25519_public_key>& signer_keys,
                                  size_t threshold, network_type nettype, std::string& reason)
{
  if (report.version != 0)
  {
    reason = "unknown absence report version";
    return false;
  }
  const size_t size = signer_keys.size();
  if (threshold == 0 || size < threshold)
  {
    reason = "no committee to report absence from";
    return false;
  }
  // Absent members are at most those the threshold can do without: a committee missing more
  // could not have gathered the signatures.
  if (report.absent.empty() || report.absent.size() > size - threshold)
  {
    reason = "an absence report names 1 to " + std::to_string(size - threshold) + " members, not "
             + std::to_string(report.absent.size());
    return false;
  }
  for (size_t i = 0; i < report.absent.size(); ++i)
  {
    if (report.absent[i] >= size || (i > 0 && report.absent[i] <= report.absent[i - 1]))
    {
      reason = "absent members must be distinct committee indices in ascending order";
      return false;
    }
  }
  if (report.reporters.size() < threshold)
  {
    reason = "too few reporters (" + std::to_string(report.reporters.size()) + " < " + std::to_string(threshold) + ")";
    return false;
  }
  const std::string msg = bridge_absence_message(nettype, report);
  for (size_t i = 0; i < report.reporters.size(); ++i)
  {
    const auto& r = report.reporters[i];
    if (r.voter_index >= size || (i > 0 && r.voter_index <= report.reporters[i - 1].voter_index))
    {
      reason = "reporters must be distinct committee indices in ascending order";
      return false;
    }
    if (std::binary_search(report.absent.begin(), report.absent.end(), r.voter_index))
    {
      reason = "a member reported absent cannot report";
      return false;
    }
    if (signer_keys[r.voter_index] == crypto::ed25519_public_key::null()
        || crypto_sign_verify_detached(r.signature.data, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                       signer_keys[r.voter_index].data) != 0)
    {
      reason = "absence report signature does not verify for reporter " + std::to_string(r.voter_index);
      return false;
    }
  }
  return true;
}

std::string bridge_resume_message(network_type nettype, const tx_extra_bridge_resume& resume)
{
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.append(hashkey::BRIDGE_RESUME);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.append(reinterpret_cast<const char*>(resume.master_node_pubkey.data), sizeof(resume.master_node_pubkey.data));
  append_u64_le(buf, resume.paused_height);
  return buf;
}

bool verify_bridge_resume(const tx_extra_bridge_resume& resume, const crypto::ed25519_public_key& signer_key,
                          network_type nettype, std::string& reason)
{
  if (resume.version != 0)
  {
    reason = "unknown bridge resume version";
    return false;
  }
  const std::string msg = bridge_resume_message(nettype, resume);
  if (signer_key == crypto::ed25519_public_key::null()
      || crypto_sign_verify_detached(resume.signature.data, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                     signer_key.data) != 0)
  {
    reason = "bridge resume signature does not verify under the seat's signer key";
    return false;
  }
  return true;
}

crypto::hash gateway_takeover_complete_message(network_type nettype, const crypto::public_key& gateway_id,
                                               uint64_t started_height)
{
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  append_u64_le(fields, started_height);
  return gateway_governance_message(hashkey::GW_TAKEOVER_COMPLETE, nettype, fields);
}

crypto::hash gateway_repoint_message(network_type nettype, const crypto::public_key& gateway_id,
                                     const gateway_descriptor_base& new_owner_descriptor,
                                     uint64_t governance_seq, uint64_t epoch_height)
{
  auto desc_copy = new_owner_descriptor; // dump_binary needs non-const
  const std::string desc_blob = serialization::dump_binary(desc_copy);
  std::string fields;
  fields.append(reinterpret_cast<const char*>(&gateway_id), sizeof(gateway_id));
  fields.append(desc_blob);
  append_u64_le(fields, governance_seq);
  append_u64_le(fields, epoch_height);
  return gateway_governance_message(hashkey::GW_REPOINT, nettype, fields);
}

bool verify_gateway_governance_evidence(const std::vector<gateway_governance_signature>& evidence,
                                        uint64_t epoch_height, const crypto::hash& msg,
                                        const checkpoint_quorum_resolver& resolve_quorum,
                                        std::string& reason)
{
  if (!resolve_quorum)
  {
    reason = "no governance quorum resolver available";
    return false;
  }

  std::vector<crypto::public_key> validators;
  if (!resolve_quorum(epoch_height, validators) || validators.empty())
  {
    reason = "no checkpoint quorum for the governance epoch height " + std::to_string(epoch_height);
    return false;
  }

  // Required supermajority: ceil(NUM/DEN · quorum_size), and always > half.
  const size_t quorum_size = validators.size();
  const size_t required = (quorum_size * GATEWAY_GOVERNANCE_SUPERMAJORITY_NUM
                           + GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN - 1)
                          / GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN;
  if (evidence.size() < required)
  {
    reason = "insufficient governance evidence (" + std::to_string(evidence.size()) + " < required "
             + std::to_string(required) + " of " + std::to_string(quorum_size) + ")";
    return false;
  }
  if (evidence.size() > quorum_size)
  {
    reason = "more governance signatures than quorum members";
    return false;
  }

  // Distinct, strictly-ascending voter indices (prevents double-counting a
  // signer and pins a canonical evidence ordering, mirroring checkpoint votes).
  for (size_t i = 0; i < evidence.size(); ++i)
  {
    const auto& e = evidence[i];
    if (e.voter_index >= quorum_size)
    {
      reason = "governance voter index out of range";
      return false;
    }
    if (i > 0 && evidence[i - 1].voter_index >= e.voter_index)
    {
      reason = "governance voter indices not strictly ascending";
      return false;
    }
    if (!crypto::check_signature(msg, validators[e.voter_index], e.signature))
    {
      reason = "governance signature verification failed at voter index " + std::to_string(e.voter_index);
      return false;
    }
  }
  return true;
}

std::string bridge_slash_message(network_type nettype, const tx_extra_bridge_slash& slash)
{
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.reserve(hashkey::BRIDGE_SLASH.size() + sizeof(genesis) + 1 + sizeof(slash.transcript_root) + 1 + 2 + 8 + 8);
  buf.append(hashkey::BRIDGE_SLASH);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.push_back(static_cast<char>(slash.scheme));
  buf.append(reinterpret_cast<const char*>(&slash.transcript_root), sizeof(slash.transcript_root));
  buf.push_back(static_cast<char>(slash.failing_check));
  buf.push_back(static_cast<char>(slash.accused_index & 0xff));        // u16 LE
  buf.push_back(static_cast<char>((slash.accused_index >> 8) & 0xff));
  append_u64_le(buf, slash.epoch);
  append_u64_le(buf, slash.height);
  if (slash.version >= 2)
    append_u64_le(buf, slash.round_height);
  return buf;
}

bool verify_bridge_slash_evidence(const tx_extra_bridge_slash& slash,
                                  const std::vector<crypto::ed25519_public_key>& signer_keys,
                                  size_t threshold, network_type nettype, std::string& reason)
{
  // Only version 2 names a standby round, and it must name one.
  if ((slash.version >= 2) != (slash.round_height != 0))
  {
    reason = "slash report version and standby round disagree";
    return false;
  }
  // Coarse/unattributed `Pevm` fault (failing_check == 3) is a governance freeze,
  // not a slash — never admissible slashing evidence.
  if (slash.failing_check == 3)
  {
    reason = "unattributed fault is not slashable evidence";
    return false;
  }
  if (threshold == 0)
  {
    reason = "zero slash threshold";
    return false;
  }
  if (slash.accused_index >= signer_keys.size())
  {
    reason = "accused index out of committee range";
    return false;
  }
  if (slash.accusers.size() < threshold)
  {
    reason = "insufficient slash accusers (" + std::to_string(slash.accusers.size()) + " < required "
             + std::to_string(threshold) + ")";
    return false;
  }
  if (slash.accusers.size() > signer_keys.size())
  {
    reason = "more slash accusers than committee members";
    return false;
  }

  // The exact bytes the off-chain committee signed.
  const std::string msg = bridge_slash_message(nettype, slash);

  // Distinct, strictly-ascending accuser indices (no double-count; canonical order),
  // each ed25519 signature valid over `msg` under that member's signer_ed25519.
  for (size_t i = 0; i < slash.accusers.size(); ++i)
  {
    const auto& a = slash.accusers[i];
    if (a.voter_index >= signer_keys.size())
    {
      reason = "slash accuser index out of range";
      return false;
    }
    if (i > 0 && slash.accusers[i - 1].voter_index >= a.voter_index)
    {
      reason = "slash accuser indices not strictly ascending";
      return false;
    }
    // The accused cannot vouch for its own slashing: its signature would count toward the
    // threshold that convicts it, so one fewer honest accuser would be needed.
    if (a.voter_index == slash.accused_index)
    {
      reason = "the accused cannot be among its own accusers";
      return false;
    }
    if (crypto_sign_verify_detached(a.signature.data,
                                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                    signer_keys[a.voter_index].data) != 0)
    {
      reason = "slash signature verification failed at accuser index " + std::to_string(a.voter_index);
      return false;
    }
  }
  return true;
}

std::string bridge_rotation_ack_message(network_type nettype, const tx_extra_bridge_rotation_ack& ack)
{
  const crypto::hash& genesis = gateway_chain_binding(nettype);
  std::string buf;
  buf.reserve(hashkey::BRIDGE_ROTATION_ACK.size() + sizeof(genesis) + 1 + 8 + 20 + 8 + 20 + 32 + 4);
  buf.append(hashkey::BRIDGE_ROTATION_ACK);
  buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
  buf.push_back(static_cast<char>(tx_extra_bridge_rotation_ack::CURRENT_VERSION)); // whichever committee observed it
  append_u64_le(buf, ack.chain_id);
  buf.append(reinterpret_cast<const char*>(ack.contract.data()), ack.contract.size());
  append_u64_le(buf, ack.key_epoch);
  buf.append(reinterpret_cast<const char*>(ack.new_signer.data()), ack.new_signer.size());
  buf.append(reinterpret_cast<const char*>(ack.evm_txid.data), sizeof(ack.evm_txid.data));
  for (int i = 0; i < 4; ++i)
    buf.push_back(static_cast<char>((ack.log_index >> (8 * i)) & 0xff));
  return buf;
}

bool verify_bridge_rotation_evidence(const tx_extra_bridge_rotation_ack& ack,
                                     const std::vector<crypto::ed25519_public_key>& signer_keys,
                                     size_t threshold, network_type nettype, std::string& reason)
{
  // Only the current layout: an older ack signed less (no contract, no log), and an
  // unknown one cannot be interpreted.
  if (ack.version != tx_extra_bridge_rotation_ack::CURRENT_VERSION && ack.version != tx_extra_bridge_rotation_ack::ROUND_VERSION)
  {
    reason = "rotation ack: unsupported version " + std::to_string(ack.version);
    return false;
  }
  if ((ack.version == tx_extra_bridge_rotation_ack::ROUND_VERSION) != (ack.round_height != 0))
  {
    reason = "rotation ack: version and standby round disagree";
    return false;
  }
  // The addresses are appended raw to the signed bytes, so a wrong length would silently
  // change the message.
  if (ack.new_signer.size() != 20)
  {
    reason = "rotation ack: new_signer must be exactly 20 bytes";
    return false;
  }
  if (ack.contract.size() != 20)
  {
    reason = "rotation ack: contract must be exactly 20 bytes";
    return false;
  }
  // The gateway's slot is not a wBDX chain. Consensus applies the gateway's owner changes
  // itself and counts them there; no committee's word may move that count, or a bond
  // waiting on the gateway hand-over could be released by attestation alone.
  if (ack.chain_id == BRIDGE_GATEWAY_CHAIN_ID)
  {
    reason = "rotation ack: chain id 0 is the native gateway, which consensus observes itself";
    return false;
  }
  if (threshold == 0)
  {
    reason = "zero rotation threshold";
    return false;
  }
  if (ack.observers.size() < threshold)
  {
    reason = "insufficient rotation observers (" + std::to_string(ack.observers.size()) + " < required "
             + std::to_string(threshold) + ")";
    return false;
  }
  if (ack.observers.size() > signer_keys.size())
  {
    reason = "more rotation observers than committee members";
    return false;
  }

  // The exact bytes the off-chain committee signed.
  const std::string msg = bridge_rotation_ack_message(nettype, ack);

  // Distinct, strictly-ascending observer indices (no double-count; canonical order),
  // each ed25519 signature valid over `msg` under that member's signer_ed25519.
  for (size_t i = 0; i < ack.observers.size(); ++i)
  {
    const auto& o = ack.observers[i];
    if (o.voter_index >= signer_keys.size())
    {
      reason = "rotation observer index out of range";
      return false;
    }
    if (i > 0 && ack.observers[i - 1].voter_index >= o.voter_index)
    {
      reason = "rotation observer indices not strictly ascending";
      return false;
    }
    if (crypto_sign_verify_detached(o.signature.data,
                                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                    signer_keys[o.voter_index].data) != 0)
    {
      reason = "rotation signature verification failed at observer index " + std::to_string(o.voter_index);
      return false;
    }
  }
  return true;
}

bool verify_gateway_release_unlocks(const transaction& tx, std::string& reason)
{
  const bool unlocked =
      tx.version == txversion::v4_tx_types && tx.type == txtype::standard &&
      !tx.vout.empty() && tx.unlock_time == 0 &&
      tx.output_unlock_times.size() == tx.vout.size() &&
      std::all_of(tx.output_unlock_times.begin(), tx.output_unlock_times.end(),
                  [](uint64_t t) { return t == 0; });
  if (!unlocked)
    reason = "a bridge release must be a standard v4 tx whose outputs are all unlocked";
  return unlocked;
}

bool verify_gateway_release_tx_key(const transaction& tx, const crypto::secret_key& tx_key,
                                   std::string& reason)
{
  // secret_key_to_public_key refuses a non-canonical scalar. Zero is canonical but makes
  // the "secret" public, so it is refused here.
  crypto::public_key derived{};
  if (tx_key == crypto::null_skey || !crypto::secret_key_to_public_key(tx_key, derived))
  {
    reason = "invalid disclosed release tx secret key";
    return false;
  }
  std::vector<tx_extra_field> fields;
  if (!parse_tx_extra(tx.extra, fields))
  {
    reason = "malformed release tx extra";
    return false;
  }
  size_t pub_keys = 0;
  for (const auto& f : fields)
  {
    if (const auto* k = std::get_if<tx_extra_pub_key>(&f))
    {
      if (++pub_keys > 1 || k->pub_key != derived)
      {
        reason = "release tx public key is ambiguous or not the disclosed key's";
        return false;
      }
    }
    else if (std::holds_alternative<tx_extra_additional_pub_keys>(f))
    {
      reason = "release tx carries additional public keys";
      return false;
    }
  }
  if (pub_keys != 1)
  {
    reason = "release tx has no public key";
    return false;
  }
  return true;
}

bool summarize_gateway_withdraw(network_type nettype, const transaction& tx,
                                gateway_withdraw_summary& out, std::string& reason)
{
  out = {};

  // Exactly one gateway input (single source), native asset only at HF22.
  const txin_gateway* gin = nullptr;
  for (const auto& in : tx.vin)
  {
    if (const auto* g = std::get_if<txin_gateway>(&in))
    {
      if (gin) { reason = "withdrawal has more than one gateway input"; return false; }
      gin = g;
    }
    else
    {
      reason = "withdrawal mixes non-gateway inputs";
      return false;
    }
  }
  if (!gin) { reason = "tx is not a gateway withdrawal (no gateway input)"; return false; }
  if (gin->asset_id != crypto::null_aid) { reason = "gateway input asset must be native at HF22"; return false; }

  out.source_gateway_id = gin->gateway_addr;
  out.total_debit       = gin->amount;

  // Classify by output type. All outputs must be one kind.
  uint64_t gw_out_sum = 0;
  size_t gw_outs = 0, other_outs = 0;
  for (const auto& o : tx.vout)
  {
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
    {
      ++gw_outs;
      if (gw_out_sum > std::numeric_limits<uint64_t>::max() - g->amount)
      { reason = "gateway output sum overflow"; return false; }
      gw_out_sum += g->amount;
      out.gateway_dests.emplace_back(g->gateway_addr, g->amount);
    }
    else
    {
      ++other_outs;
    }
  }
  if (gw_outs && other_outs) { reason = "withdrawal mixes gateway and stealth outputs"; return false; }

  out.to_wallet = other_outs > 0;
  if (out.to_wallet)
  {
    // Stealth outputs: amounts are hidden. Fee is the declared RCT fee; the
    // balance proof (checked in consensus) guarantees Σ outputs == debit − fee.
    out.fee = tx.rct_signatures.txnFee;
  }
  else
  {
    // Transparent gateway outputs: fee is the visible remainder.
    if (out.total_debit < gw_out_sum) { reason = "gateway outputs exceed the debit"; return false; }
    out.fee = out.total_debit - gw_out_sum;
  }

  out.hash_to_sign = gateway_input_message(nettype, tx);
  return true;
}

bool tx_has_gateway_constructs(const transaction& tx)
{
  if (tx.has_gateway_inputs())
    return true;
  for (const auto& o : tx.vout)
    if (std::holds_alternative<tx_out_gateway>(o.target))
      return true;
  tx_extra_gateway_descriptor_operation op{};
  if (get_field_from_tx_extra(tx.extra, op, 0))
    return true;
  tx_extra_gateway_bridge_memo memo{};
  return get_field_from_tx_extra(tx.extra, memo, 0);
}

crypto::hash gateway_balance_message(network_type nettype, const transaction& tx)
{
  // Domain-separated, chain-bound message both balance-proof Schnorr legs sign.
  // The proof itself is prunable (lives in gateway_proofs) so hashing the
  // prefix is not circular.
  return gateway_message(hashkey::GW_BALANCE, nettype, tx);
}

const gateway_balance_proof* get_gateway_balance_proof(const transaction& tx)
{
  for (const auto& p : tx.gateway_proofs)
    if (const auto* bp = std::get_if<gateway_balance_proof>(&p))
      return bp;
  return nullptr;
}

bool verify_gateway_balance_proof(network_type nettype, const transaction& tx,
                                  const gateway_balance_proof& proof, std::string& reason)
{
  if (proof.version != 0)
  {
    reason = "unsupported gateway balance proof version";
    return false;
  }
  crypto::public_key tx_pub = get_tx_pub_key_from_extra(tx);
  if (tx_pub == crypto::null_pkey)
  {
    reason = "gateway balance proof requires a tx public key in extra";
    return false;
  }
  const crypto::hash msg = gateway_balance_message(nettype, tx);
  // Leg 1: mask_point = s·G for known s (Σ output commitment masks). Proving a
  // DL wrt G pins the residual to the G generator: no hidden H component, so
  // the transparent gateway amounts cannot be inflated. check_signature
  // enforces canonical scalars (non-malleable) and rejects bad encodings.
  if (!crypto::check_signature(msg, proof.mask_point, proof.mask_sig))
  {
    reason = "gateway balance proof: mask point signature invalid";
    return false;
  }
  // Leg 2: knowledge of the tx secret key. Welds the proof to this tx's DH
  // outputs so it cannot be produced by anyone but the tx author.
  if (!crypto::check_signature(msg, tx_pub, proof.txkey_sig))
  {
    reason = "gateway balance proof: tx key signature invalid";
    return false;
  }
  return true;
}

bool generate_gateway_balance_proof(network_type nettype, const transaction& tx,
                                    const crypto::secret_key& mask_sum,
                                    const crypto::secret_key& tx_key,
                                    gateway_balance_proof& proof)
{
  proof = {};
  crypto::public_key tx_pub{};
  if (!crypto::secret_key_to_public_key(mask_sum, proof.mask_point) ||
      !crypto::secret_key_to_public_key(tx_key, tx_pub))
    return false;
  const crypto::hash msg = gateway_balance_message(nettype, tx);
  crypto::generate_signature(msg, proof.mask_point, mask_sum, proof.mask_sig);
  crypto::generate_signature(msg, tx_pub, tx_key, proof.txkey_sig);
  return true;
}

bool verify_gateway_wallet_balance(const transaction& tx, std::string& reason)
{
  // Authoritative connection-time check for a gateway→wallet withdrawal, run from
  // check_tx_inputs. It must be SELF-CONTAINED: a gateway-only withdrawal has no
  // pseudo-outs to absorb the derived output masks, so without range proofs an
  // attacker could set one stealth output near 2^64 (a "negative" amount) and,
  // balancing it against another, mint coins. Relying on the batched
  // verRctSemanticsSimple elsewhere is fragile — a future refactor that reaches
  // block-connect without that batch would silently reopen the vector. So verify
  // the range proofs here too, alongside the balance equation:
  //   Σ outPk.mask + fee·H − Σ gw_in·H − mask_point  ==  0   (== Σ pseudoOuts)
  // with mask_point separately proven to lie in <G> by verify_gateway_balance_proof
  // (so the residual cannot hide an amount/H component).
  const rct::rctSig& rv = tx.rct_signatures;
  if (rv.outPk.empty())
  {
    reason = "gateway->wallet withdrawal has no confidential outputs";
    return false;
  }
  // Reject any type without per-output range proofs (e.g. RCTType::Null): the
  // stealth outputs MUST carry BulletproofPlus proofs covering every output.
  if (!rct::is_rct_bulletproof_plus(rv.type))
  {
    reason = "gateway->wallet withdrawal must use BulletproofPlus range proofs";
    return false;
  }
  if (rv.outPk.size() != rct::n_bulletproof_plus_amounts(rv.p.bulletproofs_plus))
  {
    reason = "gateway->wallet withdrawal range proofs do not cover every output";
    return false;
  }
  // verRctSemanticsSimple verifies the BP+ range proofs AND the balance equation
  // in one audited call. For a gateway-only withdrawal pseudoOuts is empty, so its
  // sum(pseudoOuts) == sum(outPk) + fee·H + offset check reduces to the equation
  // above. The gateway offset folds in −Σgw_in·H − mask_point.
  const rct::key offset = gateway_balance_offset(tx);
  if (!rct::verRctSemanticsSimple(rv, &offset))
  {
    reason = "gateway->wallet withdrawal balance/range-proof check failed";
    return false;
  }
  return true;
}

rct::key gateway_balance_offset(const transaction& tx)
{
  // Σ gw_out·H − Σ gw_in·H − mask_point. Generator taken from asset_id
  // (null_aid → H) so the post-CA relaxation (a·H_asset) is a lookup change,
  // not a rewrite. HF22 rejects non-null asset ids, so H is always used here
  // for now. mask_point (present only on gw→wallet withdrawals, enforced in
  // validate_gateway_withdrawals) absorbs the derived output-commitment masks:
  // the RCT sum check then closes iff Σ b_i + fee == Σ gw_in and the proof
  // separately guarantees mask_point has no H component.
  rct::key offset = rct::identity();
  for (const auto& o : tx.vout)
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      rct::addKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
      rct::subKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  if (const auto* bp = get_gateway_balance_proof(tx))
    rct::subKeys(offset, offset, rct::pk2rct(bp->mask_point));
  return offset;
}

bool verify_pure_gateway_balance(const transaction& tx, uint64_t& fee, std::string& reason)
{
  // Pure-gateway tx: only gateway in/out, no RCT. Σgw_in == Σgw_out + fee.
  uint64_t in_sum = 0, out_sum = 0;
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
    {
      if (in_sum > std::numeric_limits<uint64_t>::max() - g->amount) { reason = "gateway input sum overflow"; return false; }
      in_sum += g->amount;
    }
  for (const auto& o : tx.vout)
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
    {
      if (out_sum > std::numeric_limits<uint64_t>::max() - g->amount) { reason = "gateway output sum overflow"; return false; }
      out_sum += g->amount;
    }
  if (in_sum < out_sum)
  {
    reason = "pure-gateway tx outputs exceed inputs";
    return false;
  }
  fee = in_sum - out_sum;
  return true;
}

bool load_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, gateway_account_data& acct)
{
  acct = {};
  std::string blob;
  if (!db.get_gateway_account(gateway_addr, blob))
    return false;
  serialization::parse_binary(blob, acct);
  return true;
}

void store_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, const gateway_account_data& acct)
{
  auto copy = acct; // dump_binary needs non-const
  db.set_gateway_account(gateway_addr, serialization::dump_binary(copy));
}

bool is_valid_gateway_owner_key(const gateway_owner_key_v& owner_key)
{
  // Native ed25519 owner key: require prime-order main-subgroup membership (not
  // just a decodable point), so a torsion/small-order key cannot create Schnorr
  // signature ambiguities. eth (secp256k1, cofactor 1) and eddsa (libsodium
  // is_valid_point already enforces the main subgroup) need no extra check.
  if (const auto* pk = std::get_if<crypto::public_key>(&owner_key))
    return crypto::check_key_in_main_subgroup(*pk);
  if (const auto* pk = std::get_if<crypto::eth_public_key>(&owner_key))
    return crypto::check_eth_public_key(*pk);
  if (const auto* pk = std::get_if<crypto::eddsa_public_key>(&owner_key))
    return crypto::check_eddsa_public_key(*pk);
  return false;
}

bool verify_gateway_owner_signature(const gateway_owner_key_v& owner_key,
                                    const gateway_owner_sig_v& sig,
                                    const crypto::hash& msg)
{
  if (const auto* pk = std::get_if<crypto::public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::signature>(&sig);
    return s && crypto::check_signature(msg, *pk, *s);
  }
  if (const auto* pk = std::get_if<crypto::eth_public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::eth_signature>(&sig);
    return s && crypto::verify_eth_signature(msg, *pk, *s);
  }
  if (const auto* pk = std::get_if<crypto::eddsa_public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::eddsa_signature>(&sig);
    return s && crypto::verify_eddsa_signature(msg, *pk, *s);
  }
  return false;
}

crypto::hash gateway_ownership_message(network_type nettype, const transaction& tx)
{
  // Chain-bound for the same reason as gateway_input_message: an owner-change
  // proof has no key image and must not be replayable across chains.
  return gateway_message(hashkey::GW_OWNERSHIP, nettype, tx);
}

bool validate_gateway_descriptor_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                           const tx_extra_gateway_descriptor_operation& op,
                                           hf hf_version, std::string& reason)
{
  if (!is_valid_gateway_owner_key(op.descriptor.owner_key))
  {
    reason = "gateway descriptor has an invalid owner key";
    return false;
  }
  // Bound the DB-persisted, append-only descriptor metadata (both register and
  // update). Prevents cheap consensus-state bloat via oversized meta_info.
  if (op.descriptor.meta_info.size() > GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE)
  {
    reason = "gateway descriptor meta_info exceeds " +
             std::to_string(GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE) + " bytes";
    return false;
  }
  // Reject unknown descriptor versions: v0 at HF22, v1 (adds `flags`) and v2 (adds a
  // standby owner) from HF23. Future formats must be gated by a future hard fork.
  if (op.descriptor.version > (hf_version >= feature::BRIDGE ? 2 : 0))
  {
    reason = "unsupported gateway descriptor version";
    return false;
  }
  // A v0 descriptor has no flags field; a v1 one must only set known bits, so an
  // unknown bit can never be interpreted as meaning-carrying by a future release.
  if (op.descriptor.version == 0 && op.descriptor.flags != 0)
  {
    reason = "gateway descriptor v0 must not carry flags";
    return false;
  }
  if (op.descriptor.flags & ~static_cast<uint8_t>(GATEWAY_FLAG_BRIDGE_RESERVE))
  {
    reason = "gateway descriptor sets unknown flag bits";
    return false;
  }
  if (op.descriptor.has_standby)
  {
    if (op.descriptor.has_standby != 1 || !is_valid_gateway_owner_key(op.descriptor.standby_owner))
    {
      reason = "gateway descriptor has an invalid standby owner";
      return false;
    }
    if (op.descriptor.standby_owner == op.descriptor.owner_key)
    {
      reason = "a gateway's standby owner must differ from its owner";
      return false;
    }
  }

  switch (op.op_type)
  {
    case gateway_descriptor_op_type::register_address:
    {
      if (tx.type != txtype::register_gateway_address)
      {
        reason = "register gateway op in a tx whose type is not register_gateway_address";
        return false;
      }
      // The gateway address id doubles as the on-chain identity and the DH key
      // for payment-id decryption, so require canonical main-subgroup membership.
      if (!crypto::check_key_in_main_subgroup(op.address_id))
      {
        reason = "gateway address id is not a canonical main-subgroup public key";
        return false;
      }
      if (db.gateway_exists(op.address_id))
      {
        reason = "gateway address already registered";
        return false;
      }
      const uint64_t burned = get_burned_amount_from_tx_extra(tx.extra);
      if (burned < GATEWAY_ADDRESS_REGISTRATION_FEE)
      {
        reason = "insufficient burned registration fee (" + std::to_string(burned) + " < " +
                 std::to_string(GATEWAY_ADDRESS_REGISTRATION_FEE) + ")";
        return false;
      }


      // Proof-of-ownership of the gateway id (F2). The registrant must sign the
      // register with address_id's OWN secret key. Without this, anyone could
      // squat/front-run a gateway id they do not control, set themselves as
      // owner, and later drain deposits made to it. The signature is over the tx
      // prefix hash (which covers address_id + the chosen owner_key + meta), so a
      // captured proof cannot be replayed onto a different registration. See
      // docs/GATEWAY_SECURITY_FIXES.md (F2).
      const gateway_ownership_proof* reg_proof = nullptr;
      for (const auto& p : tx.gateway_proofs)
      {
        if (const auto* rp = std::get_if<gateway_ownership_proof>(&p))
        {
          if (reg_proof)
          {
            reason = "register tx carries more than one ownership proof";
            return false;
          }
          reg_proof = rp;
        }
      }
      if (!reg_proof)
      {
        reason = "register tx is missing its gateway-id ownership proof";
        return false;
      }
      {
        // address_id is a native ed25519 key, so the proof must be the native
        // Schnorr variant; verify_gateway_owner_signature enforces the match.
        const crypto::hash msg = gateway_ownership_message(nettype, tx);
        if (!verify_gateway_owner_signature(gateway_owner_key_v{op.address_id}, reg_proof->sig, msg))
        {
          reason = "gateway-id ownership proof verification failed";
          return false;
        }
      }

      // The declared burn must be genuinely realized. Burning is applied by
      // reducing the miner-claimable fee (get_tx_miner_fee: fee -= min(fee, burned)),
      // so a burn exceeding the tx fee is NOT actually removed from supply — only
      // min(fee, burned) is. Without this upper bound a miner could self-include a
      // register tx declaring burn == REGISTRATION_FEE while paying a negligible real
      // fee (the pool min-fee check is bypassed for txs mined directly into a block),
      // registering a gateway for almost free and defeating the anti-spam cost.
      // Mirror the coin_burn rule (blockchain.cpp: burn <= fee).
      const uint64_t tx_fee = tx.rct_signatures.txnFee;
      if (burned > tx_fee)
      {
        reason = "gateway registration burn (" + std::to_string(burned) +
                 ") exceeds tx fee (" + std::to_string(tx_fee) + "); burn is not realized";
        return false;
      }
      return true;
    }

    case gateway_descriptor_op_type::update_address:
    {
      if (tx.type != txtype::update_gateway_address)
      {
        reason = "update gateway op in a tx whose type is not update_gateway_address";
        return false;
      }
      gateway_account_data acct;
      if (!load_gateway_account(db, op.address_id, acct) || acct.descriptor_history.empty())
      {
        reason = "update for an unknown gateway address";
        return false;
      }

      // HF23 circuit breaker: a frozen gateway rejects owner-signed updates too
      // (S8) — otherwise a compromised owner could rotate the key out from under
      // a freeze. Re-point (governance) is the only way to change a frozen
      // gateway's owner.
      if (acct.frozen)
      {
        reason = "gateway is frozen; owner update rejected";
        return false;
      }

      const gateway_ownership_proof* proof = nullptr;
      for (const auto& p : tx.gateway_proofs)
      {
        if (const auto* op_proof = std::get_if<gateway_ownership_proof>(&p))
        {
          if (proof)
          {
            reason = "update tx carries more than one ownership proof";
            return false;
          }
          proof = op_proof;
        }
      }
      if (!proof)
      {
        reason = "update tx is missing its ownership proof";
        return false;
      }

      // A standby takeover step is signed by the standby owner; every other update by the
      // owner (and, while a takeover is running, cancels it).
      const gateway_descriptor_base& current = acct.latest_descriptor();
      const tx_extra_gateway_takeover* takeover = nullptr;
      const auto takeovers = extract_gateway_takeovers(tx);
      for (const auto& t : takeovers)
      {
        if (t.gateway_id != op.address_id || takeovers.size() > 1)
        {
          reason = "a takeover marker must name the updated gateway, once";
          return false;
        }
        takeover = &t;
      }
      const crypto::hash msg = gateway_ownership_message(nettype, tx);
      if (!takeover)
      {
        if (!verify_gateway_owner_signature(current.owner_key, proof->sig, msg))
        {
          reason = "gateway ownership proof verification failed";
          return false;
        }
      }
      else
      {
        if (hf_version < feature::BRIDGE || !current.has_standby)
        {
          reason = "gateway has no standby owner to take it over";
          return false;
        }
        if (!verify_gateway_owner_signature(current.standby_owner, proof->sig, msg))
        {
          reason = "takeover proof is not signed by the gateway's standby owner";
          return false;
        }
        const uint64_t started = acct.takeover_started_height();
        const uint64_t height  = db.height();
        if (takeover->action == gateway_takeover_action::begin)
        {
          if (started != 0)
          {
            reason = "a takeover of this gateway is already running";
            return false;
          }
          if (!same_descriptor(op.descriptor, current))
          {
            reason = "a takeover begin must leave the descriptor unchanged";
            return false;
          }
          // One delay after a takeover ended, so the standby cannot begin on every block
          // and make the owner sign a cancel each time.
          const uint64_t ended = acct.takeover_ended_height();
          if (ended != 0 && height < ended + gateway_standby_takeover_blocks(nettype))
          {
            reason = "takeover cooling down: " + std::to_string(ended + gateway_standby_takeover_blocks(nettype) - height)
                     + " more block(s)";
            return false;
          }
        }
        else
        {
          const uint64_t wait = gateway_standby_takeover_blocks(nettype);
          if (started == 0)
          {
            reason = "no takeover of this gateway has begun";
            return false;
          }
          if (height < started + wait)
          {
            reason = "takeover not ready: " + std::to_string(started + wait - height) + " more block(s)";
            return false;
          }
          if (!same_descriptor(op.descriptor, taken_over_descriptor(current)))
          {
            reason = "a takeover must make the standby the owner and change nothing else";
            return false;
          }
        }
      }

      if (!standby_is_fresh(acct, op.descriptor, reason))
        return false;

      // The BRIDGE_RESERVE flag is STICKY (HF23): an update may set it but never
      // clear it. Otherwise the mandatory-release-ref rule (§3.6) would be trivially
      // bypassable — clear the flag, withdraw without a ref, set it back.
      if (acct.latest_descriptor().is_bridge_reserve() && !op.descriptor.is_bridge_reserve())
      {
        reason = "gateway bridge-reserve flag cannot be cleared by an update";
        return false;
      }
      return true;
    }

    default:
      reason = "unknown gateway descriptor operation type";
      return false;
  }
}

bool validate_gateway_freeze_operation(BlockchainDB& db, network_type nettype, const transaction& /*tx*/,
                                       const tx_extra_gateway_freeze& op,
                                       const checkpoint_quorum_resolver& resolve_quorum, std::string& reason)
{
  gateway_account_data acct;
  if (!load_gateway_account(db, op.gateway_id, acct) || acct.descriptor_history.empty())
  {
    reason = "freeze op targets an unknown gateway";
    return false;
  }
  if ((op.freeze != 0) == (acct.frozen != 0))
  {
    reason = op.freeze ? "gateway is already frozen" : "gateway is not frozen";
    return false;
  }
  if (op.governance_seq != acct.governance_seq)
  {
    reason = "stale governance nonce on freeze (expected " + std::to_string(acct.governance_seq)
             + ", got " + std::to_string(op.governance_seq) + ")";
    return false;
  }
  if (!governance_height_is_recent(db, nettype, op.epoch_height, reason))
    return false;
  const crypto::hash msg = gateway_freeze_message(nettype, op.gateway_id, op.freeze != 0,
                                                  op.governance_seq, op.epoch_height);
  if (!verify_gateway_governance_evidence(op.evidence, op.epoch_height, msg, resolve_quorum, reason))
    return false;
  return true;
}

bool governance_height_is_recent(BlockchainDB& db, network_type nettype, uint64_t epoch_height, std::string& reason)
{
  const uint64_t height = db.height();
  const uint64_t max_age = gateway_governance_max_age_blocks(nettype);
  if (epoch_height >= height || epoch_height + max_age < height)
  {
    reason = "governance quorum height " + std::to_string(epoch_height) + " is not a recent block (the chain is at "
             + std::to_string(height) + "; at most " + std::to_string(max_age) + " blocks back)";
    return false;
  }
  return true;
}

bool validate_gateway_repoint_operation(BlockchainDB& db, network_type nettype, const transaction& /*tx*/,
                                        const tx_extra_gateway_repoint& op,
                                        const checkpoint_quorum_resolver& resolve_quorum, std::string& reason)
{
  gateway_account_data acct;
  if (!load_gateway_account(db, op.gateway_id, acct) || acct.descriptor_history.empty())
  {
    reason = "repoint op targets an unknown gateway";
    return false;
  }
  if (!is_valid_gateway_owner_key(op.new_owner_descriptor.owner_key))
  {
    reason = "repoint new owner descriptor has an invalid owner key";
    return false;
  }
  if (op.new_owner_descriptor.has_standby &&
      (op.new_owner_descriptor.has_standby != 1 ||
       !is_valid_gateway_owner_key(op.new_owner_descriptor.standby_owner) ||
       op.new_owner_descriptor.standby_owner == op.new_owner_descriptor.owner_key))
  {
    reason = "repoint new owner descriptor has an invalid standby owner";
    return false;
  }
  if (!standby_is_fresh(acct, op.new_owner_descriptor, reason))
    return false;
  // The bridge-reserve flag is sticky for governance too: a re-point dropping it would turn
  // off the rule that every release from the reserve names the burn it pays out.
  if (acct.latest_descriptor().is_bridge_reserve() && !op.new_owner_descriptor.is_bridge_reserve())
  {
    reason = "gateway bridge-reserve flag cannot be cleared by a repoint";
    return false;
  }
  if (op.governance_seq != acct.governance_seq)
  {
    reason = "stale governance nonce on repoint (expected " + std::to_string(acct.governance_seq)
             + ", got " + std::to_string(op.governance_seq) + ")";
    return false;
  }
  if (!governance_height_is_recent(db, nettype, op.epoch_height, reason))
    return false;
  const crypto::hash msg = gateway_repoint_message(nettype, op.gateway_id, op.new_owner_descriptor,
                                                   op.governance_seq, op.epoch_height);
  if (!verify_gateway_governance_evidence(op.evidence, op.epoch_height, msg, resolve_quorum, reason))
    return false;
  return true;
}

namespace
{
  // Validate deposit outputs (tx_out_gateway).
  bool validate_gateway_deposits(BlockchainDB& db, const transaction& tx, hf hf_version, std::string& reason)
  {
    for (const auto& o : tx.vout)
    {
      const auto* g = std::get_if<tx_out_gateway>(&o.target);
      if (!g)
        continue;

      if (g->version != 0)
      {
        reason = "unsupported gateway output version";
        return false;
      }

      // HF22: native BDX only.
      if (hf_version < feature::GATEWAY_ADDRESSES && g->asset_id != crypto::null_aid)
      {
        reason = "gateway output with non-native asset id before CA";
        return false;
      }
      if (g->asset_id != crypto::null_aid)
      {
        reason = "gateway output asset_id must be null_aid at HF22";
        return false;
      }
      // Stricter than Zano: amount must be strictly positive and in range.
      if (g->amount == 0 || g->amount >= beldex::MONEY_SUPPLY)
      {
        reason = "gateway output amount out of range";
        return false;
      }
      if (!db.gateway_exists(g->gateway_addr))
      {
        reason = "gateway output targets an unregistered gateway";
        return false;
      }
    }
    return true;
  }

  // Validate withdrawal inputs (txin_gateway): asset id and the order-matched
  // owner signature over H(GW_INPUT_SIG||prefix_hash) against the LATEST owner
  // key. Balance sufficiency is NOT checked here: this runs during block
  // validation against pre-block DB state, so a same-block deposit→withdraw must
  // not be rejected. The authoritative underflow check happens in append (which
  // processes the block in order); the tx-pool tracker guards pool entry.
  bool validate_gateway_withdrawals(BlockchainDB& db, network_type nettype, const transaction& tx, hf hf_version, std::string& reason)
  {
    const auto sigs = input_sigs(tx);
    const crypto::hash msg = gateway_input_message(nettype, tx);

    std::unordered_map<crypto::public_key, gateway_account_data> acct_cache;

    // Withdrawal structure rules (Zano parity: "gateway-originated txs contain
    // only gateway inputs"): a tx with any txin_gateway must have NO native
    // ring inputs — mixing would let the pseudo-out masks and the balance
    // proof interact in unanalyzed ways, and no legitimate flow needs it (the
    // gateway owner holds no UTXOs).
    size_t gw_ins = 0, native_ins = 0, non_gw_outs = 0;
    for (const auto& in : tx.vin)
    {
      if (std::holds_alternative<txin_gateway>(in)) ++gw_ins;
      else if (std::holds_alternative<txin_to_key>(in)) ++native_ins;
    }
    for (const auto& o : tx.vout)
      if (!std::holds_alternative<tx_out_gateway>(o.target))
        ++non_gw_outs;
    if (gw_ins > 0 && native_ins > 0)
    {
      reason = "mixing native ring inputs and gateway inputs is not allowed";
      return false;
    }

    // Canonical proof-container layout. The proof vector is covered by no
    // signature (the owner signs the tx PREFIX, and gateway_proofs is not part
    // of the prefix), so its encoding must be pinned exactly. Any spare degree
    // of freedom here — a permuted order, or a surplus element that no rule
    // counts — is a second, equally valid encoding of the same authorization,
    // and therefore a second transaction with a different tx id. Since a
    // txin_gateway has no key image, tx-id uniqueness is the ONLY replay guard,
    // so such a variant is a replayable withdrawal that debits the gateway
    // again; repeated with fresh padding it drains the account outright.
    //
    // Exact size + fixed position for every element, and reject anything else.
    // Canonical order (matches construct_gateway_withdraw{,_to_wallet}_tx and
    // finalize_gateway_withdraw_tx):
    //   [ownership_proof]? [balance_proof]? [input_sig × gw_ins]
    {
      // Every gateway_input_sig signs the SAME tx-wide message
      // (gateway_input_message carries no per-input index), so the positional
      // check below pins each slot's TYPE but not its CONTENT. With two or more
      // gateway inputs resolving to the same owner key, an external signer that
      // emits byte-distinct signatures per slot (Schnorr nonces are random)
      // would let a third party permute the slots: both still verify, but the
      // tx id changes -- a replayable withdrawal. GATEWAY_TX_MAX_INPUTS == 1
      // (enforced below in this file) makes that unreachable today.
      static_assert(GATEWAY_TX_MAX_INPUTS == 1,
          "raising GATEWAY_TX_MAX_INPUTS requires binding the input index into "
          "gateway_input_message and verifying sigs[i] against input i, or the "
          "input signatures become permutable between slots");

      const bool is_descriptor_tx = tx.type == txtype::register_gateway_address
                                 || tx.type == txtype::update_gateway_address;
      const bool balance_required = gw_ins > 0 && non_gw_outs > 0;
      const size_t expected = (is_descriptor_tx ? 1u : 0u) + (balance_required ? 1u : 0u) + gw_ins;

      if (tx.gateway_proofs.size() != expected)
      {
        reason = "gateway proof count mismatch (expected " + std::to_string(expected) +
                 ", got " + std::to_string(tx.gateway_proofs.size()) + ")";
        return false;
      }

      size_t i = 0;
      if (is_descriptor_tx && !std::holds_alternative<gateway_ownership_proof>(tx.gateway_proofs[i++]))
      {
        reason = "gateway proofs: expected the ownership proof at position 0";
        return false;
      }
      if (balance_required && !std::holds_alternative<gateway_balance_proof>(tx.gateway_proofs[i++]))
      {
        reason = "gateway proofs: expected the balance proof at position " + std::to_string(i - 1);
        return false;
      }
      for (; i < tx.gateway_proofs.size(); ++i)
      {
        if (!std::holds_alternative<gateway_input_sig>(tx.gateway_proofs[i]))
        {
          reason = "gateway proofs: expected an input signature at position " + std::to_string(i);
          return false;
        }
      }
    }

    // Balance proof presence: REQUIRED for gw→wallet withdrawals (gateway
    // inputs paying confidential stealth outputs — no pseudo-outs exist, so
    // the derived output masks leave a (Σmask)·G residual that must be proven
    // to carry no hidden H component). FORBIDDEN everywhere else: deposits and
    // native txs balance via pseudo-out mask absorption, and pure-gateway txs
    // have an exactly-zero residual — a stray proof there would let its
    // mask_point skew the sum check.
    {
      size_t balance_proofs = 0;
      for (const auto& p : tx.gateway_proofs)
        if (std::holds_alternative<gateway_balance_proof>(p))
          ++balance_proofs;
      const bool required = gw_ins > 0 && non_gw_outs > 0;
      if (required && balance_proofs != 1)
      {
        reason = "gateway->wallet withdrawal requires exactly one gateway balance proof";
        return false;
      }
      if (!required && balance_proofs != 0)
      {
        reason = "gateway balance proof present in a tx that must not carry one";
        return false;
      }
      if (balance_proofs == 1)
      {
        if (!verify_gateway_balance_proof(nettype, tx, *get_gateway_balance_proof(tx), reason))
          return false;
        // Enforce the amount balance at connection time too (see helper).
        if (!verify_gateway_wallet_balance(tx, reason))
          return false;
      }
    }

    size_t gw_in_index = 0;
    for (const auto& in : tx.vin)
    {
      const auto* g = std::get_if<txin_gateway>(&in);
      if (!g)
        continue;

      if (g->version != 0)
      {
        reason = "unsupported gateway input version";
        return false;
      }

      if (g->asset_id != crypto::null_aid)
      {
        reason = "gateway input asset_id must be null_aid at HF22";
        return false;
      }

      auto [it, inserted] = acct_cache.try_emplace(g->gateway_addr);
      if (inserted && (!load_gateway_account(db, g->gateway_addr, it->second) || it->second.descriptor_history.empty()))
      {
        reason = "gateway input spends from an unregistered gateway";
        return false;
      }

      // HF23 circuit breaker (S8): a frozen gateway rejects ALL withdrawals,
      // even with a valid owner signature. Checked before signature verification
      // so a frozen state is fail-closed regardless of the (possibly stolen) key.
      if (it->second.frozen)
      {
        reason = "gateway is frozen; withdrawal rejected";
        return false;
      }

      if (gw_in_index >= sigs.size())
      {
        reason = "missing gateway input signature";
        return false;
      }
      if (!verify_gateway_owner_signature(it->second.latest_descriptor().owner_key, sigs[gw_in_index]->sig, msg))
      {
        reason = "gateway input signature verification failed";
        return false;
      }
      ++gw_in_index;
    }

    // Every gateway_input_sig must correspond to a gateway input.
    if (gw_in_index != sigs.size())
    {
      reason = "more gateway input signatures than gateway inputs";
      return false;
    }
    return true;
  }
}

bool validate_gateway_bridge_memos(const transaction& tx, std::string& reason)
{
  // Deliberately does NOT inspect the memo's chain_id/evm_addr -- it
  // structurally can't. Those only exist inside `m.ciphertext`, encrypted; this
  // function only ever sees the plaintext fields (version, output_index) below.
  // Decoding them requires the gateway's view secret key
  // (decrypt_gateway_bridge_memo, below), which no consensus path ever has for
  // an arbitrary gateway. That is also why chain_id is stored as the raw EIP-155
  // id rather than an agreed-upon index: nodes never need to agree on a value
  // they cannot see. If a future change moves any of it into a plaintext,
  // validator-visible field, this reasoning stops applying and a real consensus
  // check has to be added here.
  std::set<uint32_t> seen;
  size_t skip = 0;
  tx_extra_gateway_bridge_memo m{};
  while (get_field_from_tx_extra(tx.extra, m, skip++))
  {
    if (m.version != 0)
    {
      reason = "unsupported gateway bridge memo version";
      return false;
    }
    if (!seen.insert(m.output_index).second)
    {
      reason = "duplicate gateway bridge memo output_index";
      return false;
    }
    if (m.output_index >= tx.vout.size() || !std::holds_alternative<tx_out_gateway>(tx.vout[m.output_index].target))
    {
      reason = "gateway bridge memo output_index does not reference a gateway output";
      return false;
    }
  }
  return true;
}

bool decrypt_gateway_bridge_memo(const transaction& tx, const tx_extra_gateway_bridge_memo& memo,
                                 const crypto::secret_key& gateway_view_secret_key,
                                 gateway_bridge_memo_plaintext& out)
{
  if (memo.output_index >= tx.vout.size() || !std::holds_alternative<tx_out_gateway>(tx.vout[memo.output_index].target))
    return false;

  // Only decrypt memos addressed to *this* gateway. A tx may carry gateway
  // outputs (and memos) for several different gateways; without this we would
  // attempt a wrong-key decrypt on someone else's memo and rely solely on the
  // 4-byte zero padding to notice, which it does only with probability
  // 1 - 2^-32. Matching the output's gateway_addr against the pubkey of the
  // supplied view secret removes those attempts structurally.
  {
    crypto::public_key gw_pub{};
    if (!crypto::secret_key_to_public_key(gateway_view_secret_key, gw_pub))
      return false;
    if (std::get<tx_out_gateway>(tx.vout[memo.output_index].target).gateway_addr != gw_pub)
      return false;
  }

  const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx.extra);
  if (tx_pub_key == crypto::null_pkey)
    return false;

  crypto::key_derivation derivation;
  if (!crypto::generate_key_derivation(tx_pub_key, gateway_view_secret_key, derivation))
    return false;
  crypto::ec_scalar h;
  crypto::derivation_to_scalar(derivation, memo.output_index, h);
  std::string buf;
  buf.reserve(hashkey::GW_BRIDGE_MEMO_MASK.size() + sizeof(h));
  buf.append(hashkey::GW_BRIDGE_MEMO_MASK);
  buf.append(reinterpret_cast<const char*>(&h), sizeof(h));
  const crypto::hash mask = crypto::cn_fast_hash(buf.data(), buf.size());

  unsigned char plain[32];
  for (size_t i = 0; i < sizeof(plain); ++i)
    plain[i] = static_cast<unsigned char>(memo.ciphertext.data[i]) ^ static_cast<unsigned char>(mask.data[i]);

  // Integrity check: the 4 trailing plaintext bytes must be zero (see
  // encrypt_gateway_bridge_memo). A wrong key produces garbage there instead.
  for (size_t i = 28; i < sizeof(plain); ++i)
    if (plain[i] != 0)
      return false;

  // chain_id is stored explicitly little-endian on the wire (see
  // encrypt_gateway_bridge_memo); convert back to host order here.
  uint64_t chain_id;
  std::memcpy(&chain_id, plain, sizeof(chain_id));
  oxenc::little_to_host_inplace(chain_id);
  crypto::eth_address evm_addr;
  std::memcpy(&evm_addr, plain + sizeof(chain_id), sizeof(evm_addr));

  out.chain_id = chain_id;
  out.evm_addr = evm_addr;
  return true;
}

bool validate_gateway_takeover_step(BlockchainDB& db, network_type nettype,
                                    const tx_extra_gateway_takeover& t, std::string& reason)
{
  if (t.version != 1)
  {
    reason = "a standalone takeover step is version 1";
    return false;
  }
  gateway_account_data acct;
  if (!load_gateway_account(db, t.gateway_id, acct) || acct.descriptor_history.empty())
  {
    reason = "takeover step for an unknown gateway";
    return false;
  }
  const gateway_descriptor_base& current = acct.latest_descriptor();
  const uint64_t started = acct.takeover_started_height();
  const uint64_t height  = db.height();
  const uint64_t wait    = gateway_standby_takeover_blocks(nettype);

  switch (t.action)
  {
    case gateway_takeover_action::cancel:
    {
      if (started == 0 || started != t.started_height)
      {
        reason = "takeover cancel names no running takeover (running: " + std::to_string(started)
                 + ", named: " + std::to_string(t.started_height) + ")";
        return false;
      }
      if (!verify_gateway_owner_signature(current.owner_key, t.sig,
                                          gateway_takeover_cancel_message(nettype, t.gateway_id, t.started_height)))
      {
        reason = "takeover cancel is not signed by the gateway's owner";
        return false;
      }
      return true;
    }
    case gateway_takeover_action::begin:
    {
      if (acct.frozen)
      {
        reason = "gateway is frozen; takeover begin rejected";
        return false;
      }
      if (!current.has_standby)
      {
        reason = "gateway has no standby owner to take it over";
        return false;
      }
      if (started != 0)
      {
        reason = "a takeover of this gateway is already running";
        return false;
      }
      const uint64_t ended = acct.takeover_ended_height();
      if (ended != 0 && height < ended + wait)
      {
        reason = "takeover cooling down: " + std::to_string(ended + wait - height) + " more block(s)";
        return false;
      }
      if (t.started_height != acct.takeover_log.size())
      {
        reason = "takeover begin is for step " + std::to_string(t.started_height) + ", the gateway is at step "
                 + std::to_string(acct.takeover_log.size());
        return false;
      }
      if (!verify_gateway_owner_signature(current.standby_owner, t.sig,
            gateway_takeover_begin_message(nettype, t.gateway_id, current, acct.takeover_log.size())))
      {
        reason = "takeover begin is not signed by the gateway's standby owner";
        return false;
      }
      return true;
    }
    case gateway_takeover_action::complete:
    {
      if (acct.frozen)
      {
        reason = "gateway is frozen; takeover complete rejected";
        return false;
      }
      if (started == 0 || started != t.started_height)
      {
        reason = "takeover complete names no running takeover (running: " + std::to_string(started)
                 + ", named: " + std::to_string(t.started_height) + ")";
        return false;
      }
      if (height < started + wait)
      {
        reason = "takeover not ready: " + std::to_string(started + wait - height) + " more block(s)";
        return false;
      }
      if (!current.has_standby || !(t.new_owner == current.standby_owner))
      {
        reason = "a takeover complete must name the standby owner as the new owner";
        return false;
      }
      if (!verify_gateway_owner_signature(current.standby_owner, t.sig,
            gateway_takeover_complete_message(nettype, t.gateway_id, t.started_height)))
      {
        reason = "takeover complete is not signed by the gateway's standby owner";
        return false;
      }
      return true;
    }
    case gateway_takeover_action::name_standby:
    {
      if (acct.frozen)
      {
        reason = "gateway is frozen; naming a standby rejected";
        return false;
      }
      if (started != 0)
      {
        reason = "a takeover of this gateway is running; it must end before a standby is named";
        return false;
      }
      if (t.started_height != acct.descriptor_history.size())
      {
        reason = "standby name is for descriptor " + std::to_string(t.started_height) + ", the gateway has "
                 + std::to_string(acct.descriptor_history.size());
        return false;
      }
      if (!is_valid_gateway_owner_key(t.new_owner) || t.new_owner == current.owner_key)
      {
        reason = "a gateway's standby owner must be a valid key that differs from its owner";
        return false;
      }
      gateway_descriptor_base next = current;
      next.version = 2;
      next.has_standby = 1;
      next.standby_owner = t.new_owner;
      if (!standby_is_fresh(acct, next, reason))
        return false;
      if (!verify_gateway_owner_signature(current.owner_key, t.sig,
            gateway_standby_name_message(nettype, t.gateway_id, t.started_height, t.new_owner)))
      {
        reason = "standby name is not signed by the gateway's owner";
        return false;
      }
      return true;
    }
    case gateway_takeover_action::standby_alive:
    {
      if (!current.has_standby || t.new_owner != current.standby_owner)
      {
        reason = "a standby liveness proof must name the gateway's current standby";
        return false;
      }
      const uint64_t slot = gateway_standby_alive_slot_blocks(nettype);
      const uint64_t window = gateway_standby_alive_window_blocks(nettype);
      if (t.started_height % slot != 0 || t.started_height >= height || t.started_height + window < height)
      {
        reason = "standby liveness proof over block " + std::to_string(t.started_height)
                 + " is not a recent slot boundary (every " + std::to_string(slot) + " blocks, within the last "
                 + std::to_string(window) + ")";
        return false;
      }
      if (!verify_gateway_owner_signature(current.standby_owner, t.sig,
            gateway_standby_alive_message(nettype, t.gateway_id, current.standby_owner, t.started_height,
                                          db.get_block_hash_from_height(t.started_height))))
      {
        reason = "standby liveness proof is not signed by the gateway's standby";
        return false;
      }
      return true;
    }
  }
  reason = "unknown takeover step";
  return false;
}

bool validate_tx_gateway_operations_against_db(BlockchainDB& db, network_type nettype, const transaction& tx,
                                               hf hf_version, const checkpoint_quorum_resolver& resolve_quorum,
                                               std::string& reason)
{
  // ---- HF23 Sovereign Bridge governance & routing fields -------------------
  const auto freezes      = extract_gateway_freezes(tx);
  const auto repoints     = extract_gateway_repoints(tx);
  const auto release_refs = extract_gateway_release_refs(tx);

  const bool has_governance = !freezes.empty() || !repoints.empty();

  // Bridge deposit-routing memos are HF22, not HF23 — they are gated (and
  // structurally validated) by validate_gateway_bridge_memos on the gateway path,
  // not here. Their presence still matters for the governance clean-carrier rule
  // below, so detect it.
  const bool has_bridge_memo = [&] {
    tx_extra_gateway_bridge_memo m{};
    return get_field_from_tx_extra(tx.extra, m);
  }();

  if (hf_version < feature::BRIDGE)
  {
    // Pre-HF23: none of the HF23 bridge fields may appear.
    if (has_governance || !release_refs.empty())
    {
      reason = "gateway governance / release-ref field before HF23";
      return false;
    }
  }
  else
  {
    if (freezes.size() > 1 || repoints.size() > 1)
    {
      reason = "tx carries more than one gateway freeze/repoint op";
      return false;
    }
    if (!freezes.empty() && !repoints.empty())
    {
      reason = "tx carries both a freeze and a repoint op";
      return false;
    }

    // A governance tx is a clean carrier: no descriptor ops, no gateway in/out,
    // no bridge memo may ride alongside a freeze/repoint.
    if (has_governance)
    {
      const bool has_gw_construct =
          tx_has_gateway_constructs(tx) ||
          std::any_of(tx.vout.begin(), tx.vout.end(),
                      [](const tx_out& o){ return std::holds_alternative<tx_out_gateway>(o.target); }) ||
          has_bridge_memo || !release_refs.empty();
      if (has_gw_construct)
      {
        reason = "gateway governance op must not ride alongside other gateway constructs";
        return false;
      }
      if (!freezes.empty() && !validate_gateway_freeze_operation(db, nettype, tx, freezes.front(), resolve_quorum, reason))
        return false;
      if (!repoints.empty() && !validate_gateway_repoint_operation(db, nettype, tx, repoints.front(), resolve_quorum, reason))
        return false;
    }

    // Mandatory release ref for a bridge-reserve gateway (HF23, §3.6): a withdrawal
    // from a flagged gateway MUST name the burn it discharges, so the replay guard
    // cannot be sidestepped by simply omitting the ref. Authoritative enforcement is
    // at block apply; this is the early (relay-time) reject.
    if (release_refs.empty())
    {
      for (const auto& in : tx.vin)
      {
        const auto* g = std::get_if<txin_gateway>(&in);
        if (!g)
          continue;
        gateway_account_data acct;
        if (load_gateway_account(db, g->gateway_addr, acct) && !acct.descriptor_history.empty() &&
            acct.latest_descriptor().is_bridge_reserve())
        {
          reason = "withdrawal from a bridge-reserve gateway must carry a release ref";
          return false;
        }
      }
    }

    // Release replay guard (HF23, GATEWAY_RELEASE_REPLAY_GUARD.md): structural
    // rules + an early dedup against stored state. The authoritative dedup
    // (which also sees same-block earlier txs) runs at block apply.
    if (!release_refs.empty())
    {
      if (release_refs.size() > 1)
      {
        reason = "tx carries more than one gateway release ref";
        return false;
      }
      const auto& rf = release_refs.front();
      if (rf.version != 0)
      {
        reason = "unsupported gateway release ref version";
        return false;
      }
      // A ref names the burn a *withdrawal* discharges — it may only ride a tx
      // that actually spends a gateway.
      const bool has_withdrawal = std::any_of(tx.vin.begin(), tx.vin.end(),
          [](const auto& in){ return std::holds_alternative<txin_gateway>(in); });
      if (!has_withdrawal)
      {
        reason = "gateway release ref on a tx with no gateway withdrawal";
        return false;
      }
      // Early reject a replay of a ref already discharged on-chain (per source
      // gateway; the ref is recorded against every gateway the tx spends from). The
      // account only remembers the last two windows; the permanent index the rest.
      const crypto::hash ref = gateway_release_ref_hash(rf.chain_id, rf.evm_txid, rf.log_index);
      for (const auto& in : tx.vin)
      {
        const auto* g = std::get_if<txin_gateway>(&in);
        if (!g)
          continue;
        gateway_account_data acct;
        if ((load_gateway_account(db, g->gateway_addr, acct) && acct.release_ref_recorded(ref)) ||
            db.has_gateway_release_ref(g->gateway_addr, ref))
        {
          reason = "gateway release replays an already-discharged burn ref";
          return false;
        }
      }
    }

    // Per-tx release maximum (A.3). The cumulative per-window cap is authoritative
    // at block-apply (append); the per-tx bound is a static check enforceable here.
    uint64_t tx_release = 0;
    for (const auto& in : tx.vin)
      if (const auto* g = std::get_if<txin_gateway>(&in))
      {
        if (tx_release > std::numeric_limits<uint64_t>::max() - g->amount)
        {
          reason = "gateway withdrawal amount overflow";
          return false;
        }
        tx_release += g->amount;
      }
    if (tx_release > GATEWAY_RELEASE_PER_TX_MAX)
    {
      reason = "gateway withdrawal exceeds the per-tx release maximum";
      return false;
    }
  }

  // ---- descriptor operations (register / update) ----
  const auto ops = extract_gateway_ops(tx);
  if (ops.size() > 1)
  {
    reason = "tx carries more than one gateway descriptor operation";
    return false;
  }

  const bool is_gateway_type =
      tx.type == txtype::register_gateway_address || tx.type == txtype::update_gateway_address;

  // A version-0 takeover marker only means something on the update it rides with. A
  // version-1 one stands alone: the owner's cancel, carried by any wallet.
  {
    const auto takeovers = extract_gateway_takeovers(tx);
    const bool standalone = std::any_of(takeovers.begin(), takeovers.end(),
                                        [](const auto& t) { return t.version >= 1; });
    if (standalone)
    {
      if (hf_version < feature::BRIDGE)
      {
        reason = "standalone gateway takeover step before HF23";
        return false;
      }
      if (takeovers.size() != 1 || !ops.empty() || tx_has_gateway_constructs(tx) || has_governance
          || !release_refs.empty() || tx.type != txtype::bridge_registration)
      {
        reason = "a standalone gateway takeover step must be the only gateway content of a bridge_registration tx";
        return false;
      }
      if (!validate_gateway_takeover_step(db, nettype, takeovers.front(), reason))
        return false;
    }
    else if (!takeovers.empty() &&
             (ops.empty() || ops.front().op_type != gateway_descriptor_op_type::update_address))
    {
      reason = "gateway takeover marker without a descriptor update";
      return false;
    }
    else if (std::any_of(takeovers.begin(), takeovers.end(), [](const auto& t) {
               return t.action != gateway_takeover_action::begin && t.action != gateway_takeover_action::complete;
             }))
    {
      // Only a begin or a complete rides a descriptor update; a cancel, a standby naming and
      // a liveness proof are standalone (version 1).
      reason = "a takeover cancel, standby naming or liveness proof is standalone (version 1), not a descriptor update";
      return false;
    }
  }

  if (ops.empty())
  {
    if (is_gateway_type)
    {
      reason = "gateway tx type without a descriptor operation";
      return false;
    }
  }
  else
  {
    if (!is_gateway_type)
    {
      reason = "gateway descriptor operation in a non-gateway tx type";
      return false;
    }
    if (!validate_gateway_descriptor_operation(db, nettype, tx, ops.front(), hf_version, reason))
      return false;
  }

  // Legacy tx-wide payment id (tx_extra nonce) is incompatible with gateway
  // outputs (which carry their own encrypted payment id).
  {
    tx_extra_nonce nonce;
    bool has_gw_out = false;
    for (const auto& o : tx.vout)
      if (std::holds_alternative<tx_out_gateway>(o.target)) { has_gw_out = true; break; }
    if (has_gw_out && get_field_from_tx_extra(tx.extra, nonce))
    {
      reason = "legacy tx-wide payment id is not allowed alongside gateway outputs";
      return false;
    }
  }

  // ---- per-tx gateway construct caps (DoS bound on persisted state churn) ----
  {
    size_t gw_ins = 0, gw_outs = 0;
    for (const auto& in : tx.vin)
      if (std::holds_alternative<txin_gateway>(in)) ++gw_ins;
    for (const auto& o : tx.vout)
      if (std::holds_alternative<tx_out_gateway>(o.target)) ++gw_outs;
    if (gw_ins > GATEWAY_TX_MAX_INPUTS)
    {
      reason = "too many gateway inputs (" + std::to_string(gw_ins) + " > " +
               std::to_string(GATEWAY_TX_MAX_INPUTS) + ")";
      return false;
    }
    if (gw_outs > GATEWAY_TX_MAX_OUTPUTS)
    {
      reason = "too many gateway outputs (" + std::to_string(gw_outs) + " > " +
               std::to_string(GATEWAY_TX_MAX_OUTPUTS) + ")";
      return false;
    }
  }

  // ---- deposits & withdrawals ----
  if (!validate_gateway_deposits(db, tx, hf_version, reason))
    return false;
  if (!validate_gateway_bridge_memos(tx, reason))
    return false;
  if (!validate_gateway_withdrawals(db, nettype, tx, hf_version, reason))
    return false;

  return true;
}

namespace
{
  // HF23 release-window accounting helpers (see gateway_release_window). All set
  // version>=1 so the bridge state is serialized. Bounded: append prunes windows
  // older than w-1 (outside any legal reorg, so never re-touched by rewind).

  bool add_release(gateway_account_data& acct, uint64_t height, uint64_t amount, std::string* reason)
  {
    const uint64_t w = height / GATEWAY_RELEASE_WINDOW_BLOCKS;
    gateway_release_window* entry = nullptr;
    for (auto& e : acct.release_windows)
      if (e.window_id == w) { entry = &e; break; }
    if (!entry)
    {
      acct.release_windows.push_back(gateway_release_window{w, 0});
      entry = &acct.release_windows.back();
    }
    if (amount > GATEWAY_RELEASE_CAP_PER_WINDOW ||
        entry->amount > GATEWAY_RELEASE_CAP_PER_WINDOW - amount)
    {
      set_reason(reason, "gateway per-window release cap exceeded");
      return false;
    }
    entry->amount += amount;
    if (acct.version < 1) acct.version = 1;

    // Prune windows strictly older than the immediately-preceding one.
    if (w >= 2)
    {
      auto& v = acct.release_windows;
      v.erase(std::remove_if(v.begin(), v.end(),
              [&](const gateway_release_window& e){ return e.window_id + 1 < w; }), v.end());
    }
    return true;
  }

  bool sub_release(gateway_account_data& acct, uint64_t height, uint64_t amount, std::string* reason)
  {
    const uint64_t w = height / GATEWAY_RELEASE_WINDOW_BLOCKS;
    for (auto it = acct.release_windows.begin(); it != acct.release_windows.end(); ++it)
    {
      if (it->window_id != w) continue;
      if (it->amount < amount)
      {
        set_reason(reason, "gateway release-window underflow while rewinding");
        return false;
      }
      it->amount -= amount;
      if (it->amount == 0)
        acct.release_windows.erase(it);
      return true;
    }
    set_reason(reason, "gateway release window missing while rewinding");
    return false;
  }

  // Record a discharged release ref (HF23 replay guard). Duplicate within the
  // retained (current + previous) windows => the block is invalid. Same window
  // bucketing + lazy pruning discipline as add_release.
  bool add_release_ref(gateway_account_data& acct, uint64_t height, const crypto::hash& ref, std::string* reason)
  {
    if (acct.release_ref_recorded(ref))
    {
      set_reason(reason, "gateway release replays an already-discharged burn ref");
      return false;
    }
    const uint64_t w = height / GATEWAY_RELEASE_WINDOW_BLOCKS;
    gateway_release_ref_window* entry = nullptr;
    for (auto& e : acct.release_ref_windows)
      if (e.window_id == w) { entry = &e; break; }
    if (!entry)
    {
      acct.release_ref_windows.push_back(gateway_release_ref_window{});
      entry = &acct.release_ref_windows.back();
      entry->window_id = w;
    }
    entry->refs.push_back(ref);
    if (acct.version < 2) acct.version = 2;

    // Prune windows strictly older than the immediately-preceding one (safely
    // outside any legal reorg — see gateway_release_ref_window).
    if (w >= 2)
    {
      auto& v = acct.release_ref_windows;
      v.erase(std::remove_if(v.begin(), v.end(),
              [&](const gateway_release_ref_window& e){ return e.window_id + 1 < w; }), v.end());
    }
    return true;
  }

  // Exact inverse of add_release_ref for rewind: remove the ref from the
  // block-height's window entry (erasing an emptied entry so the blob is
  // byte-identical to the pre-append state, S9).
  bool sub_release_ref(gateway_account_data& acct, uint64_t height, const crypto::hash& ref, std::string* reason)
  {
    const uint64_t w = height / GATEWAY_RELEASE_WINDOW_BLOCKS;
    for (auto it = acct.release_ref_windows.begin(); it != acct.release_ref_windows.end(); ++it)
    {
      if (it->window_id != w) continue;
      for (auto rit = it->refs.rbegin(); rit != it->refs.rend(); ++rit)
      {
        if (*rit != ref) continue;
        it->refs.erase(std::next(rit).base());
        if (it->refs.empty())
          acct.release_ref_windows.erase(it);
        return true;
      }
      set_reason(reason, "gateway release ref missing from its window while rewinding");
      return false;
    }
    set_reason(reason, "gateway release-ref window missing while rewinding");
    return false;
  }

  // Restore byte-exact HF22 (version 0) shape for an account with no remaining
  // bridge state, so a full reorg of bridge activity leaves an identical blob.
  void normalize_bridge_state(gateway_account_data& acct)
  {
    if (!acct.takeover_log.empty())
      return; // v3 state still present: keep every field it implies
    if (acct.version >= 3)
      acct.version = 2;
    if (acct.release_ref_windows.empty() && acct.version >= 2)
      acct.version = 1;
    if (acct.frozen == 0 && acct.governance_seq == 0 && acct.release_windows.empty() &&
        acct.version <= 1)
      acct.version = 0;
  }

  // Every gateway address touched by a tx: descriptor-op targets, deposit
  // destinations, and withdrawal sources. Deduped so a tx appears once per
  // gateway in the history table.
  std::set<crypto::public_key> gateways_touched_by_tx(const transaction& tx)
  {
    std::set<crypto::public_key> gws;
    for (const auto& op : extract_gateway_ops(tx))
      gws.insert(op.address_id);
    for (const auto& o : tx.vout)
      if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
        gws.insert(g->gateway_addr);
    for (const auto& in : tx.vin)
      if (const auto* g = std::get_if<txin_gateway>(&in))
        gws.insert(g->gateway_addr);
    return gws;
  }

  // Core apply logic shared by simulate (dry-run) and append (persist). Fills
  // `cache` with the post-block gateway state, processing txs in block order
  // and, per tx, descriptor ops then deposits then withdrawals (so a same-block
  // deposit funds a later withdrawal). Returns false on any block-invalidating
  // condition (over-withdrawal underflow, overflow, register-of-existing, etc.)
  // WITHOUT mutating the DB — it reads accounts but never writes, so a false
  // return leaves no trace.
  bool compute_gateway_changes(BlockchainDB& db, const std::vector<transaction>& txs,
                               std::unordered_map<crypto::public_key, gateway_account_data>& cache,
                               uint64_t block_height, bool bridge_active, std::string* reason)
  {
    auto get = [&](const crypto::public_key& id) -> gateway_account_data& {
      auto [it, inserted] = cache.try_emplace(id);
      if (inserted)
        load_gateway_account(db, id, it->second); // absent => default (empty)
      return it->second;
    };

    for (const auto& tx : txs)
    {
      // 1) descriptor ops (register / update)
      for (const auto& op : extract_gateway_ops(tx))
      {
        gateway_account_data& acct = get(op.address_id);

        if (op.op_type == gateway_descriptor_op_type::register_address)
        {
          if (!acct.descriptor_history.empty())
          {
            set_reason(reason, "register op for an already-existing gateway");
            return false;
          }
        }
        else // update_address
        {
          if (acct.descriptor_history.empty())
          {
            set_reason(reason, "update op for an unknown gateway");
            return false;
          }
          // Takeover state (validated already): a begin starts the clock, a complete ends
          // it, and any owner-signed update while one runs cancels it.
          const crypto::hash txh = get_transaction_hash(tx);
          const auto takeovers = extract_gateway_takeovers(tx);
          if (!takeovers.empty() && takeovers.front().gateway_id == op.address_id)
          {
            const bool begin = takeovers.front().action == gateway_takeover_action::begin;
            acct.takeover_log.push_back(gateway_takeover_entry{txh, begin ? block_height : 0, block_height});
            if (acct.version < 3) acct.version = 3;
          }
          else if (acct.takeover_started_height() != 0)
          {
            acct.takeover_log.push_back(gateway_takeover_entry{txh, 0, block_height});
            if (acct.version < 3) acct.version = 3;
          }
        }
        acct.descriptor_history.push_back(op.descriptor);
      }

      // 1b) governance re-point (HF23): append the new descriptor and bump the nonce.
      for (const auto& op : extract_gateway_repoints(tx))
      {
        gateway_account_data& acct = get(op.gateway_id);
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "repoint for an unknown gateway");
          return false;
        }
        acct.descriptor_history.push_back(op.new_owner_descriptor);
        ++acct.governance_seq;
        if (acct.version < 1) acct.version = 1;
        // Governance chose the owner: a running takeover ends here.
        if (acct.takeover_started_height() != 0)
        {
          acct.takeover_log.push_back(gateway_takeover_entry{get_transaction_hash(tx), 0, block_height});
          if (acct.version < 3) acct.version = 3;
        }
      }

      // 1c) governance freeze/unfreeze (HF23): toggle the flag and bump the nonce.
      for (const auto& op : extract_gateway_freezes(tx))
      {
        gateway_account_data& acct = get(op.gateway_id);
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "freeze for an unknown gateway");
          return false;
        }
        acct.frozen = (op.freeze != 0) ? 1 : 0;
        ++acct.governance_seq;
        if (acct.version < 1) acct.version = 1;
        // (see 1d for the owner's standalone cancel)
        // A freeze is governance's veto of a running takeover. Without this the clock kept
        // running while the gateway was frozen, and the takeover completed the moment it
        // was unfrozen.
        if (op.freeze != 0 && acct.takeover_started_height() != 0)
        {
          acct.takeover_log.push_back(gateway_takeover_entry{get_transaction_hash(tx), 0, block_height});
          if (acct.version < 3) acct.version = 3;
        }
      }

      // 1d) standalone takeover steps (HF23): begin, complete or cancel. Every member of the
      // signing committee may carry the same signed step, so a copy landing after another
      // (or after the state moved on) changes nothing, and its rewind, matching by tx hash,
      // then undoes nothing either.
      for (const auto& t : extract_gateway_takeovers(tx))
      {
        if (t.version < 1)
          continue;
        gateway_account_data& acct = get(t.gateway_id);
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "takeover step for an unknown gateway");
          return false;
        }
        const uint64_t started = acct.takeover_started_height();
        const crypto::hash txh = get_transaction_hash(tx);
        switch (t.action)
        {
          case gateway_takeover_action::begin:
            if (started == 0 && acct.takeover_log.size() == t.started_height)
              acct.takeover_log.push_back(gateway_takeover_entry{txh, block_height, block_height});
            else
              continue;
            break;
          case gateway_takeover_action::complete:
            if (started != 0 && started == t.started_height)
            {
              acct.takeover_log.push_back(gateway_takeover_entry{txh, 0, block_height});
              acct.descriptor_history.push_back(taken_over_descriptor(acct.latest_descriptor()));
            }
            else
              continue;
            break;
          case gateway_takeover_action::cancel:
            if (started != 0 && started == t.started_height)
              acct.takeover_log.push_back(gateway_takeover_entry{txh, 0, block_height});
            else
              continue;
            break;
          case gateway_takeover_action::name_standby:
          {
            // Bound to the descriptor count it was signed for: a second copy finds the
            // count moved on and changes nothing.
            if (started != 0 || acct.descriptor_history.size() != t.started_height)
              continue;
            gateway_descriptor_base next = acct.latest_descriptor();
            next.version = 2;
            next.has_standby = 1;
            next.standby_owner = t.new_owner;
            acct.descriptor_history.push_back(next);
            continue; // no takeover-log entry, and the account version is unchanged
          }
          case gateway_takeover_action::standby_alive:
            continue; // recorded by the master-node state, not the gateway
        }
        if (acct.version < 3) acct.version = 3;
      }

      // 2) deposits (tx_out_gateway): increase balance
      for (const auto& o : tx.vout)
      {
        if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
        {
          gateway_account_data& acct = get(g->gateway_addr);
          if (acct.descriptor_history.empty())
          {
            set_reason(reason, "deposit to an unregistered gateway");
            return false;
          }
          if (!change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/true, reason))
            return false;
        }
      }

      // 3) withdrawals (txin_gateway): decrease balance (underflow => block invalid)
      for (const auto& in : tx.vin)
      {
        if (const auto* g = std::get_if<txin_gateway>(&in))
        {
          gateway_account_data& acct = get(g->gateway_addr);
          if (acct.descriptor_history.empty())
          {
            set_reason(reason, "withdrawal from an unregistered gateway");
            return false;
          }
          if (!change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/false, reason))
            return false;
          if (bridge_active && !add_release(acct, block_height, g->amount, reason))
            return false;
        }
      }

      // 4) release replay guard (HF23): a withdrawal carrying a release ref
      // records the discharged burn against every source gateway it spends
      // from; a ref already recorded (this block or a prior one — the cache
      // holds the in-flight block state, S9) invalidates the block. Structural
      // rules (HF23-only, at most one, must ride a withdrawal) are enforced at
      // tx validation; this is the authoritative consensus dedup.
      if (bridge_active)
      {
        const auto refs_here = extract_gateway_release_refs(tx);
        // §3.6: a withdrawal from a bridge-reserve gateway must name its burn.
        // Authoritative counterpart of the tx-level check — a block carrying a
        // ref-less withdrawal from a flagged gateway is invalid.
        if (refs_here.empty())
        {
          for (const auto& in : tx.vin)
          {
            const auto* g = std::get_if<txin_gateway>(&in);
            if (!g)
              continue;
            const gateway_account_data& acct = get(g->gateway_addr);
            if (!acct.descriptor_history.empty() && acct.latest_descriptor().is_bridge_reserve())
            {
              set_reason(reason, "withdrawal from a bridge-reserve gateway carries no release ref");
              return false;
            }
          }
        }
        for (const auto& [gw_addr, ref] : gateway_release_ref_records(tx))
        {
          // The windowed record below only reaches back two windows; past that, only
          // the permanent index still knows the burn was paid.
          if (db.has_gateway_release_ref(gw_addr, ref))
          {
            set_reason(reason, "gateway release replays an already-discharged burn ref");
            return false;
          }
          gateway_account_data& acct = get(gw_addr);
          if (!add_release_ref(acct, block_height, ref, reason))
            return false;
        }
      }
    }

    return true;
  }
}

bool simulate_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs,
                                         uint64_t block_height, bool bridge_active, std::string* reason)
{
  // Dry-run: compute the post-block state but write nothing. Used to reject an
  // over-withdrawing (or otherwise invalid) block BEFORE it is added to the DB.
  std::unordered_map<crypto::public_key, gateway_account_data> cache;
  return compute_gateway_changes(db, txs, cache, block_height, bridge_active, reason);
}

bool append_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, uint64_t block_height, bool bridge_active, std::string* reason)
{
  std::unordered_map<crypto::public_key, gateway_account_data> cache;

  // Dry-run first; persist only after the whole block computed cleanly
  // (atomic: all-or-nothing). A false return therefore guarantees no gateway
  // state was written — the caller must NOT rewind (see header).
  if (!compute_gateway_changes(db, txs, cache, block_height, bridge_active, reason))
    return false;

  // transaction-history table (second gateway table): record each tx under
  // every gateway it touched.
  for (const auto& tx : txs)
  {
    const crypto::hash tx_hash = get_transaction_hash(tx);
    for (const auto& gw : gateways_touched_by_tx(tx))
      db.add_gateway_tx(gw, block_height, tx_hash);
    if (bridge_active)
      for (const auto& [gw, ref] : gateway_release_ref_records(tx))
        db.add_gateway_release_ref(gw, ref, block_height);
  }

  for (const auto& [id, acct] : cache)
    store_gateway_account(db, id, acct);

  return true;
}

bool rewind_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs,
                                       uint64_t block_height, bool bridge_active, std::string* reason)
{
  std::unordered_map<crypto::public_key, gateway_account_data> cache;

  auto get = [&](const crypto::public_key& id, bool& ok) -> gateway_account_data& {
    auto [it, inserted] = cache.try_emplace(id);
    if (inserted)
      ok = load_gateway_account(db, id, it->second);
    else
      ok = true;
    return it->second;
  };

  // Exact inverse of append. Reverse the tx order; within each tx undo in the
  // reverse of the apply order: withdrawals(+release), deposits, freezes,
  // repoints, then descriptor ops.
  for (auto tx_it = txs.rbegin(); tx_it != txs.rend(); ++tx_it)
  {
    const transaction& tx = *tx_it;

    // undo the transaction-history entries (second gateway table)
    const crypto::hash tx_hash = get_transaction_hash(tx);
    for (const auto& gw : gateways_touched_by_tx(tx))
      db.remove_gateway_tx(gw, block_height, tx_hash);

    // undo the release-ref records (applied last within the tx, so undone first)
    if (bridge_active)
    {
      for (const auto& [gw_addr, ref] : gateway_release_ref_records(tx))
      {
        bool ok = false;
        gateway_account_data& acct = get(gw_addr, ok);
        if (!ok || !sub_release_ref(acct, block_height, ref, reason))
          return false;
        db.remove_gateway_release_ref(gw_addr, ref);
      }
    }

    // undo withdrawals: re-add the spent amount and un-account the release
    for (const auto& in : tx.vin)
    {
      if (const auto* g = std::get_if<txin_gateway>(&in))
      {
        bool ok = false;
        gateway_account_data& acct = get(g->gateway_addr, ok);
        if (!ok || !change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/true, reason))
        {
          set_reason(reason, "failed to undo gateway withdrawal while rewinding");
          return false;
        }
        if (bridge_active && !sub_release(acct, block_height, g->amount, reason))
          return false;
      }
    }

    // undo deposits: subtract the deposited amount
    for (const auto& o : tx.vout)
    {
      if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      {
        bool ok = false;
        gateway_account_data& acct = get(g->gateway_addr, ok);
        if (!ok || !change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/false, reason))
        {
          set_reason(reason, "failed to undo gateway deposit while rewinding");
          return false;
        }
      }
    }

    // undo standalone takeover steps: pop the entry this tx pushed, if it pushed one, and
    // for a complete the descriptor it appended.
    for (const auto& t : extract_gateway_takeovers(tx))
    {
      if (t.version < 1)
        continue;
      bool ok = false;
      gateway_account_data& acct = get(t.gateway_id, ok);
      if (ok && t.action == gateway_takeover_action::name_standby)
      {
        // It appended exactly one descriptor, the one after started_height, if it applied.
        if (acct.descriptor_history.size() == t.started_height + 1 && acct.latest_descriptor().has_standby
            && acct.latest_descriptor().standby_owner == t.new_owner)
          acct.descriptor_history.pop_back();
        continue;
      }
      if (ok && !acct.takeover_log.empty() && acct.takeover_log.back().tx == tx_hash)
      {
        acct.takeover_log.pop_back();
        if (t.action == gateway_takeover_action::complete && acct.descriptor_history.size() > 1)
          acct.descriptor_history.pop_back();
      }
    }

    // undo freezes: restore the prior flag (append validated freeze != prior) and
    // roll back the nonce.
    for (const auto& op : extract_gateway_freezes(tx))
    {
      bool ok = false;
      gateway_account_data& acct = get(op.gateway_id, ok);
      if (!ok || acct.descriptor_history.empty() || acct.governance_seq == 0)
      {
        set_reason(reason, "gateway freeze rewind on inconsistent state");
        return false;
      }
      acct.frozen = (op.freeze != 0) ? 0 : 1;
      --acct.governance_seq;
      if (!acct.takeover_log.empty() && acct.takeover_log.back().tx == tx_hash)
        acct.takeover_log.pop_back();
    }

    // undo repoints: pop the appended descriptor and roll back the nonce.
    for (const auto& op : extract_gateway_repoints(tx))
    {
      bool ok = false;
      gateway_account_data& acct = get(op.gateway_id, ok);
      if (!ok || acct.descriptor_history.empty() || acct.governance_seq == 0)
      {
        set_reason(reason, "gateway repoint rewind on inconsistent state");
        return false;
      }
      if (!same_descriptor(acct.descriptor_history.back(), op.new_owner_descriptor))
      {
        set_reason(reason, "repoint rewind mismatch: last descriptor does not match the popped op");
        return false;
      }
      acct.descriptor_history.pop_back();
      --acct.governance_seq;
      if (!acct.takeover_log.empty() && acct.takeover_log.back().tx == tx_hash)
        acct.takeover_log.pop_back();
    }

    // undo descriptor ops (reverse order), popping the matching last descriptor
    const auto ops = extract_gateway_ops(tx);
    for (auto op_it = ops.rbegin(); op_it != ops.rend(); ++op_it)
    {
      bool ok = false;
      gateway_account_data& acct = get(op_it->address_id, ok);
      if (!ok || acct.descriptor_history.empty())
      {
        set_reason(reason, "gateway history missing while rewinding");
        return false;
      }
      if (!same_descriptor(acct.descriptor_history.back(), op_it->descriptor))
      {
        set_reason(reason, "rewind mismatch: last descriptor does not match the popped op");
        return false;
      }
      acct.descriptor_history.pop_back();
      // Undo this tx's takeover step, if it made one.
      if (!acct.takeover_log.empty() && acct.takeover_log.back().tx == tx_hash)
        acct.takeover_log.pop_back();
    }
  }

  auto all_zero = [](const gateway_account_data& a) {
    for (const auto& b : a.balances) if (b.amount != 0) return false;
    return true;
  };

  for (auto& [id, acct] : cache)
  {
    normalize_bridge_state(acct); // restore byte-exact HF22 shape when no bridge state remains
    // A gateway whose register op was rewound (empty descriptor history) and
    // whose balances are all zero is removed entirely.
    if (acct.descriptor_history.empty() && all_zero(acct))
      db.remove_gateway_account(id);
    else
      store_gateway_account(db, id, acct);
  }

  return true;
}

std::vector<crypto::hash> get_gateway_history(BlockchainDB& db, const crypto::public_key& gateway_addr, uint64_t offset, uint64_t count)
{
  return db.get_gateway_txs(gateway_addr, offset, count);
}

} // namespace cryptonote
