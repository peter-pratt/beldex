// Copyright (c) 2026, The Beldex Project
#pragma once

#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include "common/hex.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote::rpc {

// One page of `gateway_get_history`, templated on the core so the unit tests can drive the
// production scan against an in-memory chain.
//
// The cursor is a height, so a page must end on a block boundary: `max_events` is checked
// between blocks and the last block is always returned whole, even past the budget.
// Stopping mid-block and resuming at the next height loses the rest of that block. Data
// that cannot be read is an error rather than an empty block, for the same reason.
template <typename Core>
nlohmann::json gateway_history_page(Core& core, const crypto::public_key& gw_id,
    uint64_t from_height, uint64_t requested_max_blocks, uint64_t requested_max_events)
{
  using nlohmann::json;
  // Server-side bounds so a single call can never scan/return unboundedly.
  constexpr uint64_t DEFAULT_MAX_BLOCKS = 1000, LIMIT_MAX_BLOCKS = 10000;
  constexpr uint64_t DEFAULT_MAX_EVENTS = 100,  LIMIT_MAX_EVENTS = 1000;
  const uint64_t max_blocks = std::min(requested_max_blocks ? requested_max_blocks : DEFAULT_MAX_BLOCKS, LIMIT_MAX_BLOCKS);
  const uint64_t max_events = std::min(requested_max_events ? requested_max_events : DEFAULT_MAX_EVENTS, LIMIT_MAX_EVENTS);

  const uint64_t top = core.get_current_blockchain_height();
  auto& db = core.get_blockchain_storage().get_db();

  auto events = json::array();
  uint64_t h = from_height;
  uint64_t scanned = 0;
  for (; h < top && scanned < max_blocks && events.size() < max_events; ++h, ++scanned)
  {
    // Throws on an unreadable block; the caller retries the same height.
    cryptonote::block blk = db.get_block_from_height(h);

    std::vector<cryptonote::transaction> txs;
    if (!blk.tx_hashes.empty() &&
        (!core.get_transactions(blk.tx_hashes, txs) || txs.size() != blk.tx_hashes.size()))
      throw std::runtime_error{"gateway history: missing transactions at height " + std::to_string(h)};

    for (const auto& tx : txs)
    {
      const std::string txid = tools::type_to_hex(cryptonote::get_transaction_hash(tx));

      // Bridge deposit-routing memos (tx_extra_gateway_bridge_memo), keyed by the
      // gateway output they tag. Memos are sparse and a tx may carry several, so
      // collect them all rather than taking the first. Surfaced raw (ciphertext +
      // tx pubkey + output index): the bridge signer holds the gateway view
      // secret, the daemon does not, so the signer decrypts.
      std::unordered_map<uint32_t, crypto::hash> bridge_memos;
      {
        size_t skip = 0;
        cryptonote::tx_extra_gateway_bridge_memo bm{};
        while (cryptonote::get_field_from_tx_extra(tx.extra, bm, skip++))
          bridge_memos.emplace(bm.output_index, bm.ciphertext);
      }
      const crypto::public_key memo_txpub =
          bridge_memos.empty() ? crypto::public_key{} : cryptonote::get_tx_pub_key_from_extra(tx);

      // deposits (tx_out_gateway to this gateway)
      for (size_t oi = 0; oi < tx.vout.size(); ++oi)
      {
        const auto& o = tx.vout[oi];
        const auto* g = std::get_if<cryptonote::tx_out_gateway>(&o.target);
        if (!g || g->gateway_addr != gw_id)
          continue;
        json ev{{"height", h}, {"txid", txid}, {"type", "deposit"}, {"amount", g->amount}};
        // Emitted for every gateway output, not just memoed ones: a tx may carry
        // several, so the txid alone does not identify a deposit.
        ev["out_index"] = oi;
        if (auto it = bridge_memos.find(static_cast<uint32_t>(oi)); it != bridge_memos.end())
        {
          ev["enc_memo"]  = tools::type_to_hex(it->second);
          ev["tx_pubkey"] = tools::type_to_hex(memo_txpub);
        }
        events.push_back(std::move(ev));
      }

      // withdrawals (txin_gateway from this gateway)
      for (const auto& in : tx.vin)
        if (const auto* g = std::get_if<cryptonote::txin_gateway>(&in))
          if (g->gateway_addr == gw_id)
            events.push_back(json{{"height", h}, {"txid", txid}, {"type", "withdrawal"}, {"amount", g->amount}});

      // descriptor ops (register / update)
      {
        cryptonote::tx_extra_gateway_descriptor_operation op{};
        if (cryptonote::get_field_from_tx_extra(tx.extra, op) && op.address_id == gw_id)
          events.push_back(json{{"height", h}, {"txid", txid},
              {"type", op.op_type == cryptonote::gateway_descriptor_op_type::register_address ? "register" : "update"}});
      }
      // governance freeze / unfreeze
      {
        cryptonote::tx_extra_gateway_freeze op{};
        if (cryptonote::get_field_from_tx_extra(tx.extra, op) && op.gateway_id == gw_id)
          events.push_back(json{{"height", h}, {"txid", txid}, {"type", op.freeze ? "freeze" : "unfreeze"}});
      }
      // governance re-point
      {
        cryptonote::tx_extra_gateway_repoint op{};
        if (cryptonote::get_field_from_tx_extra(tx.extra, op) && op.gateway_id == gw_id)
          events.push_back(json{{"height", h}, {"txid", txid}, {"type", "repoint"}});
      }
    }
  }

  return json{{"events", std::move(events)}, {"next_height", h}, {"top_height", top}};
}

} // namespace cryptonote::rpc
