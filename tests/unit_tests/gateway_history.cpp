// Copyright (c) 2026, The Beldex Project
//
// gateway_get_history pagination: the page cursor is a height, so a page must never stop
// part-way through a block, and unreadable data must never move the cursor.

#include <gtest/gtest.h>
#include <set>
#include "rpc/gateway_history.h"

namespace {

// Just enough of core + its DB for the paginator, over an in-memory chain.
struct history_core
{
  std::vector<cryptonote::block> blocks;
  std::vector<cryptonote::transaction> txs;
  bool lose_a_tx = false;
  bool read_fails = false;
  bool block_unreadable = false;

  history_core& get_blockchain_storage() { return *this; }
  history_core& get_db() { return *this; }
  uint64_t get_current_blockchain_height() const { return blocks.size(); }
  cryptonote::block get_block_from_height(uint64_t h) const
  {
    if (block_unreadable) throw std::runtime_error{"block unreadable"};
    return blocks.at(h);
  }
  bool get_transactions(const std::vector<crypto::hash>& ids, std::vector<cryptonote::transaction>& out) const
  {
    for (const auto& id : ids)
      for (const auto& tx : txs)
        if (cryptonote::get_transaction_hash(tx) == id)
          out.push_back(tx);
    if (lose_a_tx && !out.empty())
      out.pop_back();
    return !read_fails;
  }

  // A block of `n_txs` transactions, each paying the gateway `outs_per_tx` times.
  void add_block(const crypto::public_key& gw, size_t n_txs, size_t outs_per_tx)
  {
    cryptonote::block b{};
    for (size_t t = 0; t < n_txs; ++t)
    {
      cryptonote::transaction tx{};
      tx.unlock_time = txs.size() + 1; // distinct hashes
      for (size_t o = 0; o < outs_per_tx; ++o)
      {
        cryptonote::tx_out_gateway out{};
        out.gateway_addr = gw;
        out.amount = 1;
        tx.vout.push_back({0, out});
      }
      b.tx_hashes.push_back(cryptonote::get_transaction_hash(tx));
      txs.push_back(std::move(tx));
    }
    blocks.push_back(std::move(b));
  }
};

} // namespace

TEST(gateway_history, a_busy_block_is_returned_whole_before_the_cursor_moves)
{
  // 8 txs × 15 gateway outputs = 120 deposits in one block, against a budget of 100.
  // The old scan stopped at 100 and resumed at the next height, losing the last 20.
  history_core core;
  crypto::public_key gw{};
  core.add_block(gw, 8, 15);
  core.add_block(gw, 1, 1);

  auto first = cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 100);
  ASSERT_EQ(first["events"].size(), 120u);
  EXPECT_EQ(first["next_height"], 1u);
  std::set<std::pair<std::string, size_t>> deposits;
  for (const auto& ev : first["events"])
    deposits.emplace(ev["txid"].get<std::string>(), ev["out_index"].get<size_t>());
  EXPECT_EQ(deposits.size(), 120u);

  auto second = cryptonote::rpc::gateway_history_page(core, gw, 1, 1000, 100);
  ASSERT_EQ(second["events"].size(), 1u);
  EXPECT_EQ(second["events"][0]["height"], 1u);
  EXPECT_EQ(second["next_height"], 2u);
}

TEST(gateway_history, the_budget_is_checked_between_blocks)
{
  history_core core;
  crypto::public_key gw{};
  core.add_block(gw, 0, 0);
  core.add_block(gw, 1, 2);
  core.add_block(gw, 1, 1);

  auto p = cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 1);
  EXPECT_EQ(p["events"].size(), 2u); // the empty block, then all of block 1
  EXPECT_EQ(p["next_height"], 2u);

  auto q = cryptonote::rpc::gateway_history_page(core, gw, 0, 1, 1);
  EXPECT_TRUE(q["events"].empty()); // the block budget still bounds the scan
  EXPECT_EQ(q["next_height"], 1u);
}

TEST(gateway_history, unreadable_data_never_moves_the_cursor)
{
  history_core core;
  crypto::public_key gw{};
  core.add_block(gw, 2, 1);

  core.read_fails = true;
  EXPECT_THROW(cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 100), std::runtime_error);
  core.read_fails = false;

  core.lose_a_tx = true;
  EXPECT_THROW(cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 100), std::runtime_error);
  core.lose_a_tx = false;

  core.block_unreadable = true;
  EXPECT_THROW(cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 100), std::runtime_error);
  core.block_unreadable = false;

  EXPECT_EQ(cryptonote::rpc::gateway_history_page(core, gw, 0, 1000, 100)["events"].size(), 2u);
}
