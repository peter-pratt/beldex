#include "tx_extra.h"

namespace cryptonote {

tx_extra_contract_source tx_extra_contract_source::create_contract(
                uint8_t const& version,
                const std::string& contract_name,
                const std::string& contract_source,
                const uint64_t& deposit_amount)
{
    tx_extra_contract_source result{};
    result.m_contract_name = contract_name;
    result.m_contract_source = contract_source;
    result.m_deposit_amount = deposit_amount;
    return result;
}

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_buy(
    bns::generic_owner const& owner,
    bns::generic_owner const* backup_owner,
    bns::mapping_type type,
    const crypto::hash& name_hash,
    const std::string& encrypted_value,
    const crypto::hash& prev_txid)
{
  tx_extra_beldex_name_system result{};
  result.fields = bns::extra_field::buy;
  result.owner = owner;

  if (backup_owner)
    result.backup_owner = *backup_owner;
  else
    result.fields = bns::extra_field::buy_no_backup;

  result.type = type;
  result.name_hash = name_hash;
  result.encrypted_value = encrypted_value;
  result.prev_txid = prev_txid;
  return result;
}

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_renew(
    bns::mapping_type type, crypto::hash const &name_hash, crypto::hash const &prev_txid)
{
  assert(is_belnet_type(type) && prev_txid);

  tx_extra_beldex_name_system result{};
  result.fields = bns::extra_field::none;
  result.type = type;
  result.name_hash = name_hash;
  result.prev_txid = prev_txid;
  return result;
}

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_update(
    const bns::generic_signature& signature,
    bns::mapping_type type,
    const crypto::hash& name_hash,
    std::string_view encrypted_value,
    const bns::generic_owner* owner,
    const bns::generic_owner* backup_owner,
    const crypto::hash& prev_txid)
{
  tx_extra_beldex_name_system result{};
  result.signature = signature;
  result.type = type;
  result.name_hash = name_hash;
  result.fields |= bns::extra_field::signature;

  if (encrypted_value.size())
  {
    result.fields |= bns::extra_field::encrypted_value;
    result.encrypted_value = std::string{encrypted_value};
  }

  if (owner)
  {
    result.fields |= bns::extra_field::owner;
    result.owner = *owner;
  }

  if (backup_owner)
  {
    result.fields |= bns::extra_field::backup_owner;
    result.backup_owner = *backup_owner;
  }

  result.prev_txid = prev_txid;
  return result;
}

std::vector<std::string> readable_reasons(uint16_t decomm_reason) {
  std::vector<std::string> results;
  if (decomm_reason & missed_uptime_proof) results.push_back("Missed Uptime Proofs");
  if (decomm_reason & missed_checkpoints) results.push_back("Missed Checkpoints");
  if (decomm_reason & missed_POS_participations) results.push_back("Missed POS Participation");
  if (decomm_reason & storage_server_unreachable) results.push_back("Storage Server Unreachable");
  if (decomm_reason & timestamp_response_unreachable) results.push_back("Unreachable for Timestamp Check");
  if (decomm_reason & timesync_status_out_of_sync) results.push_back("Time out of sync");
  if (decomm_reason & belnet_unreachable) results.push_back("Belnet Unreachable");
  return results;
}

std::vector<std::string> coded_reasons(uint16_t decomm_reason) {
  std::vector<std::string> results;
  if (decomm_reason & missed_uptime_proof) results.push_back("uptime");
  if (decomm_reason & missed_checkpoints) results.push_back("checkpoints");
  if (decomm_reason & missed_POS_participations) results.push_back("POS");
  if (decomm_reason & storage_server_unreachable) results.push_back("storage");
  if (decomm_reason & timestamp_response_unreachable) results.push_back("timecheck");
  if (decomm_reason & timesync_status_out_of_sync) results.push_back("timesync");
  if (decomm_reason & belnet_unreachable) results.push_back("belnet");
  return results;
}

}
