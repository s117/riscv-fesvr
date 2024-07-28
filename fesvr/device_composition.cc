// Classes to support unified device traffic capture, replay, and bypassing.

#include "device_composition.h"
#include "htif.h"
#include "sha256.h"

device_composition_t::device_composition_t(htif_t &htif) : m_active_cmd_sequence(nullptr), m_htif(htif)
{
  m_htif.mem.register_listener(*this);
}

device_composition_t::~device_composition_t()
{
  delete m_active_cmd_sequence;
}

void device_composition_t::handle_command(command_t cmd)
{
  if (m_device_traffic_listeners.empty())
  {
    do_handle_command(cmd);
  }
  else
  {
    if (m_active_cmd_sequence) throw std::runtime_error("device_composition_t can only track one active command.");
    m_active_cmd_sequence = cmd_service_sequence_t::alloc(cmd, m_device_traffic_listeners.size());

    bool cmd_responded = false;
    uint64_t cmd_respond_value = 0;
    command_t::callback_t cmd_respond_cb = cmd.cb;
    // intercept the command response with lambda closure
    cmd.cb = [&cmd_responded, &cmd_respond_value, cmd_respond_cb](uint64_t resp) mutable {
      if (cmd_responded) throw std::runtime_error("device_composition_t cannot track command that sends multiple responds.");
      cmd_responded = true;
      cmd_respond_value = resp;
      cmd_respond_cb(resp);
    };

    do_handle_command(cmd);

    m_active_cmd_sequence->responded = cmd_responded;
    m_active_cmd_sequence->respond_value = cmd_respond_value;
    m_active_cmd_sequence->htif_exitcode = m_htif.exitcode;

    for (auto l: m_device_traffic_listeners)
    {
      l->on_cmd_serviced(m_active_cmd_sequence);
    }
    m_active_cmd_sequence = nullptr;
  }
  ++m_num_handled_commands_per_core[cmd.get_coreid()].v;
}

void device_composition_t::tick()
{
  do_tick();
}

void device_composition_t::update_target_spec(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[])
{
  for (auto l: m_device_traffic_listeners)
  {
    l->on_target_spec_obtained(target_memory_mb, target_core_count, loaded_elf_sha256);
  }
}

size_t device_composition_t::num_cmd_received()
{
  size_t total = 0;
  for (auto pair: m_num_handled_commands_per_core)
  {
    total += pair.second.v;
  }
  return total;
}

size_t device_composition_t::num_cmd_received(size_t core_id)
{
  return m_num_handled_commands_per_core[core_id].v;
}

void device_composition_t::on_mem_read(addr_t addr, const uint8_t *bytes, size_t len)
{
  if (m_active_cmd_sequence)
    m_active_cmd_sequence->append_mem_trans(addr, (const uint8_t *) bytes, len, false);
}

void device_composition_t::on_mem_write(addr_t addr, const uint8_t *bytes, size_t len)
{
  if (m_active_cmd_sequence)
    m_active_cmd_sequence->append_mem_trans(addr, (const uint8_t *) bytes, len, true);
}

void device_composition_t::update_htif_exitcode(int exitcode) { m_htif.exitcode = exitcode; }


real_composition_t::real_composition_t(htif_t &htif) : device_composition_t(htif) {}

void real_composition_t::do_handle_command(command_t cmd)
{
  m_device_list.handle_command(cmd);
}

void real_composition_t::do_tick()
{
  m_device_list.tick();
}

void real_composition_t::register_device(device_t &dev)
{
  m_device_list.register_device(&dev);
}


recorded_composition_t::recorded_composition_t(htif_t &htif, cmd_service_sequence_supplier_t *source, std::vector<size_t> &&initial_handled_cmds)
    : device_composition_t(htif), m_traffic_source(source)
{
  for (uint32_t i = 0; i < initial_handled_cmds.size(); i++)
  {
    m_num_handled_commands_per_core[i].v = initial_handled_cmds[i];
  }
}

void recorded_composition_t::do_handle_command(command_t cmd)
{
  auto &service_seq = m_traffic_source->peek(cmd.get_coreid());
  check_cmd(service_seq, cmd);
  std::vector<uint8_t> read_buf;
  for (auto &mem_transaction: service_seq.mem_transactions)
  {
    if (mem_transaction.is_write)
    {
      m_htif.memif().write(mem_transaction.addr, mem_transaction.data.size(), &mem_transaction.data[0]);
    }
    else
    {
      read_buf.reserve(mem_transaction.data.size());
      m_htif.memif().read(mem_transaction.addr, mem_transaction.data.size(), &read_buf[0]);
      if (memcmp(&mem_transaction.data[0], &read_buf[0], mem_transaction.data.size()) != 0)
      {
        throw replay_error("the data read from target system doesn't match the recorded servicing sequence.");
      }
    }
  }

  update_htif_exitcode(service_seq.htif_exitcode);

  if (service_seq.responded)
  {
    cmd.respond(service_seq.respond_value);
  }
  m_traffic_source->pop(cmd.get_coreid());
}

void recorded_composition_t::do_tick() {}

void recorded_composition_t::check_cmd(const cmd_service_sequence_t &service_seq, command_t &cmd)
{
  if (service_seq.device != cmd.device()) { throw replay_error("'device' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.cmd != cmd.cmd()) { throw replay_error("'cmd' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.core_id != cmd.get_coreid()) { throw replay_error("'core_id' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.payload != cmd.payload()) { throw replay_error("'payload' field of the incoming command doesn't match the recorded servicing sequence."); }
}

void recorded_composition_t::update_target_spec(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[256 / 8])
{
  uint32_t recorded_target_memory_mb{};
  uint32_t recorded_target_core_count{};
  uint8_t recorded_loaded_elf_sha256[256 / 8]{};
  m_traffic_source->get_target_spec(recorded_target_memory_mb, recorded_target_core_count, recorded_loaded_elf_sha256);
  if (recorded_target_memory_mb != target_memory_mb)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to have " + std::to_string(recorded_target_memory_mb) +
      "MB memory, but this system has " + std::to_string(target_memory_mb) + "MB.");
  }

  if (recorded_target_core_count != target_core_count)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to have " + std::to_string(recorded_target_core_count) +
      " core(s), but this system has " + std::to_string(target_core_count) + " core(s).");
  }

  if (memcmp(recorded_loaded_elf_sha256, loaded_elf_sha256, sizeof(recorded_loaded_elf_sha256)) != 0)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to load an ELF with SHA256 " + SHA256::bytesHashToStringHash(recorded_loaded_elf_sha256) +
      ", but this system loaded an ELF with SHA256 " + SHA256::bytesHashToStringHash(loaded_elf_sha256) + ".");
  }

  device_composition_t::update_target_spec(target_memory_mb, target_core_count, loaded_elf_sha256);
}
