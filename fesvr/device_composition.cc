// Classes to support unified device traffic capture, replay, and bypassing.

#include "device_composition.h"
#include "htif.h"

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
    uint64_t cmd_response_value = 0;
    command_t::callback_t cmd_respond_cb = cmd.cb;
    // intercept the command response with lambda closure
    cmd.cb = [&cmd_responded, &cmd_response_value, cmd_respond_cb](uint64_t resp) mutable {
      if (cmd_responded) throw std::runtime_error("device_composition_t cannot track command that sends multiple responds.");
      cmd_responded = true;
      cmd_response_value = resp;
      cmd_respond_cb(resp);
    };

    do_handle_command(cmd);

    m_active_cmd_sequence->responded = cmd_responded;
    m_active_cmd_sequence->response_value = cmd_response_value;
    m_active_cmd_sequence->htif_exitcode = m_htif.exitcode;

    for (auto l: m_device_traffic_listeners)
    {
      l->on_cmd_serviced(m_active_cmd_sequence);
    }
    m_active_cmd_sequence = nullptr;
  }
  ++m_num_handled_commands_per_hart[cmd.get_hart_id()].v;
}

void device_composition_t::tick()
{
  do_tick();
}

void device_composition_t::on_target_spec_known(const riscv_target_spec_t &target_spec)
{
  for (auto l: m_device_traffic_listeners)
  {
    l->on_target_spec_known(target_spec);
  }
}

size_t device_composition_t::total_cmd_received()
{
  size_t total = 0;
  for (auto pair: m_num_handled_commands_per_hart)
  {
    total += pair.second.v;
  }
  return total;
}

size_t device_composition_t::num_cmd_received(uint32_t hart_id)
{
  return m_num_handled_commands_per_hart[hart_id].v;
}

size_t device_composition_t::reset_num_cmd_received(uint32_t hart_id, size_t new_num)
{
  auto &num_cmd_received = m_num_handled_commands_per_hart[hart_id];
  auto old_num = num_cmd_received.v;
  num_cmd_received.v = new_num;
  return old_num;
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


recorded_composition_t::recorded_composition_t(htif_t &htif, std::unique_ptr<cmd_service_sequence_supplier_t> source)
    : device_composition_t(htif), m_traffic_source(std::move(source))
{
}

void recorded_composition_t::do_handle_command(command_t cmd)
{
  bool pkt_avail = m_traffic_source->pop(cmd.get_hart_id());
  if (!pkt_avail)
    throw replay_error("the recorded traffic source depleted when handling the " + std::to_string(num_cmd_received(cmd.get_hart_id())) + "th command for HART " + std::to_string(cmd.get_hart_id()));

  auto &service_seq = m_traffic_source->peek(cmd.get_hart_id());
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
    cmd.respond(service_seq.response_value);
  }
}

void recorded_composition_t::do_tick() {}

void recorded_composition_t::check_cmd(const cmd_service_sequence_t &service_seq, command_t &cmd)
{
  if (service_seq.device != cmd.device()) { throw replay_error("'device' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.cmd != cmd.cmd()) { throw replay_error("'cmd' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.hart_id != cmd.get_hart_id()) { throw replay_error("'hart_id' field of the incoming command doesn't match the recorded servicing sequence."); }
  if (service_seq.payload != cmd.payload()) { throw replay_error("'payload' field of the incoming command doesn't match the recorded servicing sequence."); }
}

void recorded_composition_t::on_target_spec_known(const riscv_target_spec_t &target_spec)
{
  riscv_target_spec_t expected_target_spec{};
  m_traffic_source->get_target_spec(expected_target_spec);
  if (expected_target_spec.mem_sz_mb != target_spec.mem_sz_mb)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to have " + std::to_string(expected_target_spec.mem_sz_mb) +
      "MB memory, but this system has " + std::to_string(target_spec.mem_sz_mb) + "MB.");
  }

  if (expected_target_spec.num_hart != target_spec.num_hart)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to have " + std::to_string(expected_target_spec.num_hart) +
      " HART(s), but this system has " + std::to_string(target_spec.num_hart) + " HART(s).");
  }

  if (memcmp(expected_target_spec.load_elf_sha256, target_spec.load_elf_sha256, sizeof(target_spec.load_elf_sha256)) != 0)
  {
    throw std::runtime_error(
      "incompatible FESVR device traffic recording: the recording (" + m_traffic_source->identity() + ") expects target to load an ELF with SHA256 " +
      crypto_digest_t::to_string(expected_target_spec.load_elf_sha256, sizeof(expected_target_spec.load_elf_sha256)) +
      ", but this system loaded an ELF with SHA256 " +
      crypto_digest_t::to_string(target_spec.load_elf_sha256, sizeof(target_spec.load_elf_sha256)) + ".");
  }

  device_composition_t::on_target_spec_known(target_spec);
}

void recorded_composition_t::get_spec_from_traffic_source(riscv_target_spec_t &target_spec_output)
{
  m_traffic_source->get_target_spec(target_spec_output);
}

bool recorded_composition_t::seek(uint32_t hart_id, size_t seq_no)
{
  bool succ = m_traffic_source->seek(hart_id, seq_no);
  if (succ) reset_num_cmd_received(hart_id, seq_no);
  return succ;
}

std::vector<uint8_t> recorded_composition_t::get_recording_sha256(uint32_t hart_id)
{
  return m_traffic_source->get_recording_sha256(hart_id);
}
