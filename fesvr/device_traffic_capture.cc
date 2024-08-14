// Classes to support device traffic capturing

#include "device_traffic_capture.h"
#include "device_composition.h"

device_traffic_tap_t::~device_traffic_tap_t()
{
  for (auto p: m_device_traffic_listeners)
  {
    p->on_unregistered_from_device_traffic_tap(*this);
  }
}

bool device_traffic_tap_t::register_traffic_listener(device_traffic_listener_t &listener)
{
  for (auto p: m_device_traffic_listeners)
  {
    if (p == &listener)
      return false;
  }
  m_device_traffic_listeners.push_back(&listener);
  listener.on_registered_to_device_traffic_tap(*this);
  return true;
}

bool device_traffic_tap_t::unregister_traffic_listener(device_traffic_listener_t &listener)
{
  for (auto it = m_device_traffic_listeners.begin(); it != m_device_traffic_listeners.end(); it++)
  {
    if (*it == &listener)
    {
      m_device_traffic_listeners.erase(it);
      listener.on_unregistered_from_device_traffic_tap(*this);
      return true;
    }
  }
  return false;
}

bool cmd_service_sequence_supplier_t::seek(uint32_t hart_id, size_t seq_no)
{
  throw std::runtime_error("The current cmd sequence supplier \"" + identity() + "\" doesn't support seek() operation.");
}

std::vector<uint8_t> cmd_service_sequence_supplier_t::get_recording_sha256(uint32_t hart_id)
{
  throw std::runtime_error("The current cmd sequence supplier \"" + identity() + "\" doesn't support get_recording_sha256() operation.");
}

device_traffic_listener_t::~device_traffic_listener_t()
{
  if (m_registered_dev_traffic_tap)
  {
    m_registered_dev_traffic_tap->unregister_traffic_listener(*this);
  }
}

void device_traffic_listener_t::on_registered_to_device_traffic_tap(device_traffic_tap_t &tap)
{
  if (m_registered_dev_traffic_tap)
  {
    throw std::runtime_error("cannot register a device traffic listener to multiple device traffic tap");
  }
  m_registered_dev_traffic_tap = &tap;
}

void device_traffic_listener_t::on_unregistered_from_device_traffic_tap(device_traffic_tap_t &tap)
{
  if (!m_registered_dev_traffic_tap || m_registered_dev_traffic_tap != &tap)
  {
    throw std::runtime_error("a device traffic listener is being unregistered from an unknown tap.");
  }
  m_registered_dev_traffic_tap = nullptr;
}


cmd_service_sequence_buffer_t::cmd_service_sequence_buffer_t()
    : m_target_spec_obtained(false)
{
  memset(m_target_spec.load_elf_sha256, 0, sizeof(m_target_spec.load_elf_sha256));
}

cmd_service_sequence_buffer_t::cmd_service_sequence_buffer_t(device_traffic_tap_t &source) : cmd_service_sequence_buffer_t()
{
  source.register_traffic_listener(*this);
}

cmd_service_sequence_t &cmd_service_sequence_buffer_t::peek(uint32_t hart_id)
{
  assert(hart_id < m_per_hart_seq_queue.size());
  if (!m_target_spec_obtained)
  {
    throw std::runtime_error("command servicing queue buffer is not ready for peek!");
  }

  return *m_per_hart_seq_queue_head[hart_id];
}

bool cmd_service_sequence_buffer_t::pop(uint32_t hart_id)
{
  assert(hart_id < m_per_hart_seq_queue.size());
  if (m_per_hart_seq_queue[hart_id].empty())
  {
    return false;
  }
  cmd_service_sequence_t::free(m_per_hart_seq_queue_head[hart_id]);
  m_per_hart_seq_queue_head[hart_id] = m_per_hart_seq_queue[hart_id].front();
  m_per_hart_seq_queue[hart_id].pop();
  return true;
}

void cmd_service_sequence_buffer_t::on_cmd_serviced(cmd_service_sequence_t *sequence)
{
  assert(sequence->hart_id < m_per_hart_seq_queue.size());
  m_per_hart_seq_queue[sequence->hart_id].push(sequence);
}

void cmd_service_sequence_buffer_t::on_target_spec_known(const riscv_target_spec_t &target_spec)
{
  m_target_spec = target_spec;
  m_per_hart_seq_queue_head.resize(target_spec.num_hart);
  m_per_hart_seq_queue.resize(target_spec.num_hart);
  m_target_spec_obtained = true;
}

void cmd_service_sequence_buffer_t::get_target_spec(riscv_target_spec_t &target_spec_output)
{
  if (!m_target_spec_obtained)
  {
    throw std::runtime_error("command servicing queue buffer didn't received target spec yet!");
  }
  target_spec_output = m_target_spec;
}

std::string cmd_service_sequence_buffer_t::identity()
{
  return "traffic forwarded from main FESVR";
}
