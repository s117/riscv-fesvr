// Classes to support device traffic capturing

#include "device_traffic_forwarding.h"

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
    : m_target_spec_obtained(false), m_target_memory_mb(0), m_target_core_count(0), m_loaded_elf_sha256()
{
  memset(m_loaded_elf_sha256, 0, sizeof(m_loaded_elf_sha256));
}

cmd_service_sequence_t &cmd_service_sequence_buffer_t::peek(uint32_t core_id)
{
  if (!m_target_spec_obtained)
  {
    throw std::runtime_error("command servicing queue buffer is not ready for peek!");
  }

  if (core_id >= m_per_core_seq_queue.size() || m_per_core_seq_queue[core_id].empty())
  {
    throw std::runtime_error("command servicing sequence buffer underflow!");
  }
  return *m_per_core_seq_queue[core_id].front();
}

void cmd_service_sequence_buffer_t::pop(uint32_t core_id)
{
  if (core_id >= m_per_core_seq_queue.size() || m_per_core_seq_queue[core_id].empty())
  {
    throw std::runtime_error("command servicing sequence buffer underflow!");
  }
  cmd_service_sequence_t *popped_seq = m_per_core_seq_queue[core_id].front();
  m_per_core_seq_queue[core_id].pop();
  cmd_service_sequence_t::free(popped_seq);
}

void cmd_service_sequence_buffer_t::on_cmd_serviced(cmd_service_sequence_t *sequence)
{
  assert(sequence->core_id >= m_per_core_seq_queue.size());
  m_per_core_seq_queue[sequence->core_id].push(sequence);
}

void cmd_service_sequence_buffer_t::on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[])
{
  m_target_memory_mb = target_memory_mb;
  m_target_core_count = target_core_count;
  memcpy(m_loaded_elf_sha256, loaded_elf_sha256, sizeof(m_loaded_elf_sha256));
  m_per_core_seq_queue.resize(target_core_count);
  m_target_spec_obtained = true;
}

void cmd_service_sequence_buffer_t::get_target_spec(uint32_t &target_memory_mb, uint32_t &target_core_count, uint8_t loaded_elf_sha256[256 / 8])
{
  if (!m_target_spec_obtained)
  {
    throw std::runtime_error("command servicing queue buffer didn't received target spec yet!");
  }
  target_memory_mb = m_target_memory_mb;
  target_core_count = m_target_core_count;
  memcpy(loaded_elf_sha256, m_loaded_elf_sha256, sizeof(m_loaded_elf_sha256));
}

std::string cmd_service_sequence_buffer_t::identity()
{
  return "traffic forwarded from main FESVR";
}
