
#include "memif_tap.h"

memory_traffic_tap_t::~memory_traffic_tap_t()
{
  for (auto p: m_listeners)
    p->on_unregistered_to_memory_traffic_tap(*this);
}

bool memory_traffic_tap_t::register_listener(memory_traffic_listener_t &listener)
{
  for (auto p: m_listeners)
    if (p == &listener)
      return false;

  m_listeners.push_back(&listener);
  listener.on_registered_to_memory_traffic_tap(*this);
  return true;
}

bool memory_traffic_tap_t::unregister_listener(memory_traffic_listener_t &listener)
{
  for (auto it = m_listeners.begin(); it != m_listeners.end(); it++)
    if (*it == &listener)
    {
      m_listeners.erase(it);
      listener.on_unregistered_to_memory_traffic_tap(*this);
      return true;
    }

  return false;
}

memory_traffic_listener_t::~memory_traffic_listener_t()
{
  if (m_registered_memory_traffic_tap)
    m_registered_memory_traffic_tap->unregister_listener(*this);
}

void memory_traffic_listener_t::on_registered_to_memory_traffic_tap(memory_traffic_tap_t &tap)
{
  if (m_registered_memory_traffic_tap)
    throw std::runtime_error("cannot register a memory traffic listener to multiple memory traffic tap");

  m_registered_memory_traffic_tap = &tap;
}

void memory_traffic_listener_t::on_unregistered_to_memory_traffic_tap(memory_traffic_tap_t &tap)
{
  if (!m_registered_memory_traffic_tap || m_registered_memory_traffic_tap != &tap)
    throw std::runtime_error("a memory traffic listener is being unregistered from an unknown tap.");

  m_registered_memory_traffic_tap = nullptr;
}
