// For tapping memory access traffic on an HTIF memif_t instance.

#ifndef _MEMIF_TAP_H
#define _MEMIF_TAP_H

#include "memif.h"
#include <vector>

class memory_traffic_listener_t;

class memory_traffic_tap_t
{
protected:
  std::vector<memory_traffic_listener_t *> m_listeners;

public:
  virtual ~memory_traffic_tap_t();

  virtual bool register_listener(memory_traffic_listener_t &listener);

  virtual bool unregister_listener(memory_traffic_listener_t &listener);
};

class memory_traffic_listener_t
{
protected:
  memory_traffic_tap_t *m_registered_memory_traffic_tap = nullptr;

public:
  virtual ~memory_traffic_listener_t();

  virtual void on_registered_to_memory_traffic_tap(memory_traffic_tap_t &memif_tap);

  virtual void on_unregistered_to_memory_traffic_tap(memory_traffic_tap_t &memif_tap);

  virtual void on_mem_read(addr_t addr, const uint8_t bytes[], size_t len) = 0;

  virtual void on_mem_write(addr_t addr, const uint8_t bytes[], size_t len) = 0;
};

class memif_tap_t : public memory_traffic_tap_t, public memif_t
{
public:
  explicit memif_tap_t(htif_t &htif) : memif_t(&htif) {}

  void read(addr_t addr, size_t len, void *bytes) override
  {
    memif_t::read(addr, len, bytes);
    for (auto *listener: m_listeners)
    {
      listener->on_mem_read(addr, (const uint8_t *) bytes, len);
    }
  }

  void write(addr_t addr, size_t len, const void *bytes) override
  {
    memif_t::write(addr, len, bytes);
    for (auto *listener: m_listeners)
    {
      listener->on_mem_write(addr, (const uint8_t *) bytes, len);
    }
  }
};

#endif // _MEMIF_TAP_H
