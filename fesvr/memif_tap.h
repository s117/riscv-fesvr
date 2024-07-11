// For tapping memory access traffic on an HTIF memif_t instance.

#ifndef _MEMIF_TAP_H
#define _MEMIF_TAP_H

#include "memif.h"

class memif_tap_listener_t {
public:
  virtual void on_mem_read(addr_t addr, size_t len, void *bytes) = 0;

  virtual void on_mem_write(addr_t addr, size_t len, const void *bytes) = 0;
};

class memif_tap_t : public memif_t {
public:
  memif_tap_t(htif_t *htif, memif_tap_listener_t &listener)
      : memif_t(htif), m_listener(listener) {}

  void read(addr_t addr, size_t len, void *bytes) override {
    memif_t::read(addr, len, bytes);
    m_listener.on_mem_read(addr, len, bytes);
  }

  void write(addr_t addr, size_t len, const void *bytes) override {
    memif_t::write(addr, len, bytes);
    m_listener.on_mem_write(addr, len, bytes);
  }

private:
  memif_tap_listener_t &m_listener;
};

#endif // _MEMIF_TAP_H
