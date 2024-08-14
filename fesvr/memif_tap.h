/** For monitoring memory access traffic on an HTIF memif_t instance. */

#ifndef _MEMIF_TAP_H
#define _MEMIF_TAP_H

#include "memif.h"
#include <vector>

class memory_traffic_tap_t;

/**
 * An interface for anyone who is interested in listening memory traffic broadcast from a #memory_traffic_tap_t.
 */
class memory_traffic_listener_t
{
protected:
  memory_traffic_tap_t *m_registered_memory_traffic_tap = nullptr; /** The traffic tap this listener is registered to. */

public:
  /**
   * Remove this listener from the registered tap (if exist) before being destroyed.
   */
  virtual ~memory_traffic_listener_t();

  /**
   * Event callback: newly registered to a tap. A listener can only be registered to one tap at a time.
   * This base implementation will save the tap reference to
   * #m_registered_memory_traffic_tap so that it can automatically unregister itself when destroyed.
   * @param tap Reference to the tap this listener is registered to.
   * @throw std::runtime_error When registered to multiple taps at a time.
   */
  virtual void on_registered_to_memory_traffic_tap(memory_traffic_tap_t &memif_tap);

  /**
   * Event callback: unregistered from a tap.
   * This base implementation will clear the #m_registered_memory_traffic_tap.
   * @param tap Reference to the tap this listener is unregistered from.
   * @throw std::runtime_error When unregistered from a tap that was never registered to.
   */
  virtual void on_unregistered_to_memory_traffic_tap(memory_traffic_tap_t &memif_tap);

  /**
   * Event callback: a target memory read just completed.
   * @param addr The physical address being read from.
   * @param bytes Data read from the target.
   * @param len Length of the data.
   */
  virtual void on_mem_read(addr_t addr, const uint8_t bytes[], size_t len) = 0;

  /**
   * Event callback: a target memory write just completed.
   * @param addr The physical address being written to.
   * @param bytes Data written to the target.
   * @param len Length of the data.
   */
  virtual void on_mem_write(addr_t addr, const uint8_t bytes[], size_t len) = 0;
};

/**
 * An interface of anything that can broadcast memory traffic.
 */
class memory_traffic_tap_t
{
protected:
  /**
   * Array of registered listeners. The implementation is responsible for broadcasting
   * the the memory traffic to all registered listeners by calling the proper event callback.
   */
  std::vector<memory_traffic_listener_t *> m_listeners;

public:
  /**
   * Notifying all listeners that they are unregistered before being destroyed.
   */
  virtual ~memory_traffic_tap_t();

  /**
   * Register a listener to this tap
   * @param listener Reference to the listener to be registered.
   * @return Whether the registration was succeed.
   */
  virtual bool register_listener(memory_traffic_listener_t &listener);

  /**
   * Unregister a listener from this tap.
   * @param listener Reference to the listener to be unregistered.
   * @return Whether the unregistration was succeed.
   */
  virtual bool unregister_listener(memory_traffic_listener_t &listener);
};

/**
 * A #memif_t with #memory_traffic_tap_t implemented, so that its traffic can be monitored.
 */
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
