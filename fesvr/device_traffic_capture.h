/** Classes to support device traffic capturing. */

#ifndef _TRAFFIC_FORWARDING_H
#define _TRAFFIC_FORWARDING_H

#include "device.h"
#include <cinttypes>
#include <vector>
#include <stdexcept>
#include <atomic>
#include "fesvr_logging.h"
#include "crypto_digest.h"

/**
 * Basic specs of a RISCV target.
 * It describe the important specs of the target. If two system match on these specs, the device traffic captured on
 * one system can be replayed on another system to facilitate target execution without emulating the FESVR device.
 */
struct riscv_target_spec_t
{
  uint32_t num_hart;  /** Number of HART. */
  uint32_t mem_sz_mb; /** Size of physical memory, in MByte. */
  uint8_t load_elf_sha256[32] /** SHA256 of the ELF loaded by FESVR. */;
};

/**
 * Data structure describing how a received HTIF command was serviced.
 * The captured device traffic will be converted to this structure by command granularity,
 * then broadcast to all traffic listeners.
 */
struct cmd_service_sequence_t
{
  /**
   * Data structure describing a memory access transaction made to the RISCV target memory.
   */
  struct mem_transaction_t
  {
    addr_t addr;               /** The physical address accessed. */
    std::vector<uint8_t> data; /** Array of data read from, or written to the target. */
    bool is_write;             /** Whether this access is a write to the target memory. */

    explicit mem_transaction_t(addr_t addr, const uint8_t data[], size_t len, bool is_write) : addr(addr), data(data, data + len), is_write(is_write){};
  };
  uint8_t device;                                  /** The "device" field of the original command. */
  uint8_t cmd;                                     /** The "cmd" field of the original command. */
  uint64_t payload;                                /** The "payload" field of the original command. */
  uint32_t hart_id;                                /** ID of the HART who initiated the original command. */
  bool responded;                                  /** Did this device command end with a respond? (a write to HART's fromhost CSR) */
  uint64_t response_value;                         /** If the command got a response, this is the responded value. */
  int htif_exitcode;                               /** The "htif_exitcode" field of htif_t after this command was serviced. */
  std::vector<mem_transaction_t> mem_transactions; /** An array of all the memory transactions involved to service this command. */

  ~cmd_service_sequence_t()
  {
    fesvr_log_verbose(stderr, "deleting servicing sequence %p.\n", this);
  }

  /**
   * Append a memory access transaction to this sequence.
   * @param addr The physical memory address.
   * @param data Array of the data read from the target / written to the target.
   * @param len Length of the access.
   * @param is_write Whether the access is a memory write.
   */
  void append_mem_trans(addr_t addr, const uint8_t data[], size_t len, bool is_write)
  {
    mem_transactions.emplace_back(addr, data, len, is_write);
  }

  static cmd_service_sequence_t *alloc(command_t &cmd, int ref_cnt)
  {
    return new cmd_service_sequence_t(cmd, ref_cnt);
  }

  static cmd_service_sequence_t *alloc(uint8_t device, uint8_t cmd, uint64_t payload, uint32_t hart_id, int ref_cnt)
  {
    return new cmd_service_sequence_t(device, cmd, payload, hart_id, ref_cnt);
  }

  static void free(cmd_service_sequence_t *&&seq)
  {
    cmd_service_sequence_t::free(seq);
  }

  static void free(cmd_service_sequence_t *&seq)
  {
    if (seq == nullptr) return;
    int new_ref_cnt = --seq->ref_cnt;
    assert(new_ref_cnt >= 0);
    if (new_ref_cnt == 0) delete seq;
    seq = nullptr;
  }

protected:
  std::atomic<int> ref_cnt;
  explicit cmd_service_sequence_t(command_t &cmd, int ref_cnt)
      : device(cmd.device()), cmd(cmd.cmd()), payload(cmd.payload()), hart_id(cmd.get_hart_id()), responded(false), response_value(0), htif_exitcode(0), ref_cnt(ref_cnt)
  {
    assert(ref_cnt != 0);
  };
  explicit cmd_service_sequence_t(uint8_t device, uint8_t cmd, uint64_t payload, uint32_t hart_id, int ref_cnt)
      : device(device), cmd(cmd), payload(payload), hart_id(hart_id), responded(false), response_value(0), htif_exitcode(0), ref_cnt(ref_cnt)
  {
    assert(ref_cnt != 0);
  }
};

/**
 * An interface of #cmd_service_sequence_t object supplier.
 * Each HARTs has their own supplying queue, and the interface only exposes the HEAD of the queue. The implementation of this interface
 * can optionally implement the seek() operation to support random access.
 */
class cmd_service_sequence_supplier_t
{
public:
  virtual ~cmd_service_sequence_supplier_t() = default;

  /**
   * Get the target spec of the system where the #cmd_service_sequence_t was captured.
   * @param target_spec_output Reference to a writable #riscv_target_spec_t structure to receive the specs.
   */
  virtual void get_target_spec(riscv_target_spec_t &target_spec_output) = 0;

  /**
   * Get the HEAD of a HART's queue.
   * @param hart_id HART ID.
   * @return Reference to a #cmd_service_sequence_t object. The lifetime of this returned object is managed by the supplier. It is valid until a call to pop().
   */
  virtual cmd_service_sequence_t &peek(uint32_t hart_id) = 0;

  /**
   * Pop the HEAD of a HART's queue. Any reference returned by peek() should be considered invalid after a call to pop().
   * @param hart_id HART ID.
   * @return Whether the queue is empty after the pop.
   */
  virtual bool pop(uint32_t hart_id) = 0;

  /**
   * Get a string describe the identity of this supplier.
   * @return Identity string.
   */
  virtual std::string identity() = 0;

  /**
   * (Optional) Seek to a specific position in a HART's queue. Future pop() will continue from the new position.
   * Note this method doesn't update the current HEAD. For peek() to return the object at the new position, a pop() is required first.
   * @param hart_id HART ID.
   * @param seq_no The index of the new position, start from 0.
   * @return Whether the seek operation was performed successfully.
   */
  virtual bool seek(uint32_t hart_id, size_t seq_no);

  /**
   * (Optional) Get a SHA256 hash representing the HART's entire queue (from the first command since target boot to the last command before target exit).
   * @param hart_id HART ID.
   * @return SHA256 hash.
   */
  virtual std::vector<uint8_t> get_recording_sha256(uint32_t hart_id);
};


class device_traffic_tap_t;

/**
 * An interface for anyone who is interested in listening device traffic broadcast from a #device_traffic_tap_t.
 */
class device_traffic_listener_t
{
protected:
  device_traffic_tap_t *m_registered_dev_traffic_tap = nullptr; /** The traffic tap this listener is registered to. */

public:
  /**
   * Remove this listener from the registered tap (if exist) before being destroyed.
   */
  virtual ~device_traffic_listener_t();

  /**
   * Event callback: newly registered to a tap. A listener can only be registered to one tap at a time.
   * This base implementation will save the tap reference to
   * #m_registered_dev_traffic_tap so that it can automatically unregister itself when destroyed.
   * @param tap Reference to the tap this listener is registered to.
   * @throw std::runtime_error When registered to multiple taps at a time.
   */
  virtual void on_registered_to_device_traffic_tap(device_traffic_tap_t &tap);

  /**
   * Event callback: unregistered from a tap.
   * This base implementation will clear the #m_registered_dev_traffic_tap.
   * @param tap Reference to the tap this listener is unregistered from.
   * @throw std::runtime_error When unregistered from a tap that was never registered to.
   */
  virtual void on_unregistered_from_device_traffic_tap(device_traffic_tap_t &tap);

  /**
   * Event callback: the target specs are known.
   * @param target_spec #riscv_target_spec_t structure describing the spec of target.
   */
  virtual void on_target_spec_known(const riscv_target_spec_t &target_spec) = 0;

  /**
   * Event callback: a received device command has been serviced.
   * This callback takes the ownership of sequence, and should call sequence::free() upon discarding.
   * Note that the sequence might be co-owned by many listeners. Each listener must use sequence::free() to relinquish
   * the ownership. The object will be freed upon all owners has called sequence::free().
   * @param sequence
   */
  virtual void on_cmd_serviced(cmd_service_sequence_t *sequence) = 0;
};

/**
 * An interface of anything that can broadcast device traffic.
 */
class device_traffic_tap_t
{
protected:
  /**
   * Array of registered listeners. The implementation is responsible for broadcasting
   * the the device traffic to all registered listeners by calling the proper event callback.
   */
  std::vector<device_traffic_listener_t *> m_device_traffic_listeners;

public:
  /**
   * Notifying all listeners that they are unregistered before being destroyed.
   */
  virtual ~device_traffic_tap_t();

  /**
   * Register a listener to this tap
   * @param listener Reference to the listener to be registered.
   * @return Whether the registration was succeed.
   */
  virtual bool register_traffic_listener(device_traffic_listener_t &listener);

  /**
   * Unregister a listener from this tap.
   * @param listener Reference to the listener to be unregistered.
   * @return Whether the unregistration was succeed.
   */
  virtual bool unregister_traffic_listener(device_traffic_listener_t &listener);
};


/**
 * A buffer to pipe command service sequence.
 * It takes traffic from a #device_traffic_tap_t instance, and present the buffered traffic as a #cmd_service_sequence_supplier_t instance.
 */
class cmd_service_sequence_buffer_t : public device_traffic_listener_t, public cmd_service_sequence_supplier_t
{
public:
  cmd_service_sequence_buffer_t();

  /**
   * Construct a #cmd_service_sequence_buffer_t
   * @param source The source of the traffic to buffer.
   */
  explicit cmd_service_sequence_buffer_t(device_traffic_tap_t &source);

  void get_target_spec(riscv_target_spec_t &target_spec_output) override;

  cmd_service_sequence_t &peek(uint32_t hart_id) override;

  bool pop(uint32_t hart_id) override;

  void on_target_spec_known(const riscv_target_spec_t &target_spec) override;

  void on_cmd_serviced(cmd_service_sequence_t *sequence) override;

  std::string identity() override;

protected:
  typedef std::queue<cmd_service_sequence_t *> service_seq_queue_t;

  std::vector<cmd_service_sequence_t *> m_per_hart_seq_queue_head;
  std::vector<service_seq_queue_t> m_per_hart_seq_queue;

  bool m_target_spec_obtained;
  riscv_target_spec_t m_target_spec;
};

/**
 * A listener that prints information of active traffic to console.
 */
class traffic_debug_listener_t : public device_traffic_listener_t
{
public:
  void on_target_spec_known(const riscv_target_spec_t &target_spec) override
  {
    fesvr_log_verbose(stderr, "Target configuration obtained, memory size = %" PRIu32 "MB, HART count = %" PRIu32 ", loaded ELF sha256: %s\n",
                      target_spec.mem_sz_mb, target_spec.num_hart, crypto_digest_t::to_string(target_spec.load_elf_sha256, sizeof(target_spec.load_elf_sha256)).c_str());
  }
  void on_cmd_serviced(cmd_service_sequence_t *sequence) override
  {
    fesvr_log_verbose(
      stderr,
      "Serviced dev 0x%02" PRIx8 " cmd 0x%02" PRIx8 " payload %" PRIx64 " from HART %" PRIi32 " (num_mem_trans= %" PRIuMAX ", responded=%s, respond_val=%" PRIx64 ", htif.exitcode=%d).\n",
      sequence->device, sequence->cmd, sequence->payload, sequence->hart_id,
      sequence->mem_transactions.size(),
      sequence->responded ? "yes" : "no", sequence->response_value, sequence->htif_exitcode);
    cmd_service_sequence_t::free(sequence);
  }
};

#endif //_TRAFFIC_FORWARDING_H
