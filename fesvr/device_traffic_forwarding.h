// Classes to support device traffic capturing

#ifndef _TRAFFIC_FORWARDING_H
#define _TRAFFIC_FORWARDING_H

#include "device.h"
#include <cinttypes>
#include <vector>
#include <stdexcept>
#include <atomic>

// Data structure that describes a received HTIF command and how it was serviced.
struct cmd_service_sequence_t
{
  struct mem_transaction_t
  {
    addr_t addr;
    std::vector<uint8_t> data;
    bool is_write;

    explicit mem_transaction_t(addr_t addr, const uint8_t data[], size_t len, bool is_write) : addr(addr), data(data, data + len), is_write(is_write){};
  };
  uint8_t device;
  uint8_t cmd;
  uint64_t payload;
  uint32_t core_id;
  bool responded;
  uint64_t respond_value;
  int htif_exitcode;
  std::vector<mem_transaction_t> mem_transactions;

  ~cmd_service_sequence_t()
  {
    printf("deleting servicing sequence %p.\n", this);
  }

  void append_mem_trans(addr_t addr, const uint8_t data[], size_t len, bool is_write)
  {
    mem_transactions.emplace_back(addr, data, len, is_write);
  }

  static cmd_service_sequence_t *alloc(command_t &cmd, int ref_cnt)
  {
    return new cmd_service_sequence_t(cmd, ref_cnt);
  }

  static cmd_service_sequence_t *alloc(uint8_t device, uint8_t cmd, uint64_t payload, uint32_t core_id, int ref_cnt)
  {
    return new cmd_service_sequence_t(device, cmd, payload, core_id, ref_cnt);
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
      : device(cmd.device()), cmd(cmd.cmd()), payload(cmd.payload()), core_id(cmd.get_coreid()), responded(false), respond_value(0), htif_exitcode(0), ref_cnt(ref_cnt)
  {
    assert(ref_cnt != 0);
  };
  explicit cmd_service_sequence_t(uint8_t device, uint8_t cmd, uint64_t payload, uint32_t core_id, int ref_cnt)
      : device(device), cmd(cmd), payload(payload), core_id(core_id), responded(false), respond_value(0), htif_exitcode(0), ref_cnt(ref_cnt)
  {
    assert(ref_cnt != 0);
  }
};

// An interface of anything that can supply device servicing traffic
class cmd_service_sequence_supplier_t
{
public:
  virtual void get_target_spec(uint32_t &target_memory_mb, uint32_t &target_core_count, uint8_t loaded_elf_sha256[256 / 8]) = 0;

  virtual cmd_service_sequence_t &peek(uint32_t core_id) = 0;

  virtual void pop(uint32_t core_id) = 0;

  virtual std::string identity() = 0;
};

class device_traffic_listener_t;

// An interface of anything that can monitor live device traffic stream
class device_traffic_tap_t
{
protected:
  std::vector<device_traffic_listener_t *> m_device_traffic_listeners;

public:
  virtual ~device_traffic_tap_t();

  virtual bool register_traffic_listener(device_traffic_listener_t &listener);

  virtual bool unregister_traffic_listener(device_traffic_listener_t &listener);
};

// An interface for anyone who is interested in listening live device traffic stream
class device_traffic_listener_t
{
protected:
  device_traffic_tap_t *m_registered_dev_traffic_tap = nullptr;

public:
  virtual ~device_traffic_listener_t();

  virtual void on_registered_to_device_traffic_tap(device_traffic_tap_t &tap);

  virtual void on_unregistered_from_device_traffic_tap(device_traffic_tap_t &tap);

  virtual void on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[256 / 8]) = 0;

  // the listener callback will take the ownership of sequence, and should call sequence::free() upon discarding
  virtual void on_cmd_serviced(cmd_service_sequence_t *sequence) = 0;
};

// A buffer to pipe command service sequence from a device_traffic_tap_t instance to a recorded_composition_t instance
class cmd_service_sequence_buffer_t : public cmd_service_sequence_supplier_t, public device_traffic_listener_t
{
public:
  cmd_service_sequence_buffer_t();

  void get_target_spec(uint32_t &target_memory_mb, uint32_t &target_core_count, uint8_t loaded_elf_sha256[]) override;

  cmd_service_sequence_t &peek(uint32_t core_id) override;

  void pop(uint32_t core_id) override;

  void on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[256 / 8]) override;

  void on_cmd_serviced(cmd_service_sequence_t *sequence) override;

  std::string identity() override;

protected:
  typedef std::queue<cmd_service_sequence_t *> service_seq_queue_t;

  std::vector<service_seq_queue_t> m_per_core_seq_queue;

  bool m_target_spec_obtained;
  uint32_t m_target_memory_mb;
  uint32_t m_target_core_count;
  uint8_t m_loaded_elf_sha256[256 / 8];
};

// A listener that prints information of active traffic to console.
class traffic_debug_listener_t : public device_traffic_listener_t
{
public:
  void on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t elf_sha256[]) override
  {
    printf("Target configuration obtained, memory size = %" PRIu32 "MB, core count = %" PRIu32 ", loaded ELF sha256: ",
           target_memory_mb, target_core_count);
    for (size_t i = 0; i < 256 / 8; i++)
    {
      printf("%02" PRIx8, elf_sha256[i]);
    }
    printf("\n");
  }
  void on_cmd_serviced(cmd_service_sequence_t *sequence) override
  {
    printf(
      "serviced dev 0x%02" PRIx8 " cmd 0x%02" PRIx8 " payload %" PRIx64 " from core %" PRIi32 " (num_mem_trans= %" PRIuMAX ", responded=%s, respond_val=%" PRIx64 ", htif.exitcode=%d).\n",
      sequence->device, sequence->cmd, sequence->payload, sequence->core_id,
      sequence->mem_transactions.size(),
      sequence->responded ? "yes" : "no", sequence->respond_value, sequence->htif_exitcode);
    cmd_service_sequence_t::free(sequence);
  }
};

#endif //_TRAFFIC_FORWARDING_H
