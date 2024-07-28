// Classes to support unified device traffic capture, replay, and bypassing.

#ifndef _DEVICE_COMPOSITION_H
#define _DEVICE_COMPOSITION_H

#include "device.h"
#include "memif_tap.h"
#include "device_traffic_forwarding.h"
#include <atomic>
#include <map>
#include <memory>

template<typename T, T DEFAULT_VALUE>
struct default_value_type_t
{
  T v = DEFAULT_VALUE;
};


// An interface that can service incoming device command requests
class device_composition_t : public device_traffic_tap_t, public memory_traffic_listener_t
{
public:
  explicit device_composition_t(htif_t &htif);

  ~device_composition_t() override;

  void handle_command(command_t cmd);

  void tick();

  size_t num_cmd_received();

  size_t num_cmd_received(size_t core_id);

  void on_mem_read(addr_t addr, const uint8_t bytes[], size_t len) override;

  void on_mem_write(addr_t addr, const uint8_t bytes[], size_t len) override;

  virtual void update_target_spec(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[256 / 8]);

protected:
  virtual void do_handle_command(command_t cmd) = 0;
  virtual void do_tick() = 0;

  void update_htif_exitcode(int exitcode);

  cmd_service_sequence_t *m_active_cmd_sequence;
  htif_t &m_htif;
  std::map<uint32_t, default_value_type_t<size_t, 0>> m_num_handled_commands_per_core;
};

// A real composition uses real devices to service incoming device command requests
class real_composition_t : public device_composition_t
{
public:
  explicit real_composition_t(htif_t &htif);

  void do_handle_command(command_t cmd) override;

  void do_tick() override;

  void register_device(device_t &dev);

protected:
  device_list_t m_device_list;
};

class recorded_composition_t : public device_composition_t
{
  class replay_error : public std::runtime_error
  {
  public:
    explicit replay_error(std::string &&s) : std::runtime_error(s) {}
  };

public:
  recorded_composition_t(htif_t &htif, cmd_service_sequence_supplier_t *source, std::vector<size_t> &&initial_handled_cmds);

  void do_handle_command(command_t cmd) override;

  void do_tick() override;

  static void check_cmd(const cmd_service_sequence_t &service_seq, command_t &cmd);

  void update_target_spec(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[256 / 8]) override;

protected:
  std::unique_ptr<cmd_service_sequence_supplier_t> m_traffic_source;
};


#endif //_DEVICE_COMPOSITION_H
