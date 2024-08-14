/** Classes to support unified device traffic capture, replay, and bypassing. */

#ifndef _DEVICE_COMPOSITION_H
#define _DEVICE_COMPOSITION_H

#include "device.h"
#include "memif_tap.h"
#include "device_traffic_capture.h"
#include <atomic>
#include <map>
#include <memory>

template<typename T, T DEFAULT_VALUE>
struct default_value_type_t
{
  T v = DEFAULT_VALUE;
};


/**
 * An abstract class for anything that can service HTIF command made to different devices.
 *
 * It also implements #device_traffic_tap_t to allow monitoring the traffic to all devices under this composition.
 */
class device_composition_t : public device_traffic_tap_t, public memory_traffic_listener_t
{
public:
  /**
   * Constructor.
   * @param htif The HTIF this composition belongs to
   */
  explicit device_composition_t(htif_t &htif);

  ~device_composition_t() override;

  /**
   * Service a HTIF command.
   * @param cmd The HTIF command to be serviced.
   */
  void handle_command(command_t cmd);

  /**
   * Tick all devices.
   */
  void tick();

  /**
   * Get the number of command received from all HARTs.
   * @return Command received count from all HARTs.
   */
  size_t total_cmd_received();

  /**
   * Get the number of command received from a given HART.
   * @param hart_id HART ID.
   * @return Command received count of the specified harts.
   */
  size_t num_cmd_received(uint32_t hart_id);

  /**
   * Reset the number of command received for a given HART.
   * @param hart_id HART ID.
   * @param new_num (Optional) If not reset to zero, this is the new command received count after reset.
   * @return The old count before reset.
   */
  size_t reset_num_cmd_received(uint32_t hart_id, size_t new_num = 0);

  /**
   *
   */
  void on_mem_read(addr_t addr, const uint8_t bytes[], size_t len) override;

  void on_mem_write(addr_t addr, const uint8_t bytes[], size_t len) override;

  virtual void on_target_spec_known(const riscv_target_spec_t &target_spec);

protected:
  virtual void do_handle_command(command_t cmd) = 0;
  virtual void do_tick() = 0;

  void update_htif_exitcode(int exitcode);

  cmd_service_sequence_t *m_active_cmd_sequence;
  htif_t &m_htif;
  std::map<uint32_t, default_value_type_t<size_t, 0>> m_num_handled_commands_per_hart;
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
  recorded_composition_t(htif_t &htif, std::unique_ptr<cmd_service_sequence_supplier_t> source);

  void do_handle_command(command_t cmd) override;

  void do_tick() override;

  static void check_cmd(const cmd_service_sequence_t &service_seq, command_t &cmd);

  void on_target_spec_known(const riscv_target_spec_t &target_spec) override;

  void get_spec_from_traffic_source(riscv_target_spec_t &target_spec_output);

  bool seek(uint32_t hart_id, size_t seq_no);

  std::vector<uint8_t> get_recording_sha256(uint32_t hart_id);

protected:
  std::unique_ptr<cmd_service_sequence_supplier_t> m_traffic_source;
};


#endif //_DEVICE_COMPOSITION_H
