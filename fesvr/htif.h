// See LICENSE for license details.

#ifndef __HTIF_H
#define __HTIF_H

#include "checkpoint_format.h"
#include "memif_tap.h"
#include "syscall.h"
#include "device_composition.h"
#include "device_traffic_persistent.h"
#include "ckpt_desc_reader.h"
#include "hart_execution_controller.h"
#include <string.h>
#include <vector>
#include <cinttypes>
#include <fstream>
#include <memory.h>

class htif_t
{
 public:
  htif_t(const std::vector<std::string>& target_args);
  virtual ~htif_t();

  virtual void start();
  virtual void stop();

  int run();
  bool done();
  int exit_code();

  virtual reg_t read_cr(uint32_t coreid, uint16_t regnum);
  virtual reg_t write_cr(uint32_t coreid, uint16_t regnum, reg_t val);

  virtual reg_t read_hart_exec_ctrl_reg(uint32_t hart_id, uint16_t regnum);
  virtual reg_t write_hart_exec_ctrl_reg(uint32_t hart_id, uint16_t regnum, reg_t val);

  virtual std::vector<char> download_hart_full_state(uint32_t hart_id);
  virtual void upload_hart_full_state(uint32_t hart_id, const std::vector<char> &state_buf);

  virtual size_t download_memory_dump(std::ostream& output_stream);
  virtual void upload_memory_dump(std::istream& input_stream);

  virtual memif_t& memif() { return mem; }
  virtual uint32_t num_cores();
  virtual uint32_t mem_mb();

 protected:
  FILE* stats_dump_fd = NULL;
  bool is_main_fesvr;

  void set_state_dump_path(std::string dump_path);
  void dump_final_state();

  virtual void read_chunk(addr_t taddr, size_t len, void* dst);
  virtual void write_chunk(addr_t taddr, size_t len, const void* src);

  virtual size_t chunk_align() = 0;
  virtual size_t chunk_max_size() = 0;
  virtual bool assume0init() { return false; }

  virtual ssize_t read(void* buf, size_t max_size) = 0;
  virtual ssize_t write(const void* buf, size_t size) = 0;

  const std::vector<std::string>& host_args() { return hargs; }
  int exitcode;

  virtual void load_program();
  virtual void reset();

  void download_mem_dump_test(const std::string&write_path)
  {
    constexpr bool target_compress = true;

    if (target_compress) {
      std::ofstream output_file(write_path);
      download_memory_dump(output_file);
    } else {
      ogzstream output_file("full_memory_dump.gz");
      //    std::ofstream output_file("full_memory_dump");
      constexpr size_t chunk_size = 8192<<10;
      std::vector<uint8_t> buf(chunk_size);
      size_t mem_size = size_t(mem_mb()) << 20;
      assert(mem_size / chunk_size == (mem_size + (chunk_size - 1)) / chunk_size);
      for (size_t offset = 0; offset < mem_size; offset += chunk_size)
      {
        if ((offset & ((32 << 20) - 1)) == 0)
        {
          printf("%" PRIu64 "MB memory dumped\n", offset >> 20);
        }
        memif().read(offset, chunk_size, buf.data());
        output_file.write((char *) buf.data(), chunk_size);
      }
    }
  }

  void upload_mem_dump_test(const std::string& read_path)
  {
    constexpr bool target_compress = true;

    if (target_compress) {
      std::ifstream input_file(read_path);
      upload_memory_dump(input_file);
    } else {
      assert(0);
    }
  }


  void load_checkpoint(const std::string &checkpoint_path);

  void create_checkpoint(const std::string &output_filename);

  void setup_trap_for_next_checkpoint();

private:
  memif_tap_t mem;
  bool writezeros;
  seqno_t seqno;
  bool started;
  bool stopped;
  // RISCV target specification
  uint32_t _mem_mb;
  uint32_t _num_cores;
  uint8_t loaded_elf_sha256[32];
  std::vector<std::string> hargs;
  std::vector<std::string> targs;
  std::string sig_file;
  std::string chroot;
  addr_t sig_addr; // torture
  addr_t sig_len; // torture

  hart_execution_controller_t hart_execution_ctrl;
  syscall_t syscall_proxy;
  bcd_t bcd;
  std::vector<device_t*> dynamic_devices;

  std::unique_ptr<device_composition_t> device_composition;
  std::unique_ptr<device_traffic_recorder_t> traffic_recorder;
  traffic_debug_listener_t traffic_debug_listener;
  
  ckpt_desc_list_t checkpoint_creation_list;
  size_t checkpoint_creation_num_created;

  std::string checkpoint_restoration_path;

  std::vector<char> read_buf;
  virtual packet_t read_packet(seqno_t expected_seqno);
  virtual void write_packet(const packet_t& packet);

  void set_chroot(const char* where);
  const std::vector<std::string>& target_args() { return targs; }

  friend class memif_t;
  friend class syscall_t;
  friend class target_cwd;
  friend class syscall_main_t;
  friend class syscall_mirror_t;
  friend class device_composition_t;
};

#endif // __HTIF_H
