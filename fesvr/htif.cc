// See LICENSE for license details.

#include "htif.h"
#include "rfb.h"
#include "elfloader.h"
#include <algorithm>
#include <assert.h>
#include <vector>
#include <queue>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include "device_traffic_bypass.h"
#include "ckpt_desc_reader.h"
#include "checksum.h"

/* Attempt to determine the execution prefix automatically.  autoconf
 * sets PREFIX, and pconfigure sets __PCONFIGURE__PREFIX. */
#if !defined(PREFIX) && defined(__PCONFIGURE__PREFIX)
# define PREFIX __PCONFIGURE__PREFIX
#endif

#ifndef TARGET_ARCH
# define TARGET_ARCH "riscv64-unknown-elf"
#endif

#ifndef TARGET_DIR
# define TARGET_DIR "/" TARGET_ARCH "/bin/"
#endif

bool g_fesvr_verbose_output = false;

static volatile bool signal_exit = false;
static void handle_signal(int sig)
{
  if (sig == SIGABRT || signal_exit) // someone set up us the bomb!
    exit(-1);
  signal_exit = true;
  signal(sig, &handle_signal);
}

void htif_t::set_chroot(const char* where)
{
  char buf1[PATH_MAX], buf2[PATH_MAX];

  if (getcwd(buf1, sizeof(buf1)) == NULL
      || chdir(where) != 0
      || getcwd(buf2, sizeof(buf2)) == NULL
      || chdir(buf1) != 0)
  {
    printf("could not chroot to [%s]\n", where);
    exit(-1);
  }

  chroot = buf2;
}

htif_t::htif_t(const std::vector<std::string> &args)
    : exitcode(0), mem(*this), seqno(1), started(false), stopped(false),
      _mem_mb(0), _num_cores(0), sig_addr(0), sig_len(0),
      hart_execution_ctrl(*this), syscall_proxy(this)
{
  signal(SIGINT, &handle_signal);
  signal(SIGTERM, &handle_signal);
  signal(SIGABRT, &handle_signal); // we still want to call static destructors

  memset(loaded_elf_sha256, 0, sizeof(loaded_elf_sha256));

  size_t i;
  for (i = 0; i < args.size(); i++)
    if (args[i].length() && args[i][0] != '-' && args[i][0] != '+')
      break;

  hargs.insert(hargs.begin(), args.begin(), args.begin() + i);
  targs.insert(targs.begin(), args.begin() + i, args.end());

  std::deque<std::pair<std::string, std::string>> arg_devices;
  std::string arg_target_init_cwd;
  std::string arg_strace_output_path;
  std::string arg_console_dump_base;
  std::string arg_final_state_dump_path;
  std::string arg_chroot_dir;
  std::string arg_result_sig_file;
  std::string arg_recorded_device_traffic_path;
  std::string arg_device_traffic_record_path;
  std::string arg_device_traffic_replay_path;

  for (auto &arg: hargs)
  {
    if (arg == "+rfb")
      arg_devices.emplace_back("rfb", "0");
    else if (arg.find("+rfb=") == 0)
      arg_devices.emplace_back("rfb", arg.substr(strlen("+rfb=")));
    else if (arg.find("+disk=") == 0)
      arg_devices.emplace_back("disk", arg.substr(strlen("+disk=")));
    else if (arg.find("+strace=") == 0)
      arg_strace_output_path = arg.substr(strlen("+strace="));
    else if (arg.find("+std-dump=") == 0)
      arg_console_dump_base = arg.substr(strlen("+std-dump="));
    else if (arg.find("+final-state-dump=") == 0)
      arg_final_state_dump_path = arg.substr(strlen("+final-state-dump="));
    else if (arg.find("+signature=") == 0)
      arg_result_sig_file = arg.substr(strlen("+signature="));
    else if (arg.find("+chroot=") == 0)
      arg_chroot_dir = arg.substr(strlen("+chroot="));
    else if (arg.find("+target-cwd=") == 0)
      arg_target_init_cwd = arg.substr(strlen("+target-cwd="));
    else if (arg.find("+dev-traffic-record=") == 0)
      arg_device_traffic_record_path = arg.substr(strlen("+dev-traffic-record="));
    else if (arg.find("+dev-traffic-replay=") == 0)
      arg_device_traffic_replay_path = arg.substr(strlen("+dev-traffic-replay="));
    else if (arg.find("+create-checkpoint=") == 0)
    {
      checkpoint_creation_list = ckpt_desc_file_read(arg.substr(strlen("+create-checkpoint=")));
    }
    else if (arg.find("+load-checkpoint=") == 0)
      checkpoint_restoration_path = arg.substr(strlen("+load-checkpoint="));
    else if (arg == "+verbose")
      g_fesvr_verbose_output = true;
  }


  is_main_fesvr = !device_traffic_bypass_manager_t::has_main_composition();

  if (!is_main_fesvr)
  {
    // This FESVR instance is not the main instance, it simply replays the device traffic supplied by the main instance
    if (!checkpoint_creation_list.empty() && arg_device_traffic_replay_path.empty())
      throw std::runtime_error("to create checkpoint(s), FESVR must operate in device traffic replay mode.");

    if (!checkpoint_restoration_path.empty() && arg_device_traffic_replay_path.empty())
      throw std::runtime_error("to load a checkpoint, FESVR must operate in device traffic replay mode.");

    device_composition = std::unique_ptr<device_composition_t>(
      new recorded_composition_t(
        *this,
        std::unique_ptr<cmd_service_sequence_supplier_t>(
          new cmd_service_sequence_buffer_t(
            device_traffic_bypass_manager_t::get_main_composition()))));
  }
  else
  {
    // This FESVR instance is the main instance and need to go through detailed configuration.
    if (arg_device_traffic_replay_path.empty())
    {
      // FESVR is launched in real device mode, requires device setup
      auto real_device_composition = new real_composition_t(*this);
      for (auto &dev_arg: arg_devices)
      {
        if (dev_arg.first == "rfb")
          dynamic_devices.push_back(new rfb_t(atoi(dev_arg.second.c_str())));
        else if (dev_arg.first == "disk")
          dynamic_devices.push_back(new disk_t(dev_arg.second.c_str()));
        else
          throw std::runtime_error("unknown device: " + dev_arg.first);
      }

      // strace will only work in real device mode
      if (!arg_strace_output_path.empty())
        syscall_proxy.enable_strace(arg_strace_output_path.c_str());

      // console dump will only work in real device mode
      if (!arg_console_dump_base.empty())
        syscall_proxy.dump_std_out_err(
          (arg_console_dump_base + ".stdout").c_str(),
          (arg_console_dump_base + ".stderr").c_str());

      // chroot and target-cwd only applies to real device mode
      if (!arg_chroot_dir.empty())
        set_chroot(arg_chroot_dir.c_str());
      if (arg_target_init_cwd.empty())
        syscall_proxy.init_target_cwd(nullptr);
      else
        syscall_proxy.init_target_cwd(arg_target_init_cwd.c_str());

      real_device_composition->register_device(syscall_proxy);
      real_device_composition->register_device(bcd);
      for (auto d: dynamic_devices)
        real_device_composition->register_device(*d);
      device_composition = std::unique_ptr<device_composition_t>(real_device_composition);
    }
    else
    {
      // FESVR is launched in traffic replay mode, no device setup required, but need to prepare the state of replayer
      riscv_target_spec_t recording_spec{};
      auto recorded_composition = new recorded_composition_t(*this, std::unique_ptr<device_traffic_replayer_t>(new device_traffic_replayer_t(arg_device_traffic_replay_path)));

      recorded_composition->get_spec_from_traffic_source(recording_spec);

      device_composition = std::unique_ptr<device_composition_t>(recorded_composition);
    }
    // Register this FESVR instance as the main instance
    device_traffic_bypass_manager_t::set_main_composition(*device_composition);

    // Setup final state dump
    if (!arg_final_state_dump_path.empty())
      this->set_state_dump_path(arg_final_state_dump_path);

    // Setup signature output file
    if (!arg_result_sig_file.empty())
      sig_file = arg_result_sig_file;

    // Setup the traffic recorder
    if (!arg_device_traffic_record_path.empty())
    {
      traffic_recorder = std::unique_ptr<device_traffic_recorder_t>(new device_traffic_recorder_t(arg_device_traffic_record_path));
      device_composition->register_traffic_listener(*traffic_recorder);
    }

    // debug output
    device_composition->register_traffic_listener(traffic_debug_listener);
  }
}

htif_t::~htif_t()
{
  for (auto d : dynamic_devices)
    delete d;
}

packet_t htif_t::read_packet(seqno_t expected_seqno)
{
  while (1)
  {
    if (read_buf.size() >= sizeof(packet_header_t))
    {
      packet_header_t hdr(&read_buf[0]);
      if (read_buf.size() >= hdr.get_packet_size())
      {
        packet_t p(&read_buf[0]);
        switch (p.get_header().cmd)
        {
          case HTIF_CMD_ACK:
            break;
          case HTIF_CMD_NACK:
            throw packet_error("nack!");
          default:
            throw packet_error("illegal command " + std::to_string(p.get_header().cmd));
        }
        read_buf.erase(read_buf.begin(), read_buf.begin() + hdr.get_packet_size());
        return p;
      }
    }
    size_t old_size = read_buf.size();
    size_t max_size = sizeof(packet_header_t) + chunk_max_size();
    read_buf.resize(old_size + max_size);
    ssize_t this_size = this->read(&read_buf[old_size], max_size);
    if (this_size < 0)
      throw io_error("read failed");
    read_buf.resize(old_size + this_size);
  }
}

void htif_t::write_packet(const packet_t& p)
{
  for (size_t pos = 0; pos < p.get_size(); )
  {
    ssize_t bytes = this->write(p.get_packet() + pos, p.get_size() - pos);
    if (bytes < 0)
      throw io_error("write failed");
    pos += bytes;
  }
}

void htif_t::start()
{
  assert(!started);
  started = true;

  hart_execution_ctrl.init(num_cores());

  // no need to load ELF if we will resume from a checkpoint
  if (checkpoint_restoration_path.empty()) load_program();

  // freeze all HARTs in case we need to load a checkpoint
  for (uint32_t c = 0; c < num_cores(); c++)
    hart_execution_ctrl.set_unconditional_breakpoint(c, [](hart_execution_controller_t &controller, uint32_t hart_id, reg_t frozen_bit) {});

  // reset all HARTs (while HARTs are frozen)
  reset();

  // if configured to resume from a checkpoint, stream it to the target now (while HARTs are frozen)
  if (!checkpoint_restoration_path.empty()) load_checkpoint(checkpoint_restoration_path);

  checkpoint_creation_num_created = 0;
  setup_trap_for_next_checkpoint();

  // let the device composition knows the target spec
  static_assert(sizeof(riscv_target_spec_t::load_elf_sha256) == sizeof(loaded_elf_sha256), "(sizeof(riscv_target_spec_t::load_elf_sha256) != sizeof(loaded_elf_sha256)");
  riscv_target_spec_t target_spec{};
  target_spec.num_hart = num_cores();
  target_spec.mem_sz_mb = mem_mb();
  memcpy(target_spec.load_elf_sha256, loaded_elf_sha256, sizeof(target_spec.load_elf_sha256));
  device_composition->on_target_spec_known(target_spec);

  // defrost all HARTs, execution start from here
  for (uint32_t c = 0; c < num_cores(); c++)
    hart_execution_ctrl.clear_unconditional_breakpoint(c);
}

void htif_t::load_program()
{
  if (targs.size() == 0 || targs[0] == "none")
    return;

  std::string path;
  if (access(targs[0].c_str(), F_OK) == 0)
    path = targs[0];
  else if (targs[0].find('/') == std::string::npos)
  {
    std::string test_path = PREFIX TARGET_DIR + targs[0];
    if (access(test_path.c_str(), F_OK) == 0)
      path = test_path;
  }

  if (path.empty())
    throw std::runtime_error("could not open " + targs[0]);

  std::map<std::string, uint64_t> symbols = load_elf(path.c_str(), &mem);
  auto elf_sha256 = crypto_digest_t::digest_file("sha256", path.c_str(), nullptr);
  assert(elf_sha256.size() == sizeof(loaded_elf_sha256));
  memcpy(loaded_elf_sha256, elf_sha256.data(), sizeof(loaded_elf_sha256));

  // detect torture tests so we can print the memory signature at the end
  if (symbols.count("begin_signature") && symbols.count("end_signature"))
  {
    sig_addr = symbols["begin_signature"];
    sig_len = symbols["end_signature"] - sig_addr;
  }
}

void htif_t::reset()
{
  uint32_t first_words[] = {mem_mb(), num_cores()};
  size_t al = chunk_align();
  uint8_t chunk[(sizeof(first_words)+al-1)/al*al];
  read_chunk(0, sizeof(chunk), chunk);
  memcpy(chunk, first_words, sizeof(first_words));
  write_chunk(0, sizeof(chunk), chunk);

  for (uint32_t i = 0; i < num_cores(); i++)
  {
    write_cr(i, 29, 1);
    write_cr(i, 29, 0);
  }
}

void htif_t::stop()
{
  if (!sig_file.empty() && sig_len) // print final torture test signature
  {
    std::vector<uint8_t> buf(sig_len);
    mem.read(sig_addr, sig_len, &buf[0]);

    std::ofstream sigs(sig_file);
    assert(sigs && "can't open signature file!");
    sigs << std::setfill('0') << std::hex;

    const addr_t incr = 16;
    assert(sig_len % incr == 0);
    for (addr_t i = 0; i < sig_len; i += incr)
    {
      for (addr_t j = incr; j > 0; j--)
        sigs << std::setw(2) << (uint16_t)buf[i+j-1];
      sigs << '\n';
    }

    sigs.close();
  }

  dump_final_state();

  if (traffic_recorder)
    traffic_recorder->close();

  for (uint32_t i = 0, nc = num_cores(); i < nc; i++)
    write_cr(i, 29, 1);

  stopped = true;
}

void htif_t::read_chunk(addr_t taddr, size_t len, void* dst)
{
  assert(taddr % chunk_align() == 0);
  assert(len % chunk_align() == 0 && len <= chunk_max_size());

  packet_header_t hdr(HTIF_CMD_READ_MEM, seqno,
                      len/HTIF_DATA_ALIGN, taddr/HTIF_DATA_ALIGN);
  write_packet(hdr);
  packet_t resp = read_packet(seqno);
  seqno++;

  memcpy(dst, resp.get_payload(), len);
}

void htif_t::write_chunk(addr_t taddr, size_t len, const void* src)
{
  assert(taddr % chunk_align() == 0);
  assert(len % chunk_align() == 0 && len <= chunk_max_size());

  bool nonzero = started || !assume0init();
  for (size_t i = 0; i < len && !nonzero; i++)
    nonzero |= ((uint8_t*)src)[i] != 0;

  if (nonzero)
  {
    packet_header_t hdr(HTIF_CMD_WRITE_MEM, seqno,
                        len/HTIF_DATA_ALIGN, taddr/HTIF_DATA_ALIGN);
    write_packet(packet_t(hdr, src, len));
    read_packet(seqno);
    seqno++;
  }
}

reg_t htif_t::read_cr(uint32_t coreid, uint16_t regnum)
{
  reg_t addr = (reg_t)coreid << 20 | regnum;
  packet_header_t hdr(HTIF_CMD_READ_CONTROL_REG, seqno, 1, addr);
  write_packet(hdr);

  packet_t resp = read_packet(seqno);
  seqno++;

  reg_t val;
  assert(resp.get_payload_size() == sizeof(reg_t));
  memcpy(&val, resp.get_payload(), sizeof(reg_t));
  return val;
}

reg_t htif_t::write_cr(uint32_t coreid, uint16_t regnum, reg_t val)
{
  reg_t addr = (reg_t)coreid << 20 | regnum;
  packet_header_t hdr(HTIF_CMD_WRITE_CONTROL_REG, seqno, 1, addr);
  write_packet(packet_t(hdr, &val, sizeof(val)));

  packet_t resp = read_packet(seqno);
  seqno++;

  assert(resp.get_payload_size() == sizeof(reg_t));
  memcpy(&val, resp.get_payload(), sizeof(reg_t));
  return val;
}

reg_t htif_t::read_hart_exec_ctrl_reg(uint32_t hart_id, uint16_t regnum)
{
  reg_t addr = (reg_t) hart_id << 20 | regnum;
  packet_header_t hdr(HTIF_CMD_READ_HART_EXEC_CONTROL_REG, seqno, 0, addr);
  write_packet(hdr);

  packet_t resp = read_packet(seqno);
  seqno++;

  reg_t val;
  assert(resp.get_payload_size() == sizeof(reg_t));
  memcpy(&val, resp.get_payload(), sizeof(reg_t));
  return val;
}

reg_t htif_t::write_hart_exec_ctrl_reg(uint32_t hart_id, uint16_t regnum, reg_t val)
{
  reg_t addr = (reg_t) hart_id << 20 | regnum;

  packet_header_t hdr(HTIF_CMD_WRITE_HART_EXEC_CONTROL_REG, seqno, 1, addr);
  assert(sizeof(val) == HTIF_DATA_ALIGN);
  write_packet(packet_t(hdr, &val, HTIF_DATA_ALIGN));

  packet_t resp = read_packet(seqno);
  seqno++;

  assert(resp.get_payload_size() == sizeof(reg_t));
  memcpy(&val, resp.get_payload(), sizeof(reg_t));
  return val;
}

std::vector<char> htif_t::download_hart_full_state(uint32_t hart_id)
{
  packet_header_t hdr(HTIF_CMD_DOWNLOAD_HART_FULL_STATE, seqno, 0, reg_t(hart_id));
  write_packet(hdr);

  packet_t resp = read_packet(seqno);
  seqno++;

  size_t payload_size = resp.get_payload_size();
  return {resp.get_payload(), resp.get_payload() + payload_size};
}

void htif_t::upload_hart_full_state(uint32_t hart_id, const std::vector<char> &state_buf)
{
  reg_t addr = (reg_t) hart_id;
  // state_length must be aligned to HTIF_DATA_ALIGN
  size_t state_length = state_buf.size();
  assert(state_length / HTIF_DATA_ALIGN == (state_length + HTIF_DATA_ALIGN - 1) / HTIF_DATA_ALIGN);
  packet_header_t hdr(HTIF_CMD_UPLOAD_HART_FULL_STATE, seqno, state_length / HTIF_DATA_ALIGN, addr);
  write_packet(packet_t(hdr, state_buf.data(), state_length));

  packet_t resp = read_packet(seqno);
  seqno++;

  assert(resp.get_payload_size() == 0);
}


int htif_t::run()
{
  start();
  std::vector<std::queue<reg_t>> fromhost(num_cores());

  auto enq_func = [](std::queue<reg_t>* q, uint64_t x) { q->push(x); };
  std::vector<std::function<void(reg_t)>> fromhost_callbacks;
  for (size_t i = 0; i < num_cores(); i++)
    fromhost_callbacks.push_back(std::bind(enq_func, &fromhost[i], std::placeholders::_1));

  while (!signal_exit && exitcode == 0)
  {
    for (uint32_t coreid = 0; coreid < num_cores(); coreid++)
    {
      hart_execution_ctrl.do_poll(coreid);
      if (auto tohost = write_cr(coreid, 30, 0))
      {
        command_t cmd(this, tohost, fromhost_callbacks[coreid], coreid);
        device_composition->handle_command(cmd);
      }

      device_composition->tick();

      if (!fromhost[coreid].empty())
        if (write_cr(coreid, 31, fromhost[coreid].front()) == 0)
          fromhost[coreid].pop();
    }
  }

  stop();

  return exit_code();
}

uint32_t htif_t::num_cores()
{
  if (_num_cores == 0)
    _num_cores = read_cr(-1, 0);
  return _num_cores;
}

uint32_t htif_t::mem_mb()
{
  if (_mem_mb == 0)
    _mem_mb = read_cr(-1, 1);
  return _mem_mb;
}

bool htif_t::done()
{
  return stopped;
}

int htif_t::exit_code()
{
  return exitcode >> 1;
}

void htif_t::set_state_dump_path(std::string dump_path)
{
  if (this->stats_dump_fd)
    fclose(this->stats_dump_fd);

  this->stats_dump_fd = fopen(dump_path.c_str(), "w");
  if (this->stats_dump_fd == NULL)
  {
    throw std::runtime_error(
        "Fail to create state dump file at \"" + dump_path + "\", reason: " + std::string(std::strerror(errno)));
  }
}

// dump states to this->stats_dump_fd in JSON format
void htif_t::dump_final_state()
{
  if (this->stats_dump_fd == NULL)
    return;

  const size_t n_harts = num_cores();
  fprintf(this->stats_dump_fd, "{\n");
  fprintf(this->stats_dump_fd, "  \"hart_state\": [\n");
  for (size_t n = 0; n < n_harts; n++)
  {
    fprintf(this->stats_dump_fd, "    {\n");

    // dump instret
    uint64_t instret = read_cr(n, 6);
    fprintf(this->stats_dump_fd, "      \"instret\": %" PRIu64 "\n", instret);

    if (n == n_harts - 1)
      fprintf(this->stats_dump_fd, "    }\n");
    else
      fprintf(this->stats_dump_fd, "    },\n");
  }
  fprintf(this->stats_dump_fd, "  ]\n");
  fprintf(this->stats_dump_fd, "}\n");
  fclose(this->stats_dump_fd);
  this->stats_dump_fd = NULL;
}

/**
   * Download the full memory dump from the target
   *
   * Protocol:
   *  * All packet send from host should have payload_size == 0.
   *
   *  - [H.1] To initiate the download memory dump sequence, the host should first send
   *    an initiating packet with hdr.cmd = DOWNLOAD_MEM_DUMP and hdr.addr = 0.
   *
   *  - [T.1] Once target received the initiating packet, it should reply the host with
   *    a zlib compressed full memory dump stream chunk-by-chunk. The replied packet
   *    have a non-zero payload_size, and hdr.addr representing the effective bytes.
   *
   *  - [H.2] Upon received a replied chunk from target, the host should keep sending
   *    another polling packet to obtain remaining chunks. The polling packet should have
   *    same hdr.cmd as in [H.1] and hdr.addr set to the effective bytes received previously
   *    (so that the target can optionally check it and reply NACK if it doesn't match).
   *
   *  - [T.2] If the target has more data to transmit, it should repeat [T.2] until all chunks
   *    are sent. After all chunks were sent, the target should reply the host an end-of-stream
   *    packet which has payload_size set to 0 and hdr.addr to be the total effective bytes sent
   *    counted at the target side.
   *
   *  - [H.3] Upon host polled an end-of-stream packet from target, the host should verify the
   *    total effective bytes received against the hdr.addr from the end-of-stream packet.
   *
   *  The sequence is complete once [H.3] is done.
   *
   *  @param output_stream A output stream to take the memory dump data.
   *  @return The size of the memory dump.
   */
size_t htif_t::download_memory_dump(std::ostream &output_stream)
{
  // Send dump initiating packet [H.1]
  packet_header_t hdr(HTIF_CMD_DOWNLOAD_MEM_DUMP, seqno++, 0, 0);
  write_packet(hdr);

  size_t total_received = 0;
  while (true)
  {
    // Receiving zlib compressed dump stream from target
    packet_t resp = read_packet(hdr.seqno);
    bool end_of_stream = resp.get_payload_size() == 0;
    if (end_of_stream)
    {
      // Stream ended [T.2]
      size_t sent_count_from_target = resp.get_header().addr;
      // Verify the data count [H.3]
      if (sent_count_from_target != total_received)
        throw std::runtime_error(
          "Error happened while downloading full memory dump from target: target reported " +
          std::to_string(sent_count_from_target) +
          " bytes was sent, but host only received " + std::to_string(total_received) +
          " bytes.");
      break;
    }

    // Stream continue [T.1]
    size_t prev_received = resp.get_header().addr;
    assert(prev_received <= resp.get_payload_size());
    output_stream.write((const char *) resp.get_payload(), prev_received);
    total_received += prev_received;

    // Keep polling [H.2]
    hdr.seqno = seqno++;
    hdr.addr = prev_received;
    write_packet(hdr);
  }

  return total_received;
}

/**
   * Upload a full memory dump to the target
   *
   * Protocol:
   *  * All packet send from target should have payload_size == 0.
   *
   *  - [H.1] To initiate the upload memory dump sequence, the host should first send
   *    an initiating packet with hdr.cmd = UPLOAD_MEM_DUMP and hdr.addr = 0.
   *
   *    [T.1] Once target received the initiating packet, it should reply a zero payload
   *    ACK packet, with hdr.addr set to the maximum number of bytes it can buffer in one
   *    packet transmission.
   *
   *    [H.2] Upon knowing the receiving capability, the host should begin streaming the
   *    memory dump to the target in a chunk size not exceeding the receiving capability.
   *    The streaming packet should set hdr.cmd to the same as in [H.1], and set hdr.addr
   *    to the effective size of the payload. Host wait for target ACK [T.2] before
   *    streaming another packet. Repeat until all data is streamed.
   *
   *  - [T.2] Once target received the streaming packet, it should immediately decompress
   *    the stream with the received compressed chunk and fill the memory. Once the target
   *    is ready to receive another chunk, it should send an ACK packet to the host with
   *    hdr.addr set to the effective bytes received previously (so that the host can
   *    optionally check).
   *
   *  - [H.3] Upon all data is streamed, the host should send an end-of-stream packet to target,
   *    which has the same hdr.cmd as in [H.1] and hdr.addr be the total effective bytes sent
   *    counted by the host but empty payload.
   *
   *  - [T.3] Upon receive end-of-stream packet from host, the target should confirm the stream
   *    integrity, if the upload is done successfully it should reply host an ACK with hdr.addr
   *    set to size of the decompressed data. Otherwise an NACK should be sent.
   *
   *  - [H.4] Host receive ACK / NACK from [T.2]. If it is a ACK, the host should verify the size
   *    of the decompressed data.
   *
   *  The sequence is completed once [H.4] is done.
   *
   *  @param input_stream An input stream to supply the memory dump data.
   */
void htif_t::upload_memory_dump(std::istream &input_stream)
{
  // Send the initiating packet to negotiate the chunk size [H.1]
  packet_header_t hdr(HTIF_CMD_UPLOAD_MEM_DUMP, seqno++, 0, 0);
  write_packet(hdr);

  // Get target response [T.1]
  packet_t resp = read_packet(hdr.seqno);
  assert(resp.get_payload_size() == 0);

  // Prepare the send buffer
  size_t send_chunk_size = resp.get_header().addr;
  std::vector<char> send_buf(send_chunk_size);

  size_t total_sent = 0;
  while (input_stream)
  {
    // Load memory dump from the input stream in the proposed chunk
    input_stream.read(send_buf.data(), send_buf.size());
    size_t effective_length = input_stream.gcount();
    size_t ds = (effective_length + HTIF_DATA_ALIGN - 1) / HTIF_DATA_ALIGN;
    // Zero-padding the packet if needed
    if (effective_length < (ds * HTIF_DATA_ALIGN))
      std::fill(send_buf.begin() + effective_length, send_buf.begin() + (ds * HTIF_DATA_ALIGN), 0);

    // Stream compressed memory dump to target in chunks [H.2]
    hdr.seqno = seqno++;
    hdr.data_size = ds;
    hdr.addr = effective_length;
    write_packet(packet_t(hdr, send_buf.data(), ds * HTIF_DATA_ALIGN));
    total_sent += effective_length;

    // Wait for target, and check the received bytes it reported [T.2]
    packet_t resp = read_packet(hdr.seqno);
    assert(resp.get_payload_size() == 0);
    assert(resp.get_header().addr == effective_length);
  }

  // Notify target the end-of-stream [H.3]
  hdr.seqno = seqno++;
  hdr.data_size = 0;
  hdr.addr = total_sent;
  write_packet(hdr);

  // Wait for target to confirm [T.2]
  packet_t eos_resp = read_packet(hdr.seqno);
  assert(eos_resp.get_payload_size() == 0);

  // Validate the decompressed data size [H.3]
  if (eos_resp.get_header().addr != (uint64_t(mem_mb()) << 20))
  {
    throw std::runtime_error(
      "Error happened while loading memory dump to target: target reported that " +
      std::to_string(eos_resp.get_header().addr) +
      " bytes of physical memory was written, however the physical memory size is " +
      std::to_string(uint64_t(mem_mb()) << 20) +
      " bytes.");
  }
}

void htif_t::load_checkpoint(const std::string &checkpoint_path)
{
  std::ifstream ifs(checkpoint_path.c_str());

  auto read_ckpt_data = [&ifs, &checkpoint_path](void *dst, size_t c) {
    ifs.read((char *) dst, c);
    size_t read_cnt = ifs.gcount();
    if (read_cnt != c)
      throw std::runtime_error("Fail to read " + std::to_string(c) + " bytes from file " + checkpoint_path);
  };

  std::vector<char> header_buf(std::max(
                                 offsetof(checkpoint_header_t, magic) + sizeof(checkpoint_header_t::magic),
                                 offsetof(checkpoint_header_t, num_hart) + sizeof(checkpoint_header_t::num_hart)),
                               0);
  auto *header = (checkpoint_header_t *) header_buf.data();
  read_ckpt_data(&header->magic, sizeof(header->magic));
  read_ckpt_data(&header->num_hart, sizeof(header->num_hart));

  header_buf.resize(checkpoint_header_t::size(header->num_hart), 0);
  header = (checkpoint_header_t *) header_buf.data();

  read_ckpt_data(&header->mem_sz_mb, sizeof(header->mem_sz_mb));
  read_ckpt_data(&header->load_elf_sha256, sizeof(header->load_elf_sha256));
  read_ckpt_data(&header->harts, header->num_hart * sizeof(hart_checkpoint_t));

  if (header->magic != checkpoint_header_t::RV64_CHECKPOINT_MAGIC)
    throw std::runtime_error("Cannot load the checkpoint file " + checkpoint_path + " because it has a bad magic number.");
  if (header->num_hart != num_cores())
    throw std::runtime_error("Cannot load the checkpoint file " + checkpoint_path + " because it was created for system with " + std::to_string(header->num_hart) + " HART(s), however the current system is configured with " + std::to_string(num_cores()) + " HART(s).");
  if (header->mem_sz_mb != mem_mb())
    throw std::runtime_error("Cannot load the checkpoint file " + checkpoint_path + " because it was created for system with " + std::to_string(header->mem_sz_mb) + " MB RAM, however the current system is configured with " + std::to_string(mem_mb()) + " MB RAM.");

  // fill the FESVR's loaded_elf_sha256 based on the information supplied by this checkpoint
  memcpy(loaded_elf_sha256, header->load_elf_sha256, sizeof(loaded_elf_sha256));

  auto &recorded_composition = dynamic_cast<recorded_composition_t &>(*device_composition);
  for (uint32_t i = 0; i < header->num_hart; i++)
  {
    auto hart_i_recording_sha256 = recorded_composition.get_recording_sha256(i);
    assert(hart_i_recording_sha256.size() == sizeof header->harts[i].traffic_recording_sha256);
    if (memcmp(header->harts[i].traffic_recording_sha256, hart_i_recording_sha256.data(), hart_i_recording_sha256.size()) != 0)
      throw std::runtime_error("Cannot use the checkpoint file " + checkpoint_path + " because it requires HART " + std::to_string(i) + " to load a device traffic recording with SHA256 " + crypto_digest_t::to_string(header->harts[i].traffic_recording_sha256, sizeof(header->harts[i].traffic_recording_sha256)) + ", however the SHA256 of the current loaded recording is " + crypto_digest_t::to_string(hart_i_recording_sha256) + ".");

    upload_memory_dump(ifs);

    std::vector<char> hart_state_buf(header->harts[i].hart_state_storage, header->harts[i].hart_state_storage + header->harts[i].hart_state_size);
    upload_hart_full_state(i, hart_state_buf);

    if (is_main_fesvr)
    { // only the main FESVR gets traffic from persistent recording, therefore needs seek operation
      if (!recorded_composition.seek(i, header->harts[i].traffic_skip_amt))
        throw std::runtime_error("Failed to load the checkpoint file " + checkpoint_path + " because cannot seek to the " + std::to_string(header->harts[i].traffic_skip_amt + 1) + "th command in the device traffic recording of HART " + std::to_string(i) + ".");
    }
    else
    {
      recorded_composition.reset_num_cmd_received(i, header->harts[i].traffic_skip_amt);
    }
  }
}

void htif_t::create_checkpoint(const std::string &output_filename)
{
  assert(is_main_fesvr); // only the main FESVR should create checkpoint
  std::vector<char> header_buf(checkpoint_header_t::size(num_cores()), 0);
  auto *header = (checkpoint_header_t *) header_buf.data();
  header->magic = checkpoint_header_t::RV64_CHECKPOINT_MAGIC;
  header->num_hart = num_cores();
  header->mem_sz_mb = mem_mb();
  memcpy(header->load_elf_sha256, loaded_elf_sha256, sizeof(header->load_elf_sha256));

  auto &recorded_composition = dynamic_cast<recorded_composition_t &>(*device_composition);
  for (uint32_t i = 0; i < num_cores(); i++)
  {
    // fill traffic_recording_sha256 field with SHA256 of the loaded recording
    auto hart_i_recording_sha256 = recorded_composition.get_recording_sha256(i);
    assert(hart_i_recording_sha256.size() == sizeof(header->harts[i].traffic_recording_sha256));
    std::copy(hart_i_recording_sha256.begin(), hart_i_recording_sha256.end(), header->harts[i].traffic_recording_sha256);

    // fill the traffic_skip_amt field with the current number of received command
    header->harts[i].traffic_skip_amt = device_composition->num_cmd_received(i);

    // fill the hart_state field with the collected full state dump
    auto hart_state = download_hart_full_state(i);
    if (hart_state.size() > hart_checkpoint_t::HART_STATE_STORAGE_MAX)
      throw std::runtime_error("Cannot create checkpoint: the size of HART " + std::to_string(i) + "'s full state dump (" + std::to_string(hart_state.size()) + " bytes) exceeded the pre-allocated budget (" + std::to_string(hart_checkpoint_t::HART_STATE_STORAGE_MAX) + " bytes).");
    header->harts[i].hart_state_size = hart_state.size();
    std::copy(hart_state.begin(), hart_state.end(), header->harts[i].hart_state_storage);
  }


  std::ofstream ofs(output_filename);
  ofs.write((const char *) header, header->size());
  download_memory_dump(ofs);

  ofs.close();
}

void htif_t::setup_trap_for_next_checkpoint()
{
  /**
   * If mirrored FESVR exists (for timing simulator in 721sim), only the main FESVR of the leading functional simulator
   * is allowed to create one checkpoint (cannot create more than one due shift in INTERLEAVE will lead to checker failure.
   *
   * If mirror doesn't exist, can create checkpoints as many as needed. Be aware of some tiny increment/decrement in the
   * dynamic instruction count caused by shifting in step/INTERLEAVE.
   *
   */
  if (!is_main_fesvr) return;
  if (checkpoint_creation_list.empty()) return;

  if (checkpoint_creation_num_created == checkpoint_creation_list.size())
  {
    // all checkpoint created, prepare to stop simulation
    this->exitcode = 1;
    return;
  }

  if (num_cores() != 1)
    throw std::runtime_error("Currently HTIF doesn't support to create checkpoint for multi-HART system!");
  reg_t instr_retired = checkpoint_creation_num_created == 0 ? 0 : checkpoint_creation_list[checkpoint_creation_num_created - 1].second;
  reg_t instr_to_stop = checkpoint_creation_list[checkpoint_creation_num_created].second - instr_retired;
  hart_execution_ctrl.set_instret_count_breakpoint(0, instr_to_stop, [this](hart_execution_controller_t &controller, uint32_t hart_id, reg_t frozen_bit) {
    create_checkpoint(checkpoint_creation_list[checkpoint_creation_num_created].first);
    ++checkpoint_creation_num_created;
    setup_trap_for_next_checkpoint();
    controller.defrost(hart_id, frozen_bit);
  });
}
