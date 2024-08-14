//
// Created by john on 7/18/24.
//

#include "device_traffic_persistent.h"
#include "checksum.h"
#include <cstring>
static constexpr auto CHECKSUM_ALGO = checksum_t::CRC32;

namespace device_traffic_persistent
{
  // public
  raw_packet_reader_t::raw_packet_reader_t(const std::string &path)
      : m_index_istream((path + ".index").c_str()),
        m_packets_istream((path + ".packets").c_str()),
        m_sha256_istream((path + ".sha256").c_str()),
        m_path(path),
        m_packet_buffer(4096),
        m_next_cmd_seq_no(0),
        m_current_command_active(false),
        m_cumulative_checksum(CHECKSUM_ALGO),
        m_recording_sha256(32, 0)
  {
    m_cumulative_checksum.reset();

    uint32_t packets_file_magic;
    uint32_t index_file_magic;
    uint32_t checksum_file_magic;

    m_packets_istream.read((char *) &packets_file_magic, sizeof(packets_file_magic));
    if (!m_packets_istream)
      throw std::runtime_error("Cannot open file to read device traffic packets: " + path + ".packets");
    if (m_packets_istream.gcount() != sizeof(packets_file_magic))
    {
      throw std::runtime_error("malformed device traffic packets file: cannot read magic number");
    }
    else if (packets_file_magic != PACKETS_FILE_MAGIC)
    {
      throw std::runtime_error("malformed device traffic packets file: bad magic number");
    }

    m_index_istream.read((char *) &index_file_magic, sizeof(index_file_magic));
    if (!m_index_istream)
      throw std::runtime_error("Cannot open file to read device traffic index: " + path + ".index");
    if (m_index_istream.gcount() != sizeof(index_file_magic))
    {
      throw std::runtime_error("malformed device traffic index file: cannot read magic number");
    }
    else if (index_file_magic != INDEX_FILE_MAGIC)
    {
      throw std::runtime_error("malformed device traffic index file: bad magic number");
    }

    m_sha256_istream.read((char *) &checksum_file_magic, sizeof(checksum_file_magic));
    if (!m_sha256_istream)
      throw std::runtime_error("Cannot open file to read device traffic checksum: " + path + ".sha256");
    if (m_sha256_istream.gcount() != sizeof(checksum_file_magic))
    {
      throw std::runtime_error("malformed device traffic checksum file: cannot read magic number");
    }
    else if (checksum_file_magic != SHA256_FILE_MAGIC)
    {
      throw std::runtime_error("malformed device traffic checksum file: bad magic number");
    }


    m_sha256_istream.read((char *) m_recording_sha256.data(), m_recording_sha256.size()); // NOLINT(*-narrowing-conversions)
    if (size_t(m_sha256_istream.gcount()) != m_recording_sha256.size())
    {
      throw std::runtime_error("malformed device traffic checksum file: cannot read the sha256 of the recording");
    }

    while (true)
    {
      uint64_t offset;
      m_index_istream.read((char *) &offset, sizeof(offset));
      const size_t read_count = m_index_istream.gcount();
      if (m_index_istream.eof() && read_count == 0)
        break;
      if (read_count == sizeof(offset))
      {
        m_packets_index.push_back(offset);
      }
      else
      {
        throw std::runtime_error("malformed device traffic index file");
      }
    }
    m_packets_index.shrink_to_fit();
  }

  // public
  bool raw_packet_reader_t::seek(size_t cmd_seq_no)
  {
    if (cmd_seq_no >= m_packets_index.size())
      return false;

    size_t pkt_data_offset;
    if (cmd_seq_no == 0)
    {
      pkt_data_offset = m_packets_index[0];
      m_packets_istream.seekg(pkt_data_offset);
      m_cumulative_checksum.reset();
    }
    else
    {
      pkt_data_offset = m_packets_index[cmd_seq_no];
      assert(pkt_data_offset > sizeof(cmd_end_payload_t::crc32));
      pkt_data_offset -= sizeof(cmd_end_payload_t::crc32);
      m_packets_istream.seekg(pkt_data_offset);
      uint32_t prev_crc32 = 0;
      get_raw_data(&prev_crc32, sizeof(prev_crc32), false);
      m_cumulative_checksum.set(prev_crc32);
      update_crc32(&prev_crc32, sizeof(prev_crc32));
    }

    m_next_cmd_seq_no = cmd_seq_no;

    if (!m_packets_istream)
    {
      throw std::runtime_error(
        "malformed device traffic input: failed to seek to the " +
        std::to_string(cmd_seq_no) + "th command, seeking packet stream with offset=" +
        std::to_string(pkt_data_offset) + " results in bad stream.");
    }
    return true;
  }

  // public
  const packet_t &raw_packet_reader_t::get_next_packet()
  {
    packet_t tmp;
    size_t packet_header_size, payload_base_size, payload_extra_size;

    // get the packet header part
    packet_header_size = packet_t::header_size();
    if (get_raw_data(&tmp, packet_header_size, !m_current_command_active) == EOF)
    {
      // reached the end of the device traffic packets file?
      if (num_commands() != m_next_cmd_seq_no)
        throw std::runtime_error(
          "malformed device traffic input: device traffic early termination, expect to contain " +
          std::to_string(num_commands()) + " commands, but terminated after " + std::to_string(m_next_cmd_seq_no) + " commands.");

      m_packet_buffer.reserve(packet_t::header_size());
      auto &packet_buf_ref = reinterpret_cast<packet_t &>(*&m_packet_buffer[0]);
      packet_buf_ref.header.type = PACKET_FILE_EOF;
      return packet_buf_ref;
    }

    // validate the packet header and determine the size of payload base part
    switch (tmp.header.type)
    {
    case COMMAND_BEGIN:
      if (m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected COMMAND_BEGIN packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_header_size));
      payload_base_size = cmd_begin_payload_t::payload_size();
      break;
    case PHYSICAL_MEMORY_ACCESS:
      if (!m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected PHYSICAL_MEMORY_ACCESS packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_header_size));
      payload_base_size = phy_mem_access_payload_t::payload_size(0);
      break;
    case COMMAND_END:
      if (!m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected COMMAND_END packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_header_size));
      payload_base_size = cmd_end_payload_t::payload_size();
      break;
    default:
      throw std::runtime_error(
        "malformed device traffic input: unknown packet type " + std::to_string(tmp.header.type) + " at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_header_size));
    }


    // get the payload base part
    get_raw_data(((uint8_t *) &tmp) + packet_header_size, payload_base_size, false);
    payload_extra_size = tmp.packet_size() - packet_header_size - payload_base_size;

    // reserve enough memory for the full packet, then read extra payload (if any)
    m_packet_buffer.reserve(packet_header_size + payload_base_size + payload_extra_size);
    memcpy(&m_packet_buffer[0], &tmp, packet_header_size + payload_base_size);
    if (payload_extra_size)
    {
      get_raw_data(&m_packet_buffer[packet_header_size + payload_base_size], payload_extra_size, false);
    }

    if (tmp.header.type == COMMAND_BEGIN)
    {
      command_begin();
    }

    // perform CRC32 checksum validation
    check_crc32();

    if (tmp.header.type == COMMAND_END)
    {
      command_end();
    }

    return reinterpret_cast<const packet_t &>(*&m_packet_buffer[0]);
  }

  // public
  size_t raw_packet_reader_t::num_commands() const
  {
    return m_packets_index.size();
  }

  // protected
  ssize_t raw_packet_reader_t::get_raw_data(void *dst, const ssize_t n, bool accept_eof)
  {
    assert(n > 0);
    m_packets_istream.read((char *) dst, n);
    const ssize_t read_count = m_packets_istream.gcount();
    if (read_count != n)
    {
      if (m_packets_istream.eof())
      {
        if (accept_eof && read_count == 0)
          return EOF;
        throw std::runtime_error("malformed device traffic input: unexpected EOF.");
      }
      throw std::runtime_error("malformed device traffic input: fail to read enough data.");
    }
    return read_count;
  }

  // protected
  uint32_t raw_packet_reader_t::update_crc32(const void *data, size_t len)
  {
    return m_cumulative_checksum.update(data, len);
  }

  // protected
  void raw_packet_reader_t::check_crc32()
  {
    assert(m_current_command_active);

    auto *packet_buf = (packet_t *) &m_packet_buffer[0];
    if (packet_buf->header.type == COMMAND_END)
    {
      uint32_t expect_crc32 = update_crc32(packet_buf, packet_buf->packet_size() - sizeof(cmd_end_payload_t::crc32));
      if (expect_crc32 != packet_buf->payload.cmd_end_payload.crc32)
        throw std::runtime_error("malformed device traffic input: CRC32 check failed.");
      update_crc32(&expect_crc32, sizeof(expect_crc32));
    }
    else
    {
      update_crc32(packet_buf, packet_buf->packet_size());
    }
  }

  // protected
  void raw_packet_reader_t::command_begin()
  {
    assert(!m_current_command_active);

    m_current_command_active = true;
  }

  // protected
  void raw_packet_reader_t::command_end()
  {
    assert(m_current_command_active);

    m_current_command_active = false;
    m_next_cmd_seq_no += 1;
  }

  // public
  raw_packet_writer_t::raw_packet_writer_t(const std::string &path)
      : m_index_ostream((path + ".index").c_str()),
        m_packets_ostream((path + ".packets").c_str()),
        m_sha256_ostream((path + ".sha256").c_str()),
        m_path(path),
        m_packet_buf(4096),
        m_packet_buf_empty(true),
        m_current_packet_offset(0),
        m_current_command_active(false),
        m_cumulative_checksum(CHECKSUM_ALGO),
        m_packet_stream_sha256("sha256")
  {
    m_cumulative_checksum.reset();

    m_index_ostream.write((const char *) &INDEX_FILE_MAGIC, sizeof(INDEX_FILE_MAGIC));
    m_index_ostream.flush();

    m_packets_ostream.write((const char *) &PACKETS_FILE_MAGIC, sizeof(PACKETS_FILE_MAGIC));
    m_packets_ostream.flush();
    m_current_packet_offset = sizeof(PACKETS_FILE_MAGIC);
    m_packet_stream_sha256.update(&PACKETS_FILE_MAGIC, sizeof(PACKETS_FILE_MAGIC));

    m_sha256_ostream.write((const char *) &SHA256_FILE_MAGIC, sizeof(SHA256_FILE_MAGIC));
    m_sha256_ostream.flush();

    if (!m_packets_ostream)
      throw std::runtime_error("Cannot open file to write device traffic packets: " + path + ".packets");
    if (!m_index_ostream)
      throw std::runtime_error("Cannot open file to write device traffic index: " + path + ".index");
    if (!m_sha256_ostream)
      throw std::runtime_error("Cannot open file to write device traffic checksum: " + path + ".sha256");
  }

  // public
  size_t raw_packet_writer_t::write_cmd_begin_packet(const uint8_t device, const uint8_t cmd, const uint64_t payload)
  {
    command_begin();

    const auto packet_size = packet_t::header_size() + cmd_begin_payload_t::payload_size();
    auto &packet_buf_ref = get_packet_buf(packet_size);

    packet_buf_ref.header.type = COMMAND_BEGIN;
    packet_buf_ref.payload.cmd_begin_payload.device = device;
    packet_buf_ref.payload.cmd_begin_payload.cmd = cmd;
    packet_buf_ref.payload.cmd_begin_payload.payload = payload;

    assert(packet_buf_ref.packet_size() == packet_size);
    update_crc32(&packet_buf_ref, packet_buf_ref.packet_size());
    return flush_packet_buf();
  }

  // public
  size_t raw_packet_writer_t::write_phy_mem_access_packet(const uint64_t begin_address, const bool is_write, const uint64_t access_length, const uint8_t data[])
  {
    const auto packet_size = packet_t::header_size() + phy_mem_access_payload_t::payload_size(access_length);
    auto &packet_buf_ref = get_packet_buf(packet_size);

    packet_buf_ref.header.type = PHYSICAL_MEMORY_ACCESS;
    packet_buf_ref.payload.mem_access_payload.begin_physical_address = begin_address;
    packet_buf_ref.payload.mem_access_payload.is_write = is_write;
    packet_buf_ref.payload.mem_access_payload.access_length = access_length;
    memcpy(packet_buf_ref.payload.mem_access_payload.data, data, access_length);

    assert(packet_buf_ref.packet_size() == packet_size);
    update_crc32(&packet_buf_ref, packet_buf_ref.packet_size());
    return flush_packet_buf();
  }

  // public
  size_t raw_packet_writer_t::write_cmd_end_packet(const bool responded, const uint64_t response_value, const uint64_t htif_exitcode)
  {
    const auto packet_size = packet_t::header_size() + cmd_end_payload_t::payload_size();
    auto &packet_buf_ref = get_packet_buf(packet_size);


    packet_buf_ref.header.type = COMMAND_END;
    packet_buf_ref.payload.cmd_end_payload.responded = responded ? 1 : 0;
    packet_buf_ref.payload.cmd_end_payload.response_value = response_value;
    packet_buf_ref.payload.cmd_end_payload.htif_exitcode = htif_exitcode;

    assert(packet_buf_ref.packet_size() == packet_size);
    packet_buf_ref.payload.cmd_end_payload.crc32 = update_crc32(&packet_buf_ref, packet_buf_ref.packet_size() - sizeof(cmd_end_payload_t::crc32));
    update_crc32(&packet_buf_ref.payload.cmd_end_payload.crc32, sizeof(packet_buf_ref.payload.cmd_end_payload.crc32));
    command_end();
    return flush_packet_buf();
  }

  // public
  void raw_packet_writer_t::close()
  {
    if (m_current_command_active)
    {
      throw std::runtime_error("fatal: try closing the device traffic output stream before the current command is finished.");
    }
    m_index_ostream.close();
    m_packets_ostream.close();

    auto packet_stream_sha256 = m_packet_stream_sha256.final();
    m_sha256_ostream.write((const char *) packet_stream_sha256.data(), packet_stream_sha256.size()); // NOLINT(*-narrowing-conversions)
    m_sha256_ostream.close();
  }

  // protected
  packet_t &raw_packet_writer_t::get_packet_buf(const size_t packet_size)
  {
    assert(m_packet_buf_empty);

    m_packet_buf.reserve(packet_size);
    assert(packet_size <= m_packet_buf.capacity());

    m_packet_buf_empty = false;
    return reinterpret_cast<packet_t &>(*&m_packet_buf[0]);
  }

  // protected
  size_t raw_packet_writer_t::flush_packet_buf()
  {
    assert(!m_packet_buf_empty);

    const auto *p_packet_buf = (packet_t *) &m_packet_buf[0];
    const auto packet_size = p_packet_buf->packet_size();

    assert(packet_size <= m_packet_buf.capacity());
    assert(m_packets_ostream);
    m_packets_ostream.write((const char *) p_packet_buf, packet_size); // NOLINT(*-narrowing-conversions)
    m_packet_stream_sha256.update(p_packet_buf, packet_size);
    m_current_packet_offset += packet_size;

    m_packet_buf_empty = true;
    return packet_size;
  }

  // protected
  void raw_packet_writer_t::log_packet_offset_to_index()
  {
    assert(m_index_ostream);
    m_index_ostream.write((const char *) &m_current_packet_offset, sizeof(m_current_packet_offset));
  }

  // protected
  void raw_packet_writer_t::command_begin()
  {
    assert(!m_current_command_active);

    m_current_command_active = true;
    log_packet_offset_to_index();
  }

  // protected
  void raw_packet_writer_t::command_end()
  {
    assert(m_current_command_active);

    m_current_command_active = false;
  }

  // protected
  uint32_t raw_packet_writer_t::update_crc32(const void *data, size_t len)
  {
    assert(m_current_command_active && !m_packet_buf_empty);

    return m_cumulative_checksum.update(data, len);
  }
} // namespace device_traffic_persistent


void device_traffic_recorder_t::close()
{
  for (auto &writer: m_raw_packet_writers)
  {
    writer.second->close();
  }
}

void device_traffic_recorder_t::on_target_spec_known(const riscv_target_spec_t &target_spec)
{
  for (size_t i = 0; i < target_spec.num_hart; i++)
  {
    m_raw_packet_writers.emplace(
      i,
      new device_traffic_persistent::raw_packet_writer_t(m_output_base_folder + PATH_SEP + "device_traffic_hart" + std::to_string(i)));
  }
  // export system spec information
  uint32_t target_memory_mb = target_spec.mem_sz_mb;
  uint32_t target_num_hart = target_spec.num_hart;
  assert(sizeof(target_spec.load_elf_sha256) == 256 / 8);
  std::ofstream system_spec_output_stream(m_output_base_folder + PATH_SEP + "target_spec");
  system_spec_output_stream.write((const char *) &target_memory_mb, sizeof(target_memory_mb));
  system_spec_output_stream.write((const char *) &target_num_hart, sizeof(target_num_hart));
  system_spec_output_stream.write((const char *) target_spec.load_elf_sha256, 256 / 8);
  system_spec_output_stream.close();
  m_initialized = true;
}

void device_traffic_recorder_t::on_cmd_serviced(cmd_service_sequence_t *sequence)
{
  assert(m_initialized);
  auto &packet_writer = m_raw_packet_writers[sequence->hart_id];
  packet_writer->write_cmd_begin_packet(sequence->device, sequence->cmd, sequence->payload);
  for (auto &mem_transaction: sequence->mem_transactions)
  {
    packet_writer->write_phy_mem_access_packet(mem_transaction.addr, mem_transaction.is_write, mem_transaction.data.size(), &mem_transaction.data[0]);
  }
  packet_writer->write_cmd_end_packet(sequence->responded, sequence->response_value, sequence->htif_exitcode);
}


cmd_service_sequence_t &device_traffic_replayer_t::peek(uint32_t hart_id)
{
  return *m_cmd_sequence_buffer[hart_id];
}

bool device_traffic_replayer_t::pop(uint32_t hart_id)
{
  cmd_service_sequence_t::free(m_cmd_sequence_buffer[hart_id]);

  auto &packet_reader = m_packet_readers[hart_id];
  auto *packet = &packet_reader->get_next_packet();

  if (packet->header.type == device_traffic_persistent::PACKET_FILE_EOF)
    return false;

  assert(packet->header.type == device_traffic_persistent::COMMAND_BEGIN);
  auto next_seq = cmd_service_sequence_t::alloc(
    packet->payload.cmd_begin_payload.device,
    packet->payload.cmd_begin_payload.cmd,
    packet->payload.cmd_begin_payload.payload,
    hart_id,
    1);
  for (
    packet = &packet_reader->get_next_packet();
    packet->header.type != device_traffic_persistent::COMMAND_END;
    packet = &packet_reader->get_next_packet())
  {
    if (packet->header.type == device_traffic_persistent::PHYSICAL_MEMORY_ACCESS)
    {
      next_seq->append_mem_trans(
        packet->payload.mem_access_payload.begin_physical_address,
        packet->payload.mem_access_payload.data,
        packet->payload.mem_access_payload.access_length,
        packet->payload.mem_access_payload.is_write);
    }
    else
    {
      throw std::runtime_error("fail to load packet data: unknown packet type " + std::to_string(packet->header.type));
    }
  }
  next_seq->responded = packet->payload.cmd_end_payload.responded;
  next_seq->response_value = packet->payload.cmd_end_payload.response_value;
  auto htif_exitcode = packet->payload.cmd_end_payload.htif_exitcode;
  assert(INT_MIN <= htif_exitcode && htif_exitcode <= INT_MAX);
  next_seq->htif_exitcode = htif_exitcode; // NOLINT(*-narrowing-conversions)
  m_cmd_sequence_buffer[hart_id] = next_seq;

  return true;
}

void device_traffic_replayer_t::get_target_spec(riscv_target_spec_t &target_spec_output)
{
  target_spec_output = m_expected_target_spec;
}

std::string device_traffic_replayer_t::identity()
{
  return "pre-recorded FESVR traffic from " + m_input_folder;
}

device_traffic_replayer_t::device_traffic_replayer_t(std::string input_folder) : m_input_folder(std::move(input_folder))
{
  std::ifstream fp_target_spec(m_input_folder + "/" + "target_spec");
  if (!fp_target_spec)
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot open target spec information.");
  }

  static_assert(sizeof(riscv_target_spec_t::mem_sz_mb) == sizeof(uint32_t), "sizeof(riscv_target_spec_t::mem_sz_mb) != sizeof(uint32_t)");
  static_assert(sizeof(riscv_target_spec_t::num_hart) == sizeof(uint32_t), "sizeof(riscv_target_spec_t::num_hart) != sizeof(uint32_t)");
  static_assert(sizeof(riscv_target_spec_t::load_elf_sha256) == 32, "sizeof(riscv_target_spec_t::load_elf_sha256) != 32");

  fp_target_spec.read((char *) &m_expected_target_spec.mem_sz_mb, sizeof(uint32_t));
  if (fp_target_spec.gcount() != sizeof(uint32_t))
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected target memory size from the target spec file.");
  }
  fp_target_spec.read((char *) &m_expected_target_spec.num_hart, sizeof(uint32_t));
  if (fp_target_spec.gcount() != sizeof(uint32_t))
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected target HART count from the target spec file.");
  }
  fp_target_spec.read((char *) m_expected_target_spec.load_elf_sha256, 32);
  if (fp_target_spec.gcount() != 32)
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected ELF SHA256 from the target spec file.");
  }
  fp_target_spec.close();

  m_cmd_sequence_buffer.resize(m_expected_target_spec.num_hart);

  for (size_t i = 0; i < m_expected_target_spec.num_hart; i++)
  {
    m_packet_readers.emplace_back(
      new device_traffic_persistent::raw_packet_reader_t(
        m_input_folder + "/" + "device_traffic_hart" + std::to_string(i)));
  }
}

bool device_traffic_replayer_t::seek(uint32_t hart_id, size_t seq_no)
{
  return m_packet_readers[hart_id]->seek(seq_no);
}

std::vector<uint8_t> device_traffic_replayer_t::get_recording_sha256(uint32_t hart_id)
{
  return m_packet_readers[hart_id]->get_recording_sha256();
}
