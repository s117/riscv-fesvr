//
// Created by john on 7/18/24.
//

#include "device_traffic_persistent.h"
#include "crc32.h"
#include <cstring>

namespace device_traffic_persistent
{
  // public
  raw_packet_reader_t::raw_packet_reader_t(const std::string &path)
      : m_path(path),
        m_index_istream((path + ".index").c_str()),
        m_packets_istream((path + ".packets").c_str()),
        m_packet_buffer(4096),
        m_next_cmd_seq_no(0),
        m_current_command_active(false),
        m_cumulative_crc32(crc32::INIT_CRC32)
  {
    uint32_t packets_file_magic;
    uint32_t index_file_magic;

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
      m_cumulative_crc32 = crc32::INIT_CRC32;
    }
    else
    {
      pkt_data_offset = m_packets_index[cmd_seq_no];
      assert(pkt_data_offset > sizeof(cmd_end_payload_t::crc32));
      pkt_data_offset -= sizeof(cmd_end_payload_t::crc32);
      m_packets_istream.seekg(pkt_data_offset);
      get_raw_data(&m_cumulative_crc32, sizeof(m_cumulative_crc32), false);
      update_crc32(&m_cumulative_crc32, sizeof(m_cumulative_crc32));
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
    size_t packet_base_size, payload_base_size, payload_extra_size;

    // get the packet base header part
    packet_base_size = packet_t::base_size();
    if (get_raw_data(&tmp, packet_base_size, !m_current_command_active) == EOF)
    {
      // reached the end of the device traffic packets file?
      if (num_commands() != m_next_cmd_seq_no)
        throw std::runtime_error(
          "malformed device traffic input: device traffic early termination, expect to contain " +
          std::to_string(num_commands()) + " commands, but terminated after " + std::to_string(m_next_cmd_seq_no) + " commands.");

      m_packet_buffer.reserve(packet_t::base_size());
      auto &packet_buf_ref = reinterpret_cast<packet_t &>(*&m_packet_buffer[0]);
      packet_buf_ref.type = PACKET_FILE_EOF;
      return packet_buf_ref;
    }

    // validate the packet header and determine the size of payload base header
    switch (tmp.type)
    {
    case COMMAND_BEGIN:
      if (m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected COMMAND_BEGIN packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_base_size));
      payload_base_size = cmd_begin_payload_t::payload_size();
      break;
    case PHYSICAL_MEMORY_ACCESS:
      if (!m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected PHYSICAL_MEMORY_ACCESS packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_base_size));
      payload_base_size = phy_mem_access_payload_t::payload_size(0);
      break;
    case COMMAND_END:
      if (!m_current_command_active)
        throw std::runtime_error(
          "malformed device traffic input: unexpected COMMAND_END packet at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_base_size));
      payload_base_size = cmd_end_payload_t::payload_size();
      break;
    default:
      throw std::runtime_error(
        "malformed device traffic input: unknown packet type " + std::to_string(tmp.type) + " at " + std::to_string(static_cast<size_t>(m_packets_istream.tellg()) - packet_base_size));
    }


    // get the payload base header part
    get_raw_data(((uint8_t *) &tmp) + packet_base_size, payload_base_size, false);
    payload_extra_size = tmp.packet_size() - packet_base_size - payload_base_size;

    // reserve enough memory for the full packet, then read extra payload (if any)
    m_packet_buffer.reserve(packet_base_size + payload_base_size + payload_extra_size);
    memcpy(&m_packet_buffer[0], &tmp, packet_base_size + payload_base_size);
    if (payload_extra_size)
    {
      get_raw_data(&m_packet_buffer[packet_base_size + payload_base_size], payload_extra_size, false);
    }

    if (tmp.type == COMMAND_BEGIN)
    {
      command_began();
    }

    // perform CRC32 checksum validation
    check_crc32();

    if (tmp.type == COMMAND_END)
    {
      command_finished();
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
    return m_cumulative_crc32 = crc32::crc32buf((const char *) data, len, m_cumulative_crc32);
  }

  // protected
  void raw_packet_reader_t::check_crc32()
  {
    assert(m_current_command_active);

    auto *packet_buf = (packet_t *) &m_packet_buffer[0];
    if (packet_buf->type == COMMAND_END)
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
  void raw_packet_reader_t::command_began()
  {
    assert(!m_current_command_active);

    m_current_command_active = true;
  }

  // protected
  void raw_packet_reader_t::command_finished()
  {
    assert(m_current_command_active);

    m_current_command_active = false;
    m_next_cmd_seq_no += 1;
  }

  // public
  raw_packet_writer_t::raw_packet_writer_t(const std::string &path)
      : m_path(path),
        m_index_ostream((path + ".index").c_str()),
        m_packets_ostream((path + ".packets").c_str()),
        m_packet_buf(4096),
        m_packet_buf_empty(true),
        m_current_command_active(false),
        m_cumulative_crc32(crc32::INIT_CRC32)
  {
    m_index_ostream.write((const char *) &INDEX_FILE_MAGIC, sizeof(INDEX_FILE_MAGIC));
    m_index_ostream.flush();
    m_packets_ostream.write((const char *) &PACKETS_FILE_MAGIC, sizeof(PACKETS_FILE_MAGIC));
    m_current_packet_offset = sizeof(PACKETS_FILE_MAGIC);
    m_packets_ostream.flush();

    if (!m_packets_ostream)
      throw std::runtime_error("Cannot open file to write device traffic packets: " + path + ".packets");
    if (!m_index_ostream)
      throw std::runtime_error("Cannot open file to write device traffic index: " + path + ".index");
  }

  // public
  size_t raw_packet_writer_t::write_cmd_begin_packet(const uint8_t device, const uint8_t cmd, const uint64_t payload)
  {
    command_began();

    const auto packet_size = packet_t::base_size() + cmd_begin_payload_t::payload_size();
    auto &packet_buf_ref = get_packet_buf(packet_size);

    packet_buf_ref.type = COMMAND_BEGIN;
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
    const auto packet_size = packet_t::base_size() + phy_mem_access_payload_t::payload_size(access_length);
    auto &packet_buf_ref = get_packet_buf(packet_size);

    packet_buf_ref.type = PHYSICAL_MEMORY_ACCESS;
    packet_buf_ref.payload.mem_access_payload.begin_physical_address = begin_address;
    packet_buf_ref.payload.mem_access_payload.is_write = is_write;
    packet_buf_ref.payload.mem_access_payload.access_length = access_length;
    memcpy(packet_buf_ref.payload.mem_access_payload.data, data, access_length);

    assert(packet_buf_ref.packet_size() == packet_size);
    update_crc32(&packet_buf_ref, packet_buf_ref.packet_size());
    return flush_packet_buf();
  }

  // public
  size_t raw_packet_writer_t::write_cmd_end_packet(const bool responded, const uint64_t respond_value, const uint64_t htif_exitcode)
  {
    const auto packet_size = packet_t::base_size() + cmd_end_payload_t::payload_size();
    auto &packet_buf_ref = get_packet_buf(packet_size);


    packet_buf_ref.type = COMMAND_END;
    packet_buf_ref.payload.cmd_end_payload.responded = responded ? 1 : 0;
    packet_buf_ref.payload.cmd_end_payload.respond_value = respond_value;
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
  void raw_packet_writer_t::command_began()
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

    return m_cumulative_crc32 = crc32::crc32buf(reinterpret_cast<const char *>(data), len, m_cumulative_crc32);
  }
} // namespace device_traffic_persistent


void device_traffic_recorder_t::close()
{
  for (auto &writer: m_raw_packet_writers)
  {
    writer.second->close();
  }
}

void device_traffic_recorder_t::on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[])
{
  for (size_t i = 0; i < target_core_count; i++)
  {
    m_raw_packet_writers.emplace(
      i,
      new device_traffic_persistent::raw_packet_writer_t(m_output_base_folder + PATH_SEP + "device_traffic_core" + std::to_string(i)));
  }
  // export system spec information
  std::ofstream system_spec_output_stream(m_output_base_folder + PATH_SEP + "target_spec");
  system_spec_output_stream.write((const char *) &target_memory_mb, sizeof(target_memory_mb));
  system_spec_output_stream.write((const char *) &target_core_count, sizeof(target_core_count));
  system_spec_output_stream.write((const char *) loaded_elf_sha256, 256 / 8);
  system_spec_output_stream.close();
  m_initialized = true;
}

void device_traffic_recorder_t::on_cmd_serviced(cmd_service_sequence_t *sequence)
{
  assert(m_initialized);
  auto &packet_writer = m_raw_packet_writers[sequence->core_id];
  packet_writer->write_cmd_begin_packet(sequence->device, sequence->cmd, sequence->payload);
  for (auto &mem_transaction: sequence->mem_transactions)
  {
    packet_writer->write_phy_mem_access_packet(mem_transaction.addr, mem_transaction.is_write, mem_transaction.data.size(), &mem_transaction.data[0]);
  }
  packet_writer->write_cmd_end_packet(sequence->responded, sequence->respond_value, sequence->htif_exitcode);
}


cmd_service_sequence_t &device_traffic_replayer_t::peek(uint32_t core_id)
{
  return *m_cmd_sequence_buffer[core_id];
}

void device_traffic_replayer_t::pop(uint32_t core_id)
{
  cmd_service_sequence_t::free(m_cmd_sequence_buffer[core_id]);

  auto &packet_reader = m_packet_readers[core_id];
  auto *packet = &packet_reader->get_next_packet();

  if (packet->type == device_traffic_persistent::PACKET_FILE_EOF)
    return;

  assert(packet->type == device_traffic_persistent::COMMAND_BEGIN);
  auto next_seq = cmd_service_sequence_t::alloc(
    packet->payload.cmd_begin_payload.device,
    packet->payload.cmd_begin_payload.cmd,
    packet->payload.cmd_begin_payload.payload,
    core_id,
    1);
  for (
    packet = &packet_reader->get_next_packet();
    packet->type != device_traffic_persistent::COMMAND_END;
    packet = &packet_reader->get_next_packet())
  {
    if (packet->type == device_traffic_persistent::PHYSICAL_MEMORY_ACCESS)
    {
      next_seq->append_mem_trans(
        packet->payload.mem_access_payload.begin_physical_address,
        packet->payload.mem_access_payload.data,
        packet->payload.mem_access_payload.access_length,
        packet->payload.mem_access_payload.is_write);
    }
    else
    {
      throw std::runtime_error("fail to load packet data: unknown packet type " + std::to_string(packet->type));
    }
  }
  next_seq->responded = packet->payload.cmd_end_payload.responded;
  next_seq->respond_value = packet->payload.cmd_end_payload.respond_value;
  auto htif_exitcode = packet->payload.cmd_end_payload.htif_exitcode;
  assert(INT_MIN <= htif_exitcode && htif_exitcode <= INT_MAX);
  next_seq->htif_exitcode = htif_exitcode; // NOLINT(*-narrowing-conversions)
  m_cmd_sequence_buffer[core_id] = next_seq;
}

void device_traffic_replayer_t::get_target_spec(uint32_t &target_memory_mb, uint32_t &target_core_count, uint8_t loaded_elf_sha256[256 / 8])
{
  target_memory_mb = m_expected_target_memory_mb;
  target_core_count = m_expected_target_core_count;
  memcpy(loaded_elf_sha256, m_expected_loaded_elf_sha256, sizeof(m_expected_loaded_elf_sha256));
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
  fp_target_spec.read((char *) &m_expected_target_memory_mb, sizeof(m_expected_target_memory_mb));
  if (fp_target_spec.gcount() != sizeof(m_expected_target_memory_mb))
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected target memory from the target spec file.");
  }
  fp_target_spec.read((char *) &m_expected_target_core_count, sizeof(m_expected_target_core_count));
  if (fp_target_spec.gcount() != sizeof(m_expected_target_core_count))
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected target core count from the target spec file.");
  }
  fp_target_spec.read((char *) m_expected_loaded_elf_sha256, sizeof(m_expected_loaded_elf_sha256));
  if (fp_target_spec.gcount() != sizeof(m_expected_loaded_elf_sha256))
  {
    throw std::runtime_error("fail to load pre-recorded FESVR device traffic: cannot load expected ELF SHA256 from the target spec file.");
  }
  fp_target_spec.close();

  m_cmd_sequence_buffer.resize(m_expected_target_core_count);

  for (size_t i = 0; i < m_expected_target_core_count; i++)
  {
    m_packet_readers.emplace_back(
      new device_traffic_persistent::raw_packet_reader_t(
        m_input_folder + "/" + "device_traffic_core" + std::to_string(i)));
    device_traffic_replayer_t::pop(i);
  }
}

bool device_traffic_replayer_t::seek(uint32_t core_id, size_t seq_no)
{
  return m_packet_readers[core_id]->seek(seq_no);
}
