//
// Created by john on 7/18/24.
//

#ifndef _DEVICE_TRAFFIC_PERSISTENT_H
#define _DEVICE_TRAFFIC_PERSISTENT_H

#include <cinttypes>
#include <cstddef>
#include <cassert>
#include "gzstream.h"
#include <fstream>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <memory>
#include "device_traffic_forwarding.h"

namespace device_traffic_persistent
{
  static const uint32_t PACKETS_FILE_MAGIC = 0x72255758; // Dialing S C A L L P K T on an ITU-T E.161 keypad
  static const uint32_t INDEX_FILE_MAGIC = 0x72255439;   // Dialing S C A L L I D X on an ITU-T E.161 keypad

  enum packet_type_t
  {
    COMMAND_BEGIN = 0,
    PHYSICAL_MEMORY_ACCESS = 1,
    COMMAND_END = 128,
    PACKET_FILE_EOF = -1,
  };

#pragma pack(push, 1)

  struct cmd_begin_payload_t
  {
    uint8_t device;   /**< Device ID.  */
    uint8_t cmd;      /**< Command ID. */
    uint64_t payload; /**< Command payload. */

    static size_t payload_size()
    {
      return sizeof(cmd_begin_payload_t);
    }
  };

  struct phy_mem_access_payload_t
  {
    uint64_t begin_physical_address; /**< Memory access base (physical, 64bit) */
    uint32_t access_length;          /**< Number of bytes accessed. */
    uint8_t is_write;                /**< 0 - Memory Read, 1 - Memory Write */
    uint8_t data[];                  /**< Access data. */

    static size_t payload_size(const size_t data_length)
    {
      return sizeof(phy_mem_access_payload_t) + sizeof(*((const phy_mem_access_payload_t *) nullptr)->data) * data_length;
    }
  };

  struct cmd_end_payload_t
  {
    uint8_t responded;      /**< Does this command end with a HTIF respond packet? */
    uint64_t respond_value; /**< (cont.) If yes, this is the responded value. */
    int64_t htif_exitcode;  /**< The HTIF return code being set after this command is serviced. */
    uint32_t crc32;         /** CRC32 of all the bytes from the invoke packet to the ret_code. */

    static size_t payload_size()
    {
      return sizeof(cmd_end_payload_t);
    }
  };

  struct packet_t
  {
    packet_type_t type; /**< Packet type. */
    union {
      cmd_begin_payload_t cmd_begin_payload;
      phy_mem_access_payload_t mem_access_payload;
      cmd_end_payload_t cmd_end_payload;
    } payload; /**< Packet Payload */

    static size_t base_size()
    {
      return offsetof(packet_t, payload);
    }

    size_t payload_size() const
    {
      size_t payload_size;
      switch (type)
      {
      case COMMAND_BEGIN:
        payload_size = cmd_begin_payload_t::payload_size();
        break;
      case PHYSICAL_MEMORY_ACCESS:
        payload_size = phy_mem_access_payload_t::payload_size(payload.mem_access_payload.access_length);
        break;
      case COMMAND_END:
        payload_size = cmd_end_payload_t::payload_size();
        break;
      case PACKET_FILE_EOF:
        payload_size = 0;
      default:
        payload_size = SIZE_MAX - base_size();
        assert(0);
      }
      return payload_size;
    }

    size_t packet_size() const
    {
      return base_size() + payload_size();
    }
  };

#pragma pack(pop)

  class raw_packet_reader_t
  {
  public:
    explicit raw_packet_reader_t(const std::string &path);

    bool seek(size_t cmd_seq_no);

    const packet_t &get_next_packet();

    size_t num_commands() const;

  protected:
    ssize_t get_raw_data(void *dst, const ssize_t n, bool accept_eof);

    void check_crc32();

    uint32_t update_crc32(const void *data, size_t len);

    void command_began();

    void command_finished();


    std::string m_path;

#ifdef FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT
    igzstream m_index_istream;
    igzstream m_packets_istream;
#else
    std::ifstream m_index_istream;
    std::ifstream m_packets_istream;
#endif

    std::vector<uint8_t> m_packet_buffer;

    size_t m_next_cmd_seq_no;

    uint32_t m_current_command_active;

    uint32_t m_cumulative_crc32;

    std::vector<size_t> m_packets_index;
  };


  class raw_packet_writer_t
  {
  public:
    explicit raw_packet_writer_t(const std::string &path);

    size_t write_cmd_begin_packet(const uint8_t device, const uint8_t cmd, const uint64_t payload);

    size_t write_phy_mem_access_packet(const uint64_t begin_address, const bool is_write, const uint64_t access_length, const uint8_t data[]);

    size_t write_cmd_end_packet(const bool responded, const uint64_t respond_value, const uint64_t htif_exitcode);

    void close();

  protected:
    packet_t &get_packet_buf(const size_t packet_size);

    size_t flush_packet_buf();

    void log_packet_offset_to_index();

    void command_began();

    void command_end();

    uint32_t update_crc32(const void *data, size_t len);

    std::string m_path;

#ifdef SCALL_TRACE_UNCOMPRESSED_OUTPUT
    std::ofstream m_index_ostream;
    std::ofstream m_packets_ostream;
#else
    ogzstream m_index_ostream;
    ogzstream m_packets_ostream;
#endif


    std::vector<uint8_t> m_packet_buf;
    bool m_packet_buf_empty;

    uint64_t m_current_packet_offset;

    bool m_current_command_active;

    uint32_t m_cumulative_crc32;
  };
} // namespace device_traffic_persistent

// To save device traffic in a packet based format
class device_traffic_recorder_t : public device_traffic_listener_t
{
protected:
  static constexpr auto PATH_SEP = "/";

public:
  explicit device_traffic_recorder_t(std::string output_folder)
      : m_output_base_folder(std::move(output_folder)), m_initialized(false) {}

  void close();

  void on_target_spec_obtained(uint32_t target_memory_mb, uint32_t target_core_count, const uint8_t loaded_elf_sha256[]) override;

  void on_cmd_serviced(cmd_service_sequence_t *sequence) override;;

protected:
  std::string m_output_base_folder;
  bool m_initialized;
  std::map<uint32_t, std::unique_ptr<device_traffic_persistent::raw_packet_writer_t>> m_raw_packet_writers;
};

// To convert saved device traffic packets to command service sequence
class device_traffic_replayer_t : public cmd_service_sequence_supplier_t
{
public:
  explicit device_traffic_replayer_t(std::string input_folder);
  void get_target_spec(uint32_t &target_memory_mb, uint32_t &target_core_count, uint8_t loaded_elf_sha256[256 / 8]) override;
  cmd_service_sequence_t &peek(uint32_t core_id) override;
  void pop(uint32_t core_id) override;
  std::string identity() override;
  bool seek(uint32_t core_id, size_t seq_no);

protected:
  std::string m_input_folder;
  uint32_t m_expected_target_memory_mb{};
  uint32_t m_expected_target_core_count{};
  uint8_t m_expected_loaded_elf_sha256[256 / 8]{};
  std::vector<std::unique_ptr<device_traffic_persistent::raw_packet_reader_t>> m_packet_readers;
  std::vector<cmd_service_sequence_t *> m_cmd_sequence_buffer;
};

#endif //_DEVICE_TRAFFIC_PERSISTENT_H
