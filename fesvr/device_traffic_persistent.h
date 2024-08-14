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
#include <cstdint>
#include "device_traffic_capture.h"
#include "checksum.h"

namespace device_traffic_persistent
{
  static const uint32_t PACKETS_FILE_MAGIC = 0x38837587; /** Dialing DVTF-PKTS on an ITU-T E.161 keypad */
  static const uint32_t INDEX_FILE_MAGIC = 0x38834639;   /** Dialing DVTF-INDX on an ITU-T E.161 keypad */
  static const uint32_t SHA256_FILE_MAGIC = 0x38833478;  /** Dialing DVTF-DGST on an ITU-T E.161 keypad */


  enum packet_type_t
  {
    COMMAND_BEGIN = 0,          /** The packet payload is cmd_begin_payload_t */
    PHYSICAL_MEMORY_ACCESS = 1, /** The packet payload is phy_mem_access_payload_t */
    COMMAND_END = 128,          /** The packet payload is cmd_end_payload_t */
    PACKET_FILE_EOF = -1,       /** Fractal packet type. If a packet of this type is returned by the packet reader, it means the reader has reached the end of the packet file. */
  };

#pragma pack(push, 1)

  struct packet_header_t
  {
    packet_type_t type; /** Packet type. */

    /**
     * Get the size of the packet header.
     * @return Size in bytes.
     */
    static constexpr size_t header_size()
    {
      return sizeof(packet_header_t);
    }
  };

  /**
   * The payload of a #COMMAND_BEGIN packet, fix-length.
   *
   * This packet marks the beginning of a recorded FESVR device command.
   * All the following packets describe the operations that FESVR performed in order to service this device command.
   * Another #COMMAND_BEGIN packet shall not appears until encountering a #COMMAND_END packet (which marks the end of the current command).
   */
  struct cmd_begin_payload_t
  {
    uint8_t device;   /** Device ID.  */
    uint8_t cmd;      /** Command ID. */
    uint64_t payload; /** Command payload. */

    /**
     * Get the size of this type of payload.
     * @return Size in bytes.
     */
    static constexpr size_t payload_size()
    {
      return sizeof(cmd_begin_payload_t);
    }
  };

  /**
   * The payload of a #PHYSICAL_MEMORY_ACCESS packet, variable-length.
   *
   * This packet describe a physical memory access to the target in order to service the current device command.
   * It can only appears inside a #COMMAND_BEGIN and #COMMAND_END packets pair.
   */
  struct phy_mem_access_payload_t
  {
    uint64_t begin_physical_address; /** Memory access base (physical, 64bit) */
    uint32_t access_length;          /** Number of bytes accessed. */
    uint8_t is_write;                /** 0 - Memory Read, 1 - Memory Write */
    uint8_t data[];                  /** Access data. */

    /**
     * Get the size of this type of payload.
     * @param access_length The "access_length" field of the payload.
     * @return Size in bytes.
     */
    static constexpr size_t payload_size(const size_t access_length)
    {
      return sizeof(phy_mem_access_payload_t) + sizeof(*((const phy_mem_access_payload_t *) nullptr)->data) * access_length;
    }
  };

  /**
   * The payload of #COMMAND_END packet, fix-length.
   *
   * This packet marks the end of the current device command. It shall not appears again until another #COMMAND_BEGIN packet.
   */
  struct cmd_end_payload_t
  {
    uint8_t responded;       /** Did this device command end with a respond? (a write to HART's fromhost CSR) */
    uint64_t response_value; /** (cont.) If yes, this is the responded value. */
    int64_t htif_exitcode;   /** The "htif_exitcode" field of htif_t after this command was serviced. */
    uint32_t crc32;          /** An ITU-T V.42 CRC32 (pure CRC32 with XOR 0xffffffff post-conditioning) of all the bytes from the beginning of the file till this point. */

    /**
     * Get the size of this type of payload.
     * @return Size in bytes.
     */
    static constexpr size_t payload_size()
    {
      return sizeof(cmd_end_payload_t);
    }
  };

  /**
   * The structure of a packet.
   */
  struct packet_t
  {
    packet_header_t header; /** Fix-length packet header */
    union {
      cmd_begin_payload_t cmd_begin_payload;
      phy_mem_access_payload_t mem_access_payload;
      cmd_end_payload_t cmd_end_payload;
    } payload; /** Variable-length packet payload */

    /**
     * Get size of header part of the packet.
     * @return Size in bytes.
     */
    static constexpr size_t header_size()
    {
      static_assert(offsetof(packet_t, payload) == packet_header_t::header_size(), "Unexpected padding happened in packet_t.");
      return offsetof(packet_t, payload);
    }

    /**
     * Get size of payload part of the packet.
     * @return Size in bytes.
     */
    size_t payload_size() const
    {
      size_t payload_size;
      switch (header.type)
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
        payload_size = SIZE_MAX - header_size();
        assert(0);
      }
      return payload_size;
    }

    /**
     * Get size of the entire packet.
     * @return Size in bytes.
     */
    size_t packet_size() const
    {
      return header_size() + payload_size();
    }
  };

#pragma pack(pop)

  /**
   * The device traffic are saved as a sequence of COMMAND_BEGIN, PHYSICAL_MEMORY_ACCESS, COMMAND_END packets.
   * This is the reader for the saved packet file.
   */
  class raw_packet_reader_t
  {
  public:
    /**
     * Construct a new reader. The provided path is a base path. Three files will be opened to read:
     *  1. {path}.index - The file containing the packets index information.
     *  2. {path}.packets - The file containing the actual packets data.
     *  3. {path}.sha256 - The file containing the SHA256 hash of the {path}.packet.
     *
     * @param path Base path to where the three files are located.
     * @throw std::runtime_error If any of the three files are missing, or failed to load data from them.
     */
    explicit raw_packet_reader_t(const std::string &path);

    /**
     * Seek the read position to the beginning packet of the requested command.
     * @param cmd_seq_no Sequence number of the requested command, start from 0.
     * @return Whether the seek was succeed.
     * @throw std::runtime_error If the index file contains the offset of the requested command, but it is not a valid offset for the packet file.
     */
    bool seek(size_t cmd_seq_no);

    /**
     * Get the next packet from the file. It will advance the read position.
     *  1. If returning a COMMAND_END packet, its checksum must have been verified.
     *  2. If returning a PACKET_FILE_EOF packet, it means the reader has reach to the end of the packet file.
     * @return The next packet in the file, or a fractal PACKET_FILE_EOF packet indicating reaching the end of the file.
     * @throw std::runtime_error On malformed packet file, or checksum verification failure.
     */
    const packet_t &get_next_packet();

    /**
     * Get the total number of commands the underlying file stored.
     * Note that the number of commands is not the number of raw packet (a command is recorded in multiple raw packets).
     * @return Total number of commands.
     */
    size_t num_commands() const;

    /**
     * Get the SHA256 of the {path}.packets file.
     * Be aware the returned SHA256 is just the pre-calculated value saved in the {path}.sha256 file for speed consideration.
     * @return The pre-calculated SHA256 of the {path}.packets file (read from the {path}.sha256 file).
     */
    std::vector<uint8_t> get_recording_sha256() { return m_recording_sha256; }

  protected:
    /**
     * Get raw data from the packet file.
     * @param dst Output buffer.
     * @param n Number of bytes to read.
     * @param accept_eof If set to true and encountered EOF before getting any data, the function will return with EOF, otherwise it will throw a std::runtime_error.
     * @return Read count, or EOF if #accept_eof is true and zero data was read.
     * @throw std::runtime_error If failed to read enough data or reached an unexpected EOF.
     */
    ssize_t get_raw_data(void *dst, const ssize_t n, bool accept_eof);

    /**
     * Perform CRC32 check.
     */
    void check_crc32();

    /**
     * Update the cumulative CRC32.
     * @param data Input data.
     * @param len Length of data.
     * @return The ITU-T V.42 CRC32 (pure CRC32 with XOR 0xffffffff post-conditioning).
     */
    uint32_t update_crc32(const void *data, size_t len);

    /**
     * Update internal states upon a command begin.
     */
    void command_begin();

    /**
     * Update internal states upon a command end.
     */
    void command_end();

#ifdef FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT
    using raw_inputstream_t = igzstream;
#else
    using raw_inputstream_t = std::ifstream;
#endif


    raw_inputstream_t m_index_istream;       /** File input stream for {path}.index. */
    raw_inputstream_t m_packets_istream;     /** File input stream for {path}.packets. */
    raw_inputstream_t m_sha256_istream;      /** File input stream for {path}.sha256. */

    std::string m_path;                      /** The base path of the underlying input files. */

    std::vector<uint8_t> m_packet_buffer;    /** Buffer to hold packet data obtained from file. */

    size_t m_next_cmd_seq_no;                /** The sequence number of the next command to return. */

    uint32_t m_current_command_active;       /** Set to true when returning a COMMAND_BEGIN packet, and to false when returning a COMMAND_END packet. */

    checksum_t m_cumulative_checksum;        /** The CRC32 since the beginning of the packet file. However, due to the mathematical property of CRC32, its only affected by the data since the last COMMAND_END packet. */

    std::vector<size_t> m_packets_index;     /** An array storing the begin offset for each command. Indexed by the command sequence number. */

    std::vector<uint8_t> m_recording_sha256; /** The SHA256 read from the {path}.sha256 file. It is a pre-calculated SHA256 of {path}.packets */
  };

  /**
   * The device traffic are saved as a sequence of COMMAND_BEGIN, PHYSICAL_MEMORY_ACCESS, COMMAND_END packets.
   * This is the writer to created saved packet file.
   */
  class raw_packet_writer_t
  {
  public:
    /**
     * Construct a new writer. The provided path is a base path. Three files will be created to write:
     *  1. {path}.index - The file to save the packets index information.
     *  2. {path}.packets - The file to save the actual packets data.
     *  3. {path}.sha256 - The file to save the SHA256 hash of the {path}.packet.
     *
     * The index generation and sha256 calculation are automatically handled.
     *
     * @param path Base path to where the three files are to be created.
     * @throw std::runtime_error If failed to open any of the three files.
     */
    explicit raw_packet_writer_t(const std::string &path);

    /**
     * Write a COMMAND_BEGIN packet.
     *
     * @param device The device ID field of the command.
     * @param cmd The command field of the command.
     * @param payload The payload field of the command.
     * @return Size of the packet.
     */
    size_t write_cmd_begin_packet(const uint8_t device, const uint8_t cmd, const uint64_t payload);

    /**
     * Write a PHYSICAL_MEMORY_ACCESS packet.
     *
     * @param begin_address The physical memory address.
     * @param is_write Whether the access is a memory write.
     * @param access_length Length of the access.
     * @param data Data of the access.
     * @return Size of the packet.
     */
    size_t write_phy_mem_access_packet(const uint64_t begin_address, const bool is_write, const uint64_t access_length, const uint8_t data[]);

    /**
     * Write a COMMAND_END packet.
     *
     * @param responded Did this device command end with a respond? (a write to HART's fromhost CSR)
     * @param response_value If the command got a response, this is the responded value.
     * @param htif_exitcode The "htif_exitcode" field of htif_t after this command was serviced.
     * @return Size of the packet.
     */
    size_t write_cmd_end_packet(const bool responded, const uint64_t response_value, const uint64_t htif_exitcode);

    /**
     * Finalize and dump the SHA256 of the packet file. Then flush and close all output stream.
     */
    void close();

  protected:
    /**
     * Get a buffer with a size guaranteed to buffer the outputting packet.
     * @param packet_size Minimal size of the buffer in bytes.
     * @return A reference to the beginning of the buffer in #packet_t type.
     */
    packet_t &get_packet_buf(const size_t packet_size);

    /**
     * Flush the packet in the packet buffer to the output stream.
     * @return Number of bytes flushed from the buffer.
     */
    size_t flush_packet_buf();

    /**
     * Log the current packet offset to the index output stream.
     */
    void log_packet_offset_to_index();

    /**
     * Update internal states upon a command begin.
     */
    void command_begin();

    /**
     * Update internal states upon a command end.
     */
    void command_end();

    /**
     * Update the cumulative CRC32.
     * @param data Input data.
     * @param len Length of data.
     * @return The ITU-T V.42 CRC32 (pure CRC32 with XOR 0xffffffff post-conditioning).
     */
    uint32_t update_crc32(const void *data, size_t len);

#ifdef FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT
    using raw_outputstream_t = ogzstream;
#else
    using raw_outputstream_t = std::ofstream;
#endif


    raw_outputstream_t m_index_ostream;     /** File output stream for {path}.index. */
    raw_outputstream_t m_packets_ostream;   /** File output stream for {path}.packets. */
    raw_outputstream_t m_sha256_ostream;    /** File output stream for {path}.sha256. */

    std::string m_path;                     /** The base path of the underlying output files. */

    std::vector<uint8_t> m_packet_buf;      /** Buffer to hold packet data to be flushed to file. */
    bool m_packet_buf_empty;                /** Is the packet buffer empty? */

    uint64_t m_current_packet_offset;       /** The current write position in the packet output stream. */

    bool m_current_command_active;          /** Set to true when handling a write_cmd_begin_packet() call, and to false when handling a write_cmd_end_packet() call. */

    checksum_t m_cumulative_checksum;       /** The CRC32 since the beginning of the packet file. However, due to the mathematical property of CRC32, its only affected by the data since the last COMMAND_END packet. */
    crypto_digest_t m_packet_stream_sha256; /** An incrementally updated SHA256 since the beginning of the packet file. It will be finalized and dumped to the {path}.sha256 on a close() call. */
  };
} // namespace device_traffic_persistent


/**
 * The device traffic recorder can make a #cmd_service_sequence_t stream persistent by saving the stream to file system using #device_traffic_persistent::raw_packet_writer_t.
 * The stream are obtained from a #device_traffic_tap_t.
 */
class device_traffic_recorder_t : public device_traffic_listener_t
{
protected:
  static constexpr auto PATH_SEP = "/";

public:
  explicit device_traffic_recorder_t(std::string output_folder)
      : m_output_base_folder(std::move(output_folder)), m_initialized(false) {}

  void close();

  void on_target_spec_known(const riscv_target_spec_t &target_spec) override;

  void on_cmd_serviced(cmd_service_sequence_t *sequence) override;

protected:
  std::string m_output_base_folder;
  bool m_initialized;
  std::map<uint32_t, std::unique_ptr<device_traffic_persistent::raw_packet_writer_t>> m_raw_packet_writers;
};


/**
 * The device traffic replayer can recreate a saved #cmd_service_sequence_t stream from file system using #device_traffic_persistent::raw_packet_reader_t.
 * The recreated stream are presented in the #cmd_service_sequence_supplier_t interface.
 */
class device_traffic_replayer_t : public cmd_service_sequence_supplier_t
{
public:
  explicit device_traffic_replayer_t(std::string input_folder);
  void get_target_spec(riscv_target_spec_t &target_spec_output) override;
  cmd_service_sequence_t &peek(uint32_t hart_id) override;
  bool pop(uint32_t hart_id) override;
  std::string identity() override;
  bool seek(uint32_t hart_id, size_t seq_no) override;
  std::vector<uint8_t> get_recording_sha256(uint32_t hart_id) override;

protected:
  std::string m_input_folder;
  riscv_target_spec_t m_expected_target_spec{};
  std::vector<std::unique_ptr<device_traffic_persistent::raw_packet_reader_t>> m_packet_readers;
  std::vector<cmd_service_sequence_t *> m_cmd_sequence_buffer;
};

#endif //_DEVICE_TRAFFIC_PERSISTENT_H
