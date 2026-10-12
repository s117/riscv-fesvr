/**
 * The on-disk format of a device traffic recording: the magic numbers of its files and the packets of the .packets
 * file. The packets are written and read as these packed structs, little-endian (see little_endian.h). The .index file
 * is the magic number followed by the uint64_t offset of each command's first packet, and the .sha256 file the magic
 * number followed by the SHA256 of the .packets file. These three files are gzip-compressed by default (see
 * device_traffic_persistent.h). The recording folder also holds target_spec.data (uint32_t memory size in MB, uint32_t
 * number of HARTs, the 32-byte SHA256 of the boot ELF) and boot.elf.
 */

#ifndef _DEVICE_TRAFFIC_FORMAT_H
#define _DEVICE_TRAFFIC_FORMAT_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include "little_endian.h"

namespace device_traffic_persistent
{
  static const uint32_t PACKETS_FILE_MAGIC = 0x38837587; /** Dialing DVTF-PKTS on an ITU-T E.161 keypad */
  static const uint32_t INDEX_FILE_MAGIC = 0x38834639;   /** Dialing DVTF-INDX on an ITU-T E.161 keypad */
  static const uint32_t SHA256_FILE_MAGIC = 0x38833478;  /** Dialing DVTF-DGST on an ITU-T E.161 keypad */
  static const char *const BOOT_ELF_FILE_NAME = "boot.elf"; /** The ELF loaded at boot, saved in the recording folder */


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
    int32_t type; /** Packet type, a packet_type_t (stored with a fixed width, as the size of an enum may vary). */

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
        break;
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

  // The layout of the packets in the files, whatever the compiler and host ABI
  static_assert(sizeof(packet_header_t) == 4, "packet_header_t layout");
  static_assert(sizeof(cmd_begin_payload_t) == 10 && offsetof(cmd_begin_payload_t, payload) == 2, "cmd_begin_payload_t layout");
  static_assert(sizeof(phy_mem_access_payload_t) == 13 && offsetof(phy_mem_access_payload_t, access_length) == 8 &&
                  offsetof(phy_mem_access_payload_t, data) == 13, "phy_mem_access_payload_t layout");
  static_assert(sizeof(cmd_end_payload_t) == 21 && offsetof(cmd_end_payload_t, response_value) == 1 &&
                  offsetof(cmd_end_payload_t, htif_exitcode) == 9 && offsetof(cmd_end_payload_t, crc32) == 17,
                "cmd_end_payload_t layout");
} // namespace device_traffic_persistent

#endif //_DEVICE_TRAFFIC_FORMAT_H
