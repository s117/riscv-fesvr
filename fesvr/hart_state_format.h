/**
 * The portable format of a HART's full state, as exchanged by HTIF_CMD_DOWNLOAD_HART_FULL_STATE and
 * HTIF_CMD_UPLOAD_HART_FULL_STATE, and as stored in checkpoints.
 *
 * Every field is little-endian and encoded byte by byte, so a state saved on one host loads on any other, whatever its
 * byte order, alignment rules, compiler or build options:
 *
 *   offset  size    field
 *   0       8       magic: the ASCII bytes "RVHSTATE"
 *   8       4       version (VERSION)
 *   12      4       count: the number of entries
 *   16      16 * n  entries: u32 id, u32 reserved (0), u64 value
 *
 * An entry id is one of:
 *   [ID_CSR_BASE, ID_CSR_END)  a CSR, by its address in the target's encoding.h
 *   ID_XPR_BASE + i            integer register x[i]
 *   ID_FPR_BASE + i            floating-point register f[i] (its raw bits)
 *   ID_PC                      the pc
 *   ID_LOAD_RESERVATION        the address reserved by LR, (reg_t) -1 when none
 *
 * Which entries a state holds is decided by the target. A reader must reject a state with an id it doesn't know or
 * without one it needs, so that a mismatch is reported instead of loading a partial state. Adding an entry to the
 * format takes a new id and a new version.
 *
 * The whole state is a multiple of 8 bytes (HTIF_DATA_ALIGN).
 */

#ifndef _HART_STATE_FORMAT_H
#define _HART_STATE_FORMAT_H

#include "little_endian.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace hart_state_format
{
  static constexpr char MAGIC[8] = {'R', 'V', 'H', 'S', 'T', 'A', 'T', 'E'};
  static constexpr uint32_t VERSION = 1;
  static constexpr size_t HEADER_SIZE = 16;
  static constexpr size_t ENTRY_SIZE = 16;

  static constexpr uint32_t ID_CSR_BASE = 0x0000;
  static constexpr uint32_t ID_CSR_END = 0x1000;
  static constexpr uint32_t ID_XPR_BASE = 0x1000;
  static constexpr uint32_t ID_FPR_BASE = 0x1100;
  static constexpr uint32_t ID_PC = 0x2000;
  static constexpr uint32_t ID_LOAD_RESERVATION = 0x2001;

  struct entry_t
  {
    uint32_t id;
    uint64_t value;
  };

  /**
   * Size of a state with count entries, in bytes.
   */
  inline size_t size(uint32_t count)
  {
    return HEADER_SIZE + size_t(count) * ENTRY_SIZE;
  }

  /**
   * Write the header of a state with count entries (dst must hold size(count) bytes).
   */
  inline void put_header(uint8_t *dst, uint32_t count)
  {
    memcpy(dst, MAGIC, sizeof(MAGIC));
    little_endian::put_le32(dst + 8, VERSION);
    little_endian::put_le32(dst + 12, count);
  }

  /**
   * Write entry number index of a state.
   */
  inline void put_entry(uint8_t *state, uint32_t index, const entry_t &entry)
  {
    uint8_t *dst = state + HEADER_SIZE + size_t(index) * ENTRY_SIZE;
    little_endian::put_le32(dst, entry.id);
    little_endian::put_le32(dst + 4, 0);
    little_endian::put_le64(dst + 8, entry.value);
  }

  /**
   * Read entry number index of a state that passed check_header().
   */
  inline entry_t get_entry(const uint8_t *state, uint32_t index)
  {
    const uint8_t *src = state + HEADER_SIZE + size_t(index) * ENTRY_SIZE;
    return {little_endian::get_le32(src), little_endian::get_le64(src + 8)};
  }

  /**
   * Check that data holds a state in this format: its magic, version, and that its size matches its entry count.
   * @param[out] count The number of entries, on success.
   * @param[out] why Why the check failed, on failure.
   * @return True on success.
   */
  inline bool check_header(const uint8_t *data, size_t data_size, uint32_t &count, std::string &why)
  {
    if (data_size < HEADER_SIZE || memcmp(data, MAGIC, sizeof(MAGIC)) != 0)
    {
      why = "it is not a hart state in the portable format (no \"RVHSTATE\" magic)";
      return false;
    }
    uint32_t version = little_endian::get_le32(data + 8);
    if (version != VERSION)
    {
      why = "its hart state format version is " + std::to_string(version) + ", but this build reads version " +
            std::to_string(VERSION);
      return false;
    }
    count = little_endian::get_le32(data + 12);
    // (compared without computing size(count), which could overflow a 32-bit size_t)
    if ((data_size - HEADER_SIZE) % ENTRY_SIZE != 0 || (data_size - HEADER_SIZE) / ENTRY_SIZE != count)
    {
      why = "its hart state is " + std::to_string(data_size) + " bytes, which doesn't match its " +
            std::to_string(count) + " entries";
      return false;
    }
    return true;
  }
} // namespace hart_state_format

#endif //_HART_STATE_FORMAT_H
