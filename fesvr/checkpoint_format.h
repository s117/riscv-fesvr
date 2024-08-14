/**
 * Data structures used in FESVR created checkpoint.
 */

#ifndef _CHECKPOINT_FORMAT_H
#define _CHECKPOINT_FORMAT_H

#include <cinttypes>
#include <cstddef>

#pragma pack(push, 1)

struct hart_checkpoint_t
{
  static constexpr uint32_t HART_STATE_STORAGE_MAX = 8192; // Fixed 8K-bytes space to save the state for each HART
  uint8_t traffic_recording_sha256[32];
  uint64_t traffic_skip_amt;
  uint32_t hart_state_size;
  uint8_t hart_state_storage[HART_STATE_STORAGE_MAX];
};

struct checkpoint_header_t
{
  static constexpr uint32_t RV64_CHECKPOINT_MAGIC = 0x78642578; // Dialing R V 6 4 C K P T on an ITU-T E.161 keypad

  uint32_t magic;
  uint32_t num_hart;
  uint32_t mem_sz_mb;
  uint8_t load_elf_sha256[32];
  hart_checkpoint_t harts[];

  size_t size() const
  {
    return sizeof(checkpoint_header_t) + num_hart * sizeof(hart_checkpoint_t);
  }

  static size_t size(uint32_t num_hart)
  {
    return sizeof(checkpoint_header_t) + num_hart * sizeof(hart_checkpoint_t);
  }
};

#pragma pack(pop)

#endif //_CHECKPOINT_FORMAT_H
