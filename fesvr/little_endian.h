/**
 * Little-endian encoding of fixed-width integers, byte by byte, so that the result doesn't depend on the host's byte
 * order or alignment rules.
 */

#ifndef _LITTLE_ENDIAN_H
#define _LITTLE_ENDIAN_H

#include <cstdint>

namespace little_endian
{
  inline void put_le16(uint8_t *dst, uint16_t val)
  {
    dst[0] = uint8_t(val);
    dst[1] = uint8_t(val >> 8);
  }

  inline void put_le32(uint8_t *dst, uint32_t val)
  {
    for (int i = 0; i < 4; i++)
      dst[i] = uint8_t(val >> (8 * i));
  }

  inline void put_le64(uint8_t *dst, uint64_t val)
  {
    for (int i = 0; i < 8; i++)
      dst[i] = uint8_t(val >> (8 * i));
  }

  inline uint16_t get_le16(const uint8_t *src)
  {
    return uint16_t(src[0] | (src[1] << 8));
  }

  inline uint32_t get_le32(const uint8_t *src)
  {
    uint32_t val = 0;
    for (int i = 3; i >= 0; i--)
      val = (val << 8) | src[i];
    return val;
  }

  inline uint64_t get_le64(const uint8_t *src)
  {
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--)
      val = (val << 8) | src[i];
    return val;
  }
} // namespace little_endian

#endif //_LITTLE_ENDIAN_H
