/* Crc - 32 BIT ANSI X3.66 CRC checksum files */
/* Copyright (C) 1986 Gary S. Brown.  You may use this program, or
   code or tables extracted from it, as desired without restriction.*/

/* Converted to standalone C++ implementation by Jiayang Li, 2024.   */

#ifndef CRC32_H
#define CRC32_H
#include <cinttypes>
#include <cstddef>

class crc32
{
public:
  static constexpr uint32_t INIT_CRC32 = 0xFFFFFFFF;
  static uint32_t updateCRC32(unsigned char ch, uint32_t crc);
  static bool crc32file(const char *name, uint32_t *crc, int64_t *charcnt);
  static uint32_t crc32buf(const char *buf, size_t len, uint32_t oldcrc32 = INIT_CRC32);
};


#endif //CRC32_H
