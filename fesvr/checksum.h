/**
 * Checksum calculating wrapper of zlib.
 *
 * zlib API Ref:
 *   https://www.zlib.net/manual.html
 */

#ifndef _CRC32_UTILS_H
#define _CRC32_UTILS_H

#include <cinttypes>
#include <cstddef>
#include <string>
#include <cstdint>

class checksum_t
{
public:
  enum checksum_algo_e
  {
    CRC32,  /** CRC-32 (ITU-T V.42) */
    ADLER32 /** Adler-32 (zlib) */
  };

  explicit checksum_t(checksum_algo_e algo);

  void reset();

  void set(uint32_t new_checksum);

  uint32_t update(const void *dat, size_t len);

  uint32_t result() const;

  static uint32_t checksum_buf(checksum_algo_e algo, const void *dat, size_t len);

  static uint32_t checksum_file(checksum_algo_e algo, const char *filepath, size_t *file_char_count = nullptr, size_t block_size = 4096);

  static std::string to_string(uint32_t checksum, bool capitalized = false);

private:
  uint32_t m_checksum;
  const uintptr_t m_checksum_handler;
};


#endif //_CRC32_UTILS_H
