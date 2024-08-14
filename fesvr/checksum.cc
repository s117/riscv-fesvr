/**
 * Checksum calculating wrapper of zlib.
 *
 * zlib API Ref:
 *   https://www.zlib.net/manual.html
 */

#include "checksum.h"

#include <zlib.h>

#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

typedef uLong (*checksum_handler_t)(uLong crc, const Bytef *buf, z_size_t len);

checksum_t::checksum_t(checksum_t::checksum_algo_e algo)
    : m_checksum(0), m_checksum_handler(
                       algo == CRC32 ? uintptr_t(crc32_z) : algo == ADLER32 ? uintptr_t(adler32_z)
                                                                            : uintptr_t(nullptr))
{
  switch (algo)
  {
  case CRC32:
  case ADLER32:
    break;
  default:
    throw std::runtime_error("Unsupported checksum algorithm.");
  }
}

void checksum_t::reset()
{
  m_checksum = ((checksum_handler_t) m_checksum_handler)(0, Z_NULL, 0);
}

void checksum_t::set(uint32_t new_checksum)
{
  m_checksum = new_checksum;
}

uint32_t checksum_t::result() const
{
  return m_checksum;
}

uint32_t checksum_t::update(const void *dat, size_t len)
{
  return m_checksum = ((checksum_handler_t) m_checksum_handler)(m_checksum, (const Bytef *) dat, len);
}

uint32_t checksum_t::checksum_buf(checksum_algo_e algo, const void *dat, size_t len)
{

  checksum_t checksum_inst(algo);
  checksum_inst.reset();
  return checksum_inst.update(dat, len);
}

uint32_t checksum_t::checksum_file(checksum_algo_e algo, const char *filepath, size_t *file_char_count, size_t block_size)
{
  std::ifstream fin(filepath, std::ifstream::binary);

  if (!fin)
    throw std::runtime_error("Fail to open file \"" + std::string(filepath) + "\" to in binary mode to read.");

  size_t count = 0;
  std::vector<char> buffer(block_size, 0);
  checksum_t checksum_inst(algo);
  checksum_inst.reset();

  while (!fin.eof())
  {
    fin.read(buffer.data(), buffer.size()); // NOLINT(*-narrowing-conversions)
    std::streamsize s = fin.gcount();
    checksum_inst.update(buffer.data(), s);
    count += s;
  }
  if (file_char_count)
    *file_char_count = count;

  return checksum_inst.m_checksum;
}

std::string checksum_t::to_string(uint32_t checksum, bool capitalized)
{
  std::ostringstream hash_str;

  hash_str << std::hex << std::setw(8) << std::setfill('0');
  if (capitalized) hash_str << std::hex << std::uppercase;
  hash_str << checksum;

  return hash_str.str();
}
