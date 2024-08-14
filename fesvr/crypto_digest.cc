/**
 * Cryptographic digesting wrapper of OpenSSL.
 *
 * OpenSSL 3 Message Digest API Ref:
 *   https://docs.openssl.org/3.3/man3/EVP_DigestInit/#examples
 */

#include "crypto_digest.h"

#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cassert>

crypto_digest_t::crypto_digest_t()
{
  m_md_ctx = EVP_MD_CTX_new();
  if (m_md_ctx == nullptr)
    throw std::runtime_error("Error creating EVP_MD_CTX.");
}

crypto_digest_t::crypto_digest_t(const char *digest_algo) : crypto_digest_t()
{
  crypto_digest_t::init(digest_algo);
}

crypto_digest_t::~crypto_digest_t()
{
  EVP_MD_CTX_free(m_md_ctx);
}

void crypto_digest_t::init(const char *digest_algo)
{
  const EVP_MD *md = EVP_get_digestbyname(digest_algo);
  if (md == nullptr)
    throw std::runtime_error("Unsupported digest algorithm \"" + std::string(digest_algo) + "\".");

  EVP_MD_CTX_reset(m_md_ctx);
  if (EVP_DigestInit_ex(m_md_ctx, md, nullptr) != 1)
    throw std::runtime_error("Error initializing EVP context.");
}

void crypto_digest_t::update(const void *dat, size_t len)
{
  if (EVP_DigestUpdate(m_md_ctx, dat, len) != 1)
    throw std::runtime_error("Error updating EVP context with data.");
}

std::vector<uint8_t> crypto_digest_t::final()
{
  std::vector<uint8_t> final_digest(EVP_MAX_MD_SIZE, 0);

  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(m_md_ctx, final_digest.data(), &hash_len) != 1)
    throw std::runtime_error("Error finalizing the hash computation.");
  assert(hash_len <= EVP_MAX_MD_SIZE);
  final_digest.resize(hash_len);

  return final_digest;
}

std::vector<uint8_t> crypto_digest_t::digest_buf(const char *digest_algo, const void *data, size_t len)
{
  crypto_digest_t md;
  md.init(digest_algo);
  md.update(data, len);
  return md.final();
}

std::vector<uint8_t> crypto_digest_t::digest_file(const char *digest_algo, const char *filepath, size_t *file_char_count, size_t block_size)
{
  std::ifstream fin(filepath, std::ifstream::binary);

  if (!fin)
    throw std::runtime_error("Fail to open file \"" + std::string(filepath) + "\" to in binary mode to read.");

  size_t count = 0;
  std::vector<char> buffer(block_size, 0);
  crypto_digest_t md;
  md.init(digest_algo);

  while (!fin.eof())
  {
    fin.read(buffer.data(), buffer.size()); // NOLINT(*-narrowing-conversions)
    std::streamsize s = fin.gcount();
    md.update(buffer.data(), s);
    count += s;
  }
  if (file_char_count)
    *file_char_count = count;

  return md.final();
}

std::string crypto_digest_t::to_string(const std::vector<uint8_t> &digest, bool capitalized)
{
  return to_string(digest.data(), digest.size(), capitalized);
}

std::string crypto_digest_t::to_string(const void *digest, size_t digest_len, bool capitalized)
{
  std::ostringstream hash_str;
  auto d = (uint8_t *) digest;
  hash_str << std::hex << std::setw(2) << std::setfill('0');
  if (capitalized) hash_str << std::uppercase;
  for (size_t i = 0; i < digest_len; i++)
    hash_str << uint16_t(d[i]);

  return hash_str.str();
}
