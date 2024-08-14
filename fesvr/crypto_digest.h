/**
 * Cryptographic digesting wrapper of OpenSSL.
 *
 * OpenSSL 3 Message Digest API Ref:
 *   https://docs.openssl.org/3.3/man3/EVP_DigestInit/#examples
 */


#ifndef _CRYPTO_DIGEST_H
#define _CRYPTO_DIGEST_H

#include <openssl/evp.h>
#include <vector>
#include <string>

class crypto_digest_t
{
private:
  EVP_MD_CTX *m_md_ctx;

public:
  explicit crypto_digest_t();

  explicit crypto_digest_t(const char *digest_algo);

  ~crypto_digest_t();

  void init(const char *digest_algo);

  void update(const void *dat, size_t len);

  std::vector<uint8_t> final(); // Note: once final() is called, no further call to update() will be allowed until after a reset() call.

  static std::vector<uint8_t> digest_buf(const char *digest_algo, const void *data, size_t len);

  static std::vector<uint8_t> digest_file(const char *digest_algo, const char *filepath, size_t *file_char_count = nullptr, size_t block_size = 4096);

  static std::string to_string(const std::vector<uint8_t> &digest, bool capitalized = false);
  static std::string to_string(const void *digest, size_t digest_len, bool capitalized = false);
};


#endif //_CRYPTO_DIGEST_H
