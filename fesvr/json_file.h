// See LICENSE for license details.

#ifndef _FESVR_JSON_FILE_H
#define _FESVR_JSON_FILE_H

// Helpers to write the JSON files of the FESVR (the final state dump, a recording's provenance)

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

// Quote a string as a JSON string literal
inline std::string json_str(const std::string &s)
{
  std::string out = "\"";
  for (unsigned char c: s)
  {
    if (c == '"' || c == '\\')
      out += std::string("\\") + (char) c;
    else if (c < 0x20)
    {
      char buf[8];
      snprintf(buf, sizeof(buf), "\\u%04x", c);
      out += buf;
    }
    else
      out += (char) c;
  }
  return out + "\"";
}

// Replace the file at path by text atomically: write it to a temporary file next to it, with plain write(2)s (no stdio
// buffer that an exit() would flush again), then rename it over path. A process dying at any point leaves the previous
// content or the new one, never a part (at worst a stray temporary file). Throws on failure.
inline void write_file_atomically(const std::string &path, const std::string &text)
{
  const std::string tmp_path = path + ".tmp." + std::to_string(getpid());
  auto fail = [&](const std::string &what, bool created) {
    const std::string reason = std::strerror(errno);
    if (created)
      unlink(tmp_path.c_str());
    throw std::runtime_error("Fail to write \"" + path + "\": " + what + ", reason: " + reason);
  };

  // Create the temporary file anew: O_EXCL fails on anything already there, a symlink included (O_NOFOLLOW says so
  // explicitly), so a name planted in a shared directory can't redirect the write. Remove a stale one first, e.g. left
  // by an earlier process with the same pid. The mode is 0666 & ~umask, as fopen() creates files.
  unlink(tmp_path.c_str());
  int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
  if (fd < 0)
    fail("cannot create " + tmp_path, false);
  for (size_t pos = 0; pos < text.size(); )
  {
    ssize_t n = write(fd, text.data() + pos, text.size() - pos);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
    {
      ::close(fd);
      fail("cannot write " + tmp_path, true);
    }
    pos += n;
  }
  if (::close(fd) != 0)
    fail("cannot close " + tmp_path, true);
  if (rename(tmp_path.c_str(), path.c_str()) != 0)
    fail("cannot rename " + tmp_path, true);
}

#endif // _FESVR_JSON_FILE_H
