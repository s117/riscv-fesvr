// See LICENSE for license details.

#include "syscall.h"
#include "htif.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <termios.h>
#include <dirent.h>
#include <sys/random.h>
#include <sstream>
#include <iostream>

using namespace std::placeholders;

#define RISCV_AT_FDCWD -100

struct riscv_stat
{
  uint64_t dev;
  uint64_t ino;
  uint32_t mode;
  uint32_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint64_t rdev;
  uint64_t __pad1;
  uint64_t size;
  uint32_t blksize;
  uint32_t __pad2;
  uint64_t blocks;
  uint64_t atime;
  uint64_t __pad3;
  uint64_t mtime;
  uint64_t __pad4;
  uint64_t ctime;
  uint64_t __pad5;
  uint32_t __unused4;
  uint32_t __unused5;

  riscv_stat(const struct stat& s)
    : dev(s.st_dev), ino(s.st_ino), mode(s.st_mode), nlink(s.st_nlink),
      uid(s.st_uid), gid(s.st_gid), rdev(s.st_rdev), __pad1(0),
      size(s.st_size), blksize(s.st_blksize), __pad2(0),
      blocks(s.st_blocks), atime(s.st_atime), __pad3(0),
      mtime(s.st_mtime), __pad4(0), ctime(s.st_ctime), __pad5(0),
      __unused4(0), __unused5(0) {}
};

syscall_t::syscall_t(htif_t* htif)
  : htif(htif), memif(&htif->memif()), table(2048)
{
  table[93] = &syscall_t::sys_exit;
  table[63] = &syscall_t::sys_read;
  table[64] = &syscall_t::sys_write;
  table[56] = &syscall_t::sys_openat;
  table[57] = &syscall_t::sys_close;
  table[80] = &syscall_t::sys_fstat;
  table[62] = &syscall_t::sys_lseek;
  table[1039] = &syscall_t::sys_lstat;
  table[79] = &syscall_t::sys_fstatat;
  table[48] = &syscall_t::sys_faccessat;
  table[25] = &syscall_t::sys_fcntl;
  table[37] = &syscall_t::sys_linkat;
  table[35] = &syscall_t::sys_unlinkat;
  table[34] = &syscall_t::sys_mkdirat;
  table[17] = &syscall_t::sys_getcwd;
  table[67] = &syscall_t::sys_pread;
  table[68] = &syscall_t::sys_pwrite;
  table[2011] = &syscall_t::sys_getmainvars;
  table[46] = &syscall_t::sys_ftruncate;
  table[49] = &syscall_t::sys_chdir;
  table[61] = &syscall_t::sys_getdents64;
  table[278] = &syscall_t::sys_getrandom;
  table[276] = &syscall_t::sys_renameat2;

  register_command(0, std::bind(&syscall_t::handle_syscall, this, _1), "syscall");

  int stdin_fd = dup(0), stdout_fd0 = dup(1), stdout_fd1 = dup(1);
  if (stdin_fd < 0 || stdout_fd0 < 0 || stdout_fd1 < 0)
    throw std::runtime_error("could not dup stdin/stdout");

  fds.alloc(stdin_fd); // stdin -> stdin
  fds.alloc(stdout_fd0); // stdout -> stdout
  fds.alloc(stdout_fd1); // stderr -> stdout
}

std::string syscall_t::do_chroot(const char* fn)
{
  if (!htif->chroot.empty() && *fn == '/')
    return htif->chroot + fn;
  return fn;
}

std::string syscall_t::undo_chroot(const char* fn)
{
  if (htif->chroot.empty())
    return fn;
  if (strncmp(fn, htif->chroot.c_str(), htif->chroot.size()) == 0
      && (htif->chroot.back() == '/' || fn[htif->chroot.size()] == '/'))
    return fn + htif->chroot.size() - (htif->chroot.back() == '/');
  return "/";
}

void syscall_t::handle_syscall(command_t cmd)
{
  if (cmd.payload() & 1) // test pass/fail
  {
    htif->exitcode = cmd.payload();
    if (htif->exit_code())
      std::cerr << "*** FAILED *** (tohost = " << htif->exit_code() << ")" << std::endl;
  }
  else // proxied system call
    dispatch(cmd.payload());

  cmd.respond(1);
}

reg_t syscall_t::sys_exit(reg_t code, reg_t a1, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  htif->exitcode = code << 1 | 1;

  m_strace.syscall_record_begin("sys_exit", 93);
  m_strace.syscall_record_param_int64("status", code);
  m_strace.syscall_record_end(0);

  return 0;
}

static reg_t sysret_errno(sreg_t ret)
{
  return ret == -1 ? -errno : ret;
}

reg_t syscall_t::sys_read(reg_t fd, reg_t pbuf, reg_t len, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(len);
  ssize_t ret = read(fds.lookup(fd), &buf[0], len);
  reg_t ret_errno = sysret_errno(ret);
  if (ret > 0)
    memif->write(pbuf, ret, &buf[0]);

  m_strace.syscall_record_begin("sys_read", 63);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'o');
  m_strace.syscall_record_param_uint64("count", len);
  m_strace.syscall_record_end(ret_errno);

  return ret_errno;
}

reg_t syscall_t::sys_pread(reg_t fd, reg_t pbuf, reg_t len, reg_t off, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(len);
  ssize_t ret = pread(fds.lookup(fd), &buf[0], len, off);
  reg_t ret_errno = sysret_errno(ret);
  if (ret > 0)
    memif->write(pbuf, ret, &buf[0]);

  m_strace.syscall_record_begin("sys_pread", 67);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'o');
  m_strace.syscall_record_param_uint64("count", len);
  m_strace.syscall_record_param_int64("offset", off);
  m_strace.syscall_record_end(ret_errno);

  return ret_errno;
}

reg_t syscall_t::sys_write(reg_t fd, reg_t pbuf, reg_t len, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(len);
  memif->read(pbuf, len, &buf[0]);
  reg_t ret = sysret_errno(write(fds.lookup(fd), &buf[0], len));

  m_strace.syscall_record_begin("sys_write", 64);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'i');
  m_strace.syscall_record_param_uint64("count", len);
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_pwrite(reg_t fd, reg_t pbuf, reg_t len, reg_t off, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(len);
  memif->read(pbuf, len, &buf[0]);
  reg_t ret = sysret_errno(pwrite(fds.lookup(fd), &buf[0], len, off));

  m_strace.syscall_record_begin("sys_pwrite", 68);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'i');
  m_strace.syscall_record_param_uint64("count", len);
  m_strace.syscall_record_param_int64("offset", off);
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_close(reg_t fd, reg_t a1, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  auto scall_ret = close(fds.lookup(fd));

  m_strace.syscall_record_begin("sys_close", 57);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));

  if (scall_ret < 0) {
    reg_t ret = sysret_errno(-1);
    m_strace.syscall_record_end(ret);
    return ret;
  }

  fds.dealloc(fd);
  m_strace.syscall_record_end(0);
  return 0;
}

reg_t syscall_t::sys_lseek(reg_t fd, reg_t offset, reg_t whence, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  reg_t ret = sysret_errno(lseek(fds.lookup(fd), offset, whence));

  m_strace.syscall_record_begin("sys_lseek", 62);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_int64(PASS_PARAM(offset));
  m_strace.syscall_record_param_int64(PASS_PARAM(whence));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_fstat(reg_t fd, reg_t pbuf, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  struct stat buf;
  reg_t ret = sysret_errno(fstat(fds.lookup(fd), &buf));
  if (ret != (reg_t)-1)
  {
    riscv_stat rbuf(buf);
    memif->write(pbuf, sizeof(rbuf), &rbuf);
  }

  m_strace.syscall_record_begin("sys_fstat", 80);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("statbuf", pbuf, 'o');
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_fcntl(reg_t fd, reg_t cmd, reg_t arg, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  reg_t ret = sysret_errno(fcntl(fds.lookup(fd), cmd, arg));

  m_strace.syscall_record_begin("sys_fcntl", 25);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_int64(PASS_PARAM(cmd));
  m_strace.syscall_record_param_uint64(PASS_PARAM(arg));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_ftruncate(reg_t fd, reg_t len, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  reg_t ret = sysret_errno(ftruncate(fds.lookup(fd), len));

  m_strace.syscall_record_begin("sys_ftruncate", 46);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_int64("length", len);
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_lstat(reg_t pname, reg_t len, reg_t pbuf, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);

  struct stat buf;
  reg_t ret = sysret_errno(lstat(do_chroot(&name[0]).c_str(), &buf));
  riscv_stat rbuf(buf);
  if (ret != (reg_t)-1)
  {
    riscv_stat rbuf(buf);
    memif->write(pbuf, sizeof(rbuf), &rbuf);
  }

  m_strace.syscall_record_begin("sys_lstat", 1039);
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_simple_ptr("statbuf", pbuf, 'o');
  m_strace.syscall_record_end(ret);

  return ret;
}

#define AT_SYSCALL(syscall, fd, name, ...) \
  (syscall(fds.lookup(fd), int(fd) == RISCV_AT_FDCWD ? do_chroot(name).c_str() : (name), __VA_ARGS__))

reg_t syscall_t::sys_openat(reg_t dirfd, reg_t pname, reg_t len, reg_t flags, reg_t mode, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);
  int fd = sysret_errno(AT_SYSCALL(openat, dirfd, &name[0], flags, mode));

  m_strace.syscall_record_begin("sys_openat", 56);
  m_strace.syscall_record_param_fd(PASS_PARAM(dirfd));
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_int64(PASS_PARAM(flags));
  m_strace.syscall_record_param_uint64(PASS_PARAM(mode));

  reg_t ret;
  if (fd < 0) {
    ret = sysret_errno(-1);
    m_strace.syscall_record_end(ret);
    return ret;
  }

  ret = fds.alloc(fd);

  m_strace.syscall_record_end(ret);
  return ret;
}

reg_t syscall_t::sys_fstatat(reg_t dirfd, reg_t pname, reg_t len, reg_t pbuf, reg_t flags, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);

  struct stat buf;
  reg_t ret = sysret_errno(AT_SYSCALL(fstatat, dirfd, &name[0], &buf, flags));
  if (ret != (reg_t)-1)
  {
    riscv_stat rbuf(buf);
    memif->write(pbuf, sizeof(rbuf), &rbuf);
  }

  m_strace.syscall_record_begin("sys_fstatat", 79);
  m_strace.syscall_record_param_fd(PASS_PARAM(dirfd));
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_simple_ptr("statbuf", pbuf, 'o');
  m_strace.syscall_record_param_int64(PASS_PARAM(flags));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_faccessat(reg_t dirfd, reg_t pname, reg_t len, reg_t mode, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);
  reg_t ret = sysret_errno(AT_SYSCALL(faccessat, dirfd, &name[0], mode, 0));

  m_strace.syscall_record_begin("sys_faccessat", 48);
  m_strace.syscall_record_param_fd(PASS_PARAM(dirfd));
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_int64(PASS_PARAM(mode));
  m_strace.syscall_record_param_int64("flags",0);
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_linkat(reg_t odirfd, reg_t poname, reg_t olen, reg_t ndirfd, reg_t pnname, reg_t nlen, reg_t flags)
{
  std::vector<char> oname(olen), nname(nlen);
  memif->read(poname, olen, &oname[0]);
  memif->read(pnname, nlen, &nname[0]);
  reg_t ret = sysret_errno(linkat(fds.lookup(odirfd), int(odirfd) == RISCV_AT_FDCWD ? do_chroot(&oname[0]).c_str() : &oname[0],
                             fds.lookup(ndirfd), int(ndirfd) == RISCV_AT_FDCWD ? do_chroot(&nname[0]).c_str() : &nname[0],
                             flags));

  m_strace.syscall_record_begin("sys_linkat", 37);
  m_strace.syscall_record_param_fd("olddirfd", odirfd);
  m_strace.syscall_record_param_path_name("oldpath", poname, &oname[0], 'i');
  m_strace.syscall_record_param_fd("newdirfd", ndirfd);
  m_strace.syscall_record_param_path_name("newpath", pnname, &nname[0], 'i');
  m_strace.syscall_record_param_int64(PASS_PARAM(flags));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_unlinkat(reg_t dirfd, reg_t pname, reg_t len, reg_t flags, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);
  reg_t ret = sysret_errno(AT_SYSCALL(unlinkat, dirfd, &name[0], flags));

  m_strace.syscall_record_begin("sys_unlinkat", 35);
  m_strace.syscall_record_param_fd(PASS_PARAM(dirfd));
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_int64(PASS_PARAM(flags));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_mkdirat(reg_t dirfd, reg_t pname, reg_t len, reg_t mode, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> name(len);
  memif->read(pname, len, &name[0]);
  reg_t ret = sysret_errno(AT_SYSCALL(mkdirat, dirfd, &name[0], mode));

  m_strace.syscall_record_begin("sys_mkdirat", 34);
  m_strace.syscall_record_param_fd(PASS_PARAM(dirfd));
  m_strace.syscall_record_param_path_name("pathname", pname, &name[0], 'i');
  m_strace.syscall_record_param_uint64(PASS_PARAM(mode));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_getcwd(reg_t pbuf, reg_t size, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(size);
  char* ret = getcwd(&buf[0], size);

  m_strace.syscall_record_begin("sys_getcwd", 17);
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'o');
  m_strace.syscall_record_param_uint64(PASS_PARAM(size));

  if (ret == NULL){
    reg_t r = sysret_errno(-1);
    m_strace.syscall_record_end(r);
    return r;
  }

  std::string tmp = undo_chroot(&buf[0]);
  if (size <= tmp.size()){
    reg_t r = -ENOMEM;
    m_strace.syscall_record_end(r);
    return r;
  }

  memif->write(pbuf, tmp.size() + 1, &tmp[0]);

  reg_t r = tmp.size() + 1;
  m_strace.syscall_record_end(r);
  return r;
}

reg_t syscall_t::sys_getmainvars(reg_t pbuf, reg_t limit, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<std::string> args = htif->target_args();
  std::vector<uint64_t> words(args.size() + 3);
  words[0] = args.size();
  words[args.size()+1] = 0; // argv[argc] = NULL
  words[args.size()+2] = 0; // envp[0] = NULL

  size_t sz = (args.size() + 3) * sizeof(words[0]);
  for (size_t i = 0; i < args.size(); i++)
  {
    words[i+1] = sz + pbuf;
    sz += args[i].length() + 1;
  }

  std::vector<char> bytes(sz);
  memcpy(&bytes[0], &words[0], sizeof(words[0]) * words.size());
  for (size_t i = 0; i < args.size(); i++)
    strcpy(&bytes[words[i+1] - pbuf], args[i].c_str());

  m_strace.syscall_record_begin("sys_getmainvars", 2011);
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'o');
  m_strace.syscall_record_param_uint64(PASS_PARAM(limit));

  if (bytes.size() > limit){
    m_strace.syscall_record_end(-ENOMEM);
    return -ENOMEM;
  }


  memif->write(pbuf, bytes.size(), &bytes[0]);

  m_strace.syscall_record_end(0);
  return 0;
}

reg_t syscall_t::sys_chdir(reg_t path, reg_t size, reg_t a2, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(size);
  for (size_t offset = 0; offset < size; offset++)
  {
    buf[offset] = memif->read_uint8(path + offset);
    if (!buf[offset])
      break;
  }
  assert(buf[size-1] == 0);
  reg_t ret = sysret_errno(chdir(buf.data()));

  m_strace.syscall_record_begin("sys_chdir", 49);
  m_strace.syscall_record_param_path_name(PASS_PARAM(path), buf.data(), 'i');
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_getdents64(reg_t fd, reg_t dirbuf, reg_t size, reg_t a3, reg_t a4, reg_t a5, reg_t a6)
{
  std::vector<char> buf(size);
  reg_t ret = sysret_errno(getdents64(fds.lookup(fd), &buf[0], size));
  if ((sreg_t)ret > 0)
  {
    memif->write(dirbuf, ret, &buf[0]);
  }

  m_strace.syscall_record_begin("sys_getdents64", 61);
  m_strace.syscall_record_param_fd(PASS_PARAM(fd));
  m_strace.syscall_record_param_simple_ptr("dirp", dirbuf, 'o');
  m_strace.syscall_record_param_uint64("count", size);
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_getrandom(reg_t pbuf, reg_t len, reg_t flags, reg_t a3, reg_t a4, reg_t a5, reg_t a6){
  std::vector<char> buf(len);
  reg_t ret =  sysret_errno(getrandom(&buf[0], len, flags));
  if ((sreg_t)ret > 0)
  {
    memif->write(pbuf, ret, &buf[0]);
  }

  m_strace.syscall_record_begin("sys_getrandom", 278);
  m_strace.syscall_record_param_simple_ptr("buf", pbuf, 'o');
  m_strace.syscall_record_param_uint64("buflen", len);
  m_strace.syscall_record_param_uint64(PASS_PARAM(flags));
  m_strace.syscall_record_end(ret);

  return ret;
}

reg_t syscall_t::sys_renameat2(reg_t odirfd, reg_t popath, reg_t olen, reg_t ndirfd, reg_t pnpath, reg_t nlen, reg_t flags)
{
  std::vector<char> opath(olen), npath(nlen);
  memif->read(popath, olen, &opath[0]);
  memif->read(pnpath, nlen, &npath[0]);
  reg_t ret = sysret_errno(renameat2(fds.lookup(odirfd), int(odirfd) == RISCV_AT_FDCWD ? do_chroot(&opath[0]).c_str() : &opath[0],
                               fds.lookup(ndirfd), int(ndirfd) == RISCV_AT_FDCWD ? do_chroot(&npath[0]).c_str() : &npath[0],
                               flags));

  m_strace.syscall_record_begin("sys_renameat2", 276);
  m_strace.syscall_record_param_fd("olddirfd", odirfd);
  m_strace.syscall_record_param_path_name("oldpath", popath, &opath[0], 'i');
  m_strace.syscall_record_param_fd("newdirfd", ndirfd);
  m_strace.syscall_record_param_path_name("newpath", pnpath, &npath[0], 'i');
  m_strace.syscall_record_param_uint64(PASS_PARAM(flags));
  m_strace.syscall_record_end(ret);

  return ret;
}

void syscall_t::dispatch(reg_t mm)
{
  reg_t magicmem[8];
  memif->read(mm, sizeof(magicmem), magicmem);

  reg_t n = magicmem[0];
  if (n >= table.size() || !table[n])
    throw std::runtime_error("bad syscall #" + std::to_string(n));

  magicmem[0] = (this->*table[n])(magicmem[1], magicmem[2], magicmem[3], magicmem[4], magicmem[5], magicmem[6], magicmem[7]);

  memif->write(mm, sizeof(magicmem), magicmem);
}

reg_t fds_t::alloc(int fd)
{
  reg_t i;
  for (i = 0; i < fds.size(); i++)
    if (fds[i] == -1)
      break;

  if (i == fds.size())
    fds.resize(i+1);

  fds[i] = fd;
  return i;
}

void fds_t::dealloc(reg_t fd)
{
  fds[fd] = -1;
}

int fds_t::lookup(reg_t fd)
{
  if (int(fd) == RISCV_AT_FDCWD)
    return AT_FDCWD;
  return fd >= fds.size() ? -1 : fds[fd];
}
