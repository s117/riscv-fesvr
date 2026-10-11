#ifndef _TARGET_CWD_H
#define _TARGET_CWD_H

#include <cstddef>
#include <string>

class syscall_t;

class target_cwd {
public:
  target_cwd(syscall_t *syscall);

  int get_fd_cwd() const { return m_fd_cwd; };

  int target_chdir(const char *path);

  char *target_getcwd(char *buf, size_t size);

  /**
   * Lexically normalize a target path. A relative path is resolved against pwd (which is normalized as well), empty
   * and "." components are dropped, and ".." removes the previous component (".." at the root stays at the root).
   * No symlink is followed.
   * @return The normalized absolute path.
   */
  static std::string normalize_path(const std::string &pwd, const std::string &path);

private:
  syscall_t *m_syscall;
  std::string m_target_cwd;
  int m_fd_cwd;
};

#endif //_TARGET_CWD_H
