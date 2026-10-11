#include <fcntl.h>
#include <climits>
#include <cstring>
#include <unistd.h>
#include <string>
#include <vector>
#include "syscall.h"
#include "htif.h"
#include "target_cwd.h"

//#define _DEBUG_MSG(...) fprintf(stderr, __VA_ARGS__)
#define _DEBUG_MSG(...)

std::string target_cwd::normalize_path(const std::string &pwd, const std::string &path) {
  // Resolve a relative path against pwd, drop empty and "." components, and let ".." remove the previous component
  // (".." at the root stays at the root). This is purely lexical: no symlink is followed.
  std::vector<std::string> components;
  auto push_components = [&components](const std::string &p) {
    size_t begin = 0;
    while (begin <= p.size()) {
      size_t end = p.find('/', begin);
      if (end == std::string::npos)
        end = p.size();
      std::string component = p.substr(begin, end - begin);
      if (component == "..") {
        if (!components.empty())
          components.pop_back();
      } else if (!component.empty() && component != ".") {
        components.push_back(std::move(component));
      }
      begin = end + 1;
    }
  };

  // pwd goes through the same rules, so a pwd that is not normalized (or not absolute) still gives a correct result
  if (path.empty() || path[0] != '/')
    push_components(pwd);
  push_components(path);

  if (components.empty())
    return "/";
  std::string result;
  for (const auto &component: components) {
    result += '/';
    result += component;
  }
  return result;
}

target_cwd::target_cwd(syscall_t *syscall) : m_syscall(syscall), m_fd_cwd(AT_FDCWD) {
  // initialized with default cwd
  char path_buf[PATH_MAX];
  if (syscall->htif->chroot.empty()) {
    // Use host cwd as the default target cwd if chroot disabled
    _DEBUG_MSG("FESVR started with chroot disabled\n");
    if (!getcwd(path_buf, sizeof(path_buf))) {
      fprintf(stderr, "Fatal: getcwd() failed (%s).\n", strerror(errno));
      exit(-1);
    }
  } else {
    // Use root as the default target cwd if chroot enabled
    _DEBUG_MSG("FESVR started with chroot enabled [%s <-> /]\n", syscall->htif->chroot.c_str());
    path_buf[0] = '/';
    path_buf[1] = '\0';
  }
  _DEBUG_MSG("Initialize target cwd with default path [%s]\n", path_buf);
  if (this->target_chdir(path_buf)) {
    fprintf(stderr, "Cannot init target cwd using the default value (%s) - %s\n", strerror(errno), path_buf);
    exit(-1);
  }
}

int target_cwd::target_chdir(const char *path) {
  std::string normalized_path = normalize_path(m_target_cwd, path);
  if (normalized_path.size() >= PATH_MAX) {
    _DEBUG_MSG("Target chdir() failed %s (path too long)\n", path);
    errno = ENAMETOOLONG;
    return -1;
  }
  std::string new_host_path = m_syscall->do_chroot(normalized_path.c_str());

  int new_fd_dir = openat(m_fd_cwd, new_host_path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NONBLOCK);

  if (new_fd_dir < 0) {
    _DEBUG_MSG("Target chdir() failed %s %s %s (%s)\n", path, normalized_path.c_str(), new_host_path.c_str(), strerror(errno));
    return -1;
  }

  _DEBUG_MSG("Target chdir() succeed %s %s %s, new fd_dir = %d\n", path, normalized_path.c_str(), new_host_path.c_str(),
             new_fd_dir);

  close(m_fd_cwd);
  m_fd_cwd = new_fd_dir;
  m_target_cwd = normalized_path;

  return 0;
}

std::string target_cwd::to_host_path(const std::string &target_path) const {
  return m_syscall->do_chroot(normalize_path(m_target_cwd, target_path).c_str());
}

char *target_cwd::target_getcwd(char *buf, size_t size) {
  if (size < m_target_cwd.size() + 1) {

    _DEBUG_MSG("Target getcwd() failed (buffer size too small)\n");
    errno = ERANGE;
    return nullptr;
  }
  memcpy(buf, m_target_cwd.c_str(), m_target_cwd.size());
  buf[m_target_cwd.size()] = '\0';
  _DEBUG_MSG("Target getcwd() returns %s\n", buf);
  return buf;
}
