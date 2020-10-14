//
// Created by s117 on 10/12/20.
//

#ifndef RISCV_ISA_SIM_STRACE_H
#define RISCV_ISA_SIM_STRACE_H

#include <fstream>
#include <iostream>
#include <cassert>
#include <cinttypes>
#include "base64.h"

#define PASS_PARAM(p) #p, p

class strace {
public:
  strace() {
    m_output_file = fopen(m_strace_filename, "w");
    if (!m_output_file) {
      std::cerr << "Syscall trace output error: fail to open trace output file" << m_strace_filename << std::endl;
      exit(1);
    }
  }

  ~strace() {
//    std::cout << std::endl << "Saving syscall trace to \"" << m_strace_filename << "\"..." << std::endl;
    fflush(m_output_file);
    fclose(m_output_file);
  }

  void syscall_record_begin(const char *scall_name, uint64_t scall_id) {
    fprintf(m_output_file, "[%" PRIu64 "] %s {\n", scall_id, scall_name);
  }

  void syscall_record_end(uint64_t ret_code) {
    fprintf(m_output_file, "} -> %" PRIu64 "\n\n", ret_code);
  }

  void syscall_record_param_int(const char *param_name, uint64_t value) {
    fprintf(m_output_file, "  uint64_t %s = %" PRIu64 "\n", param_name, value);
  }

  void syscall_record_param_simple_ptr(const char *param_name, uintptr_t ptr_val, char io_direction) {
    const char *type_prefix;
    if (io_direction == 'i') {
      type_prefix = "PtrIN";

    } else {
      assert(io_direction == 'o');
      type_prefix = "PtrOUT";
    }
    fprintf(m_output_file, "  %s %s = 0x%" PRIX64 "\n", type_prefix, param_name, ptr_val);
  }

  void syscall_record_param_str(const char *param_name, uint64_t ptr_val, const char *ptr_dat, char io_direction) {
    const char *type_prefix;
    if (io_direction == 'i') {
      type_prefix = "StrIN";

    } else {
      assert(io_direction == 'o');
      type_prefix = "StrOUT";
    }
    fprintf(
      m_output_file, "  %s %s = 0x%" PRIX64 "|%s|\n",
      type_prefix, param_name, ptr_val, base64_encode(ptr_dat).c_str()
    );
  }

private:
  const char *m_strace_filename = "syscall_trace.txt";
  FILE *m_output_file;
};


#endif //RISCV_ISA_SIM_STRACE_H
