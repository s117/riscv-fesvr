cmake_minimum_required(VERSION 3.14)

# The installation prefix is RISCV_INSTALL_PREFIX. It used to be PREFIX, but CMake's compiler detection
# (CMakeCompilerIdDetection.cmake) sets and unsets a variable of that name, so a cache entry PREFIX (-DPREFIX=...)
# corrupts it: the compiler ID comes out empty, and so do the flags that depend on it, such as -fPIC and -std=.
# Take a PREFIX given that way as RISCV_INSTALL_PREFIX, and drop it before project() detects the compiler.
if (DEFINED CACHE{PREFIX})
    message(WARNING "PREFIX is deprecated, use RISCV_INSTALL_PREFIX instead (now set to ${PREFIX})")
    set(RISCV_INSTALL_PREFIX "${PREFIX}" CACHE PATH "Installation prefix of the RISC-V tools" FORCE)
    unset(PREFIX CACHE)
endif ()

project(riscv-fesvr)

add_subdirectory(fesvr)

# Rule to produce a dir "lib" containing libfesvr
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
file(CREATE_LINK ../fesvr/libfesvr-shared.so ${CMAKE_CURRENT_BINARY_DIR}/lib/liblibfesvr.so SYMBOLIC)
file(CREATE_LINK ../fesvr/libfesvr-static.a ${CMAKE_CURRENT_BINARY_DIR}/lib/libfesvr.a SYMBOLIC)
add_custom_target(fesvr-lib-dir)
add_dependencies(fesvr-lib-dir fesvr-shared fesvr-static)
set_target_properties(fesvr-lib-dir PROPERTIES FESVR_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR})
