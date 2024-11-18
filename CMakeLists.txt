cmake_minimum_required(VERSION 3.14)

project(riscv-fesvr)

add_subdirectory(fesvr)

# Rule to produce a dir "lib" containing libfesvr
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
file(CREATE_LINK ../fesvr/libfesvr-shared.so ${CMAKE_CURRENT_BINARY_DIR}/lib/liblibfesvr.so SYMBOLIC)
file(CREATE_LINK ../fesvr/libfesvr-static.a ${CMAKE_CURRENT_BINARY_DIR}/lib/libfesvr.a SYMBOLIC)
add_custom_target(fesvr-lib-dir)
add_dependencies(fesvr-lib-dir fesvr-shared fesvr-static)
set_target_properties(fesvr-lib-dir PROPERTIES FESVR_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR})
