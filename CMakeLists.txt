cmake_minimum_required(VERSION 2.8)

project(riscv-fesvr)

add_subdirectory(fesvr)

# Rule to produce a dir "lib" containing libfesvr
add_custom_command(
        COMMAND mkdir -p lib
        OUTPUT lib
        VERBATIM
)
add_custom_command(
        COMMAND ln -sf ../fesvr/libfesvr-shared.so libfesvr.so
        DEPENDS lib
        WORKING_DIRECTORY lib
        OUTPUT lib/fesvr.so
        VERBATIM
)
add_custom_command(
        COMMAND ln -sf ../fesvr/libfesvr-static.a libfesvr.a
        DEPENDS lib
        WORKING_DIRECTORY lib
        OUTPUT lib/fesvr.a
        VERBATIM
)
add_custom_target(
        fesvr-lib-dir
        DEPENDS lib lib/fesvr.so lib/fesvr.a
)

add_dependencies(fesvr-lib-dir fesvr-shared fesvr-static)

set_target_properties(fesvr-lib-dir PROPERTIES FESVR_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR})
