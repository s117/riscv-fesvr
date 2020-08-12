cmake_minimum_required(VERSION 3.1)

project(riscv-fesvr)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(NOT DEFINED AC_CONFIGURE_PREFIX)
  message(FATAL_ERROR "Variable AC_CONFIGURE_PREFIX is not set, give it a value so the macro PREFIX can be determined")
endif()

set(
  fesvr_hdrs
	fesvr/elf.h
	fesvr/elfloader.h
	fesvr/htif.h
	fesvr/memif.h
	fesvr/syscall.h
	fesvr/packet.h
  fesvr/context.h
	fesvr/htif_pthread.h
	fesvr/htif_rs232.h
	fesvr/htif_hexwriter.h
	fesvr/htif_eth.h
	fesvr/htif_zedboard.h
	fesvr/option_parser.h
	fesvr/term.h
	fesvr/device.h
	fesvr/rfb.h
)

set(
  fesvr_srcs
  fesvr/elfloader.cc
  fesvr/htif.cc
  fesvr/packet.cc
  fesvr/memif.cc
  fesvr/syscall.cc
  fesvr/device.cc
  fesvr/rfb.cc
  fesvr/context.cc
  fesvr/htif_pthread.cc
  fesvr/htif_rs232.cc
  fesvr/htif_hexwriter.cc
  fesvr/htif_eth.cc
  fesvr/htif_zedboard.cc
  fesvr/dummy.cc
  fesvr/option_parser.cc
  fesvr/term.cc
)

add_library(
        fesvr-static STATIC
        ${fesvr_srcs}
        ${fesvr_hdrs}
)

add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)

target_include_directories(fesvr-static INTERFACE .)
target_include_directories(fesvr-shared INTERFACE .)

target_include_directories(fesvr-static PUBLIC fesvr)
target_include_directories(fesvr-shared PUBLIC fesvr)

target_compile_options(fesvr-static PRIVATE "-DPREFIX=\"${AC_CONFIGURE_PREFIX}\"")
target_compile_options(fesvr-shared PRIVATE "-DPREFIX=\"${AC_CONFIGURE_PREFIX}\"")

target_link_libraries(fesvr-static PUBLIC Threads::Threads)
target_link_libraries(fesvr-shared PUBLIC Threads::Threads)

add_executable(elf2hex fesvr/elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr/fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr/fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr/fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)
