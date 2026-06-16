cmake_minimum_required(VERSION 3.23)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if (NOT DEFINED PREFIX)
    message(FATAL_ERROR "Variable PREFIX is not set, give it a value so the macro PREFIX can be determined")
endif ()

set(
        fesvr_hdrs
        elf.h
        elfloader.h
        htif.h
        memif.h
        syscall.h
        packet.h
        context.h
        htif_pthread.h
        htif_rs232.h
        htif_hexwriter.h
        htif_eth.h
        htif_zedboard.h
        option_parser.h
        term.h
        device.h
        rfb.h
        strace.h
        base64.h
        target_cwd.h
        syscall_bypass.h
)

set(
        fesvr_srcs
        elfloader.cc
        htif.cc
        packet.cc
        memif.cc
        syscall.cc
        device.cc
        rfb.cc
        context.cc
        htif_pthread.cc
        htif_rs232.cc
        htif_hexwriter.cc
        htif_eth.cc
        htif_zedboard.cc
        dummy.cc
        option_parser.cc
        term.cc
        base64.cc
        target_cwd.cc
        syscall_bypass.cc
)

add_library(fesvr-interface INTERFACE)
target_compile_definitions(fesvr-interface INTERFACE PREFIX="${PREFIX}")
target_sources(fesvr-interface INTERFACE
        FILE_SET HEADERS
        BASE_DIRS ..
        FILES ${fesvr_hdrs}
)

add_library(
        fesvr-static STATIC
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_link_libraries(fesvr-static PUBLIC fesvr-interface)
target_link_libraries(fesvr-static PUBLIC Threads::Threads)

add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_link_libraries(fesvr-shared PUBLIC fesvr-interface)
target_link_libraries(fesvr-shared PUBLIC Threads::Threads)

add_executable(elf2hex elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)
