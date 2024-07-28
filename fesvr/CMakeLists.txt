cmake_minimum_required(VERSION 3.23)

find_package(ZLIB)
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
        memif_tap.h
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
        device_composition.h
        device_traffic_forwarding.h
        device_traffic_bypass.h
        device_traffic_persistent.h
        rfb.h
        gzstream.h
        strace.h
        base64.h
        crc32.h
        sha256.h
        target_cwd.h
)

set(
        fesvr_srcs
        elfloader.cc
        htif.cc
        packet.cc
        memif.cc
        memif_tap.cc
        syscall.cc
        device.cc
        device_composition.cc
        device_traffic_forwarding.cc
        device_traffic_bypass.cc
        device_traffic_persistent.cc
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
        gzstream.cc
        base64.cc
        crc32.cc
        sha256.cc
        target_cwd.cc
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
target_link_libraries(fesvr-static PUBLIC ZLIB::ZLIB)
target_link_libraries(fesvr-static PUBLIC Threads::Threads)

add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_link_libraries(fesvr-shared PUBLIC fesvr-interface)
target_link_libraries(fesvr-shared PUBLIC ZLIB::ZLIB)
target_link_libraries(fesvr-shared PUBLIC Threads::Threads)

add_executable(elf2hex elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)

target_compile_definitions(fesvr-shared PRIVATE SCALL_TRACE_UNCOMPRESSED_OUTPUT)
target_compile_definitions(fesvr-static PRIVATE SCALL_TRACE_UNCOMPRESSED_OUTPUT)