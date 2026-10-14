cmake_minimum_required(VERSION 3.23)

find_package(ZLIB)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL)

if (NOT DEFINED RISCV_INSTALL_PREFIX)
    message(FATAL_ERROR "Variable RISCV_INSTALL_PREFIX is not set, give it a value so the macro PREFIX can be determined")
endif ()

set(
        fesvr_hdrs
        fesvr_logging.h
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
        hart_execution_reg.h
        hart_execution_controller.h
        device_composition.h
        device_traffic_capture.h
        device_traffic_bypass.h
        device_traffic_persistent.h
        device_traffic_format.h
        checkpoint_format.h
        fesvr_build_info.h
        hart_state_format.h
        little_endian.h
        ckpt_desc_reader.h
        rfb.h
        gzstream.h
        strace.h
        base64.h
        checksum.h
        crypto_digest.h
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
        hart_execution_controller.cc
        device_composition.cc
        device_traffic_capture.cc
        device_traffic_bypass.cc
        device_traffic_persistent.cc
        ckpt_desc_reader.cc
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
        crypto_digest.cc
        checksum.cc
        target_cwd.cc
        ${CMAKE_CURRENT_BINARY_DIR}/fesvr_build_info.cc
)

# Build information (git version, compiler, date...) of libfesvr, see fesvr_build_info.h. An ALL custom target runs
# on every build; the script rewrites fesvr_build_info.cc only when its content changed.
string(TOUPPER "${CMAKE_BUILD_TYPE}" fesvr_build_type_upper)
add_custom_target(
        fesvr-build-info ALL
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/fesvr_build_info.cc
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/stamp-build-info.sh
                ${CMAKE_CURRENT_BINARY_DIR}/fesvr_build_info.cc fesvr "FESVR (libfesvr)" ${CMAKE_CURRENT_SOURCE_DIR}/..
                ${CMAKE_CXX_COMPILER}
                "${CMAKE_BUILD_TYPE} ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${fesvr_build_type_upper}}"
                ${CMAKE_SYSTEM}
        COMMENT "Gathering the build information of libfesvr"
        VERBATIM
)

add_library(fesvr-interface INTERFACE)
target_compile_definitions(fesvr-interface INTERFACE PREFIX="${RISCV_INSTALL_PREFIX}")
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
add_dependencies(fesvr-static fesvr-build-info)
target_link_libraries(fesvr-static PUBLIC ZLIB::ZLIB)
target_link_libraries(fesvr-static PUBLIC Threads::Threads)
target_link_libraries(fesvr-static PUBLIC OpenSSL::Crypto)

add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_link_libraries(fesvr-shared PUBLIC fesvr-interface)
add_dependencies(fesvr-shared fesvr-build-info)
target_link_libraries(fesvr-shared PUBLIC ZLIB::ZLIB)
target_link_libraries(fesvr-shared PUBLIC Threads::Threads)
target_link_libraries(fesvr-shared PUBLIC OpenSSL::Crypto)

add_executable(elf2hex elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)

# Write device traffic recordings gzip-compressed (turn off to get plain files while debugging, they are read either way)
option(FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT "Write device traffic recordings gzip-compressed" ON)
if (FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT)
    set(fesvr_traffic_record_compressed 1)
else ()
    set(fesvr_traffic_record_compressed 0)
endif ()
target_compile_definitions(fesvr-shared PRIVATE FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT=${fesvr_traffic_record_compressed})
target_compile_definitions(fesvr-static PRIVATE FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT=${fesvr_traffic_record_compressed})