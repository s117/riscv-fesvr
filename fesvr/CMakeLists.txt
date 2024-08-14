if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    find_package(ZLIB)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    find_package(OpenSSL)
endif ()

if (NOT DEFINED PREFIX)
    message(FATAL_ERROR "Variable PREFIX is not set, give it a value so the macro PREFIX can be determined")
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
        checkpoint_format.h
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
)

add_library(
        fesvr-static STATIC
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_include_directories(fesvr-static INTERFACE ..)
target_include_directories(fesvr-static PUBLIC .)
target_compile_definitions(fesvr-static PRIVATE PREFIX="${PREFIX}")
if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    target_link_libraries(fesvr-static ZLIB::ZLIB)
    target_link_libraries(fesvr-static Threads::Threads)
    target_link_libraries(fesvr-static OpenSSL::Crypto)

else ()
    target_link_libraries(fesvr-static z)
    target_link_libraries(fesvr-static pthread)
endif ()


add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_include_directories(fesvr-shared INTERFACE ..)
target_include_directories(fesvr-shared PUBLIC .)
target_compile_definitions(fesvr-shared PRIVATE PREFIX="${PREFIX}")
if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    target_link_libraries(fesvr-shared ZLIB::ZLIB)
    target_link_libraries(fesvr-shared Threads::Threads)
    target_link_libraries(fesvr-shared OpenSSL::Crypto)
else ()
    target_link_libraries(fesvr-shared z)
    target_link_libraries(fesvr-shared pthread)
endif ()

add_executable(elf2hex elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)

target_compile_definitions(fesvr-shared PRIVATE FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT)
target_compile_definitions(fesvr-static PRIVATE FESVR_TRAFFIC_RECORD_COMPRESSED_OUTPUT)