if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif ()

if (NOT DEFINED AC_CONFIGURE_PREFIX)
    message(FATAL_ERROR "Variable AC_CONFIGURE_PREFIX is not set, give it a value so the macro PREFIX can be determined")
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

add_library(
        fesvr-static STATIC
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_include_directories(fesvr-static INTERFACE ..)
target_include_directories(fesvr-static PUBLIC .)
target_compile_options(fesvr-static PRIVATE "-DPREFIX=\"${AC_CONFIGURE_PREFIX}\"")
if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    target_link_libraries(fesvr-static PUBLIC Threads::Threads)
else ()
    target_link_libraries(fesvr-static PUBLIC pthread)
endif ()


add_library(
        fesvr-shared SHARED
        ${fesvr_srcs}
        ${fesvr_hdrs}
)
target_include_directories(fesvr-shared INTERFACE ..)
target_include_directories(fesvr-shared PUBLIC .)
target_compile_options(fesvr-shared PRIVATE "-DPREFIX=\"${AC_CONFIGURE_PREFIX}\"")
if ("${CMAKE_VERSION}" VERSION_GREATER "3.0.0")
    target_link_libraries(fesvr-shared PUBLIC Threads::Threads)
else ()
    target_link_libraries(fesvr-shared PUBLIC pthread)
endif ()

add_executable(elf2hex elf2hex.cc)
target_link_libraries(elf2hex fesvr-static)

add_executable(fesvr-eth fesvr-eth.cc)
target_link_libraries(fesvr-eth fesvr-static)

add_executable(fesvr-rs232 fesvr-rs232.cc)
target_link_libraries(fesvr-rs232 fesvr-static)

add_executable(fesvr-zedboard fesvr-zedboard.cc)
target_link_libraries(fesvr-zedboard fesvr-static)
