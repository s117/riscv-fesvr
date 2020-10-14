set(base64_lite_hdrs base64.h)

set(base64_lite_srcs base64.cc)

add_library(
        base64_lite STATIC
        ${base64_lite_hdrs}
        ${base64_lite_srcs}
)

target_include_directories(base64_lite INTERFACE .)
