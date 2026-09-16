# lanpipe_core —— 无 GUI 的核心层（§1、§8）。
#
# 这个目标刻意只链接 Qt6::Core 与 Qt6::Network。Quick 在顶层根本没被 find_package，
# 所以「core 不许依赖 GUI」（§1.1 规则 2）不是靠约定，而是链接时会直接失败。
#
# OpenSSL::Crypto 目前在 M0 还没有使用者，先链上是为了让 CI 在第一天就证明
# 三个平台都能找到 OpenSSL 3——这是 §2.5 里最可能在后期才暴露的一类环境问题。
# M1 的证书生成会真正用它。

add_library(lanpipe_core STATIC
    protocol.h
    identity.h
    identity.cpp
    settings.h
    settings.cpp
    tlsbackend.h
    tlsbackend.cpp
    files/filesource.h
    files/filesink.h
)

target_include_directories(lanpipe_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(lanpipe_core
    PUBLIC
        Qt6::Core
        Qt6::Network
        OpenSSL::Crypto
    PRIVATE
        lanpipe_warnings
)

set_target_properties(lanpipe_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
