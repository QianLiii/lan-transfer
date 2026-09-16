# lanpipe_core —— 无 GUI 的核心层（§1、§8）。
#
# 这个目标刻意只链接 Qt6::Core 与 Qt6::Network。Quick 在顶层根本没被 find_package，
# 所以「core 不许依赖 GUI」（§1.1 规则 2）不是靠约定，而是链接时会直接失败。
#
# OpenSSL::Crypto 由 identity.cpp 直接使用（密钥生成与自签证书）。
#
# Qt6::Network 里的 QSslServer 只在 OpenSSL 后端下才被强制为我们想要的校验行为，
# 后端的固定发生在运行期（tlsbackend.cpp），链接期无从检查。

add_library(lanpipe_core STATIC
    protocol.h
    random.h
    random.cpp
    sas.h
    sas.cpp
    mtls.h
    mtls.cpp
    http/httprequest.h
    http/httprequest.cpp
    http/httpresponse.h
    http/httpresponse.cpp
    http/httpconnection.h
    http/httpconnection.cpp
    http/httpserver.h
    http/httpserver.cpp
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
