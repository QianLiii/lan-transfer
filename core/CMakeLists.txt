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
    transfer/ping.h
    transfer/ping.cpp
    transfer/pingclient.h
    transfer/pingclient.cpp
    discovery/discovery.h
    discovery/peerdirectory.h
    discovery/peerdirectory.cpp
    discovery/broadcastdiscovery.h
    discovery/broadcastdiscovery.cpp
    discovery/peerconnector.h
    discovery/peerconnector.cpp
    trust/truststore.h
    trust/truststore.cpp
    files/filesource.h
    files/filesink.h
    files/atomicwrite.h
    files/atomicwrite.cpp
)

target_include_directories(lanpipe_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Linux 上的系统 DNS-SD 后端走 Avahi 的 D-Bus 接口（§3.6）。只有找得到 QtDBus
# 才编它——CI 的 Qt 若不带 DBus 模块，configure 不该因此失败。
if(UNIX AND NOT APPLE)
    find_package(Qt6 QUIET COMPONENTS DBus)
    if(Qt6DBus_FOUND)
        target_sources(lanpipe_core PRIVATE
            discovery/avahidiscovery.h
            discovery/avahidiscovery.cpp
        )
        target_link_libraries(lanpipe_core PUBLIC Qt6::DBus)
        target_compile_definitions(lanpipe_core PUBLIC LANPIPE_HAVE_AVAHI)
    else()
        message(STATUS "未找到 Qt6::DBus，Linux 的 Avahi 后端不参与构建")
    endif()
endif()

# Windows 的系统 DNS-SD 后端走 Win32 的 DNS-SD API（windns.h，§3.6）：
# 微软文档把 WinRT 那套（Windows.Networking.ServiceDiscovery.Dnssd）的浏览半边
# 标为「不受支持、可能变化或不可用」，只剩注册可用。
if(WIN32)
    target_sources(lanpipe_core PRIVATE
        discovery/windnssddiscovery.h
        discovery/windnssddiscovery.cpp
    )
    target_link_libraries(lanpipe_core PUBLIC dnsapi)
    target_compile_definitions(lanpipe_core PUBLIC LANPIPE_HAVE_WINDNSSD)
endif()

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
