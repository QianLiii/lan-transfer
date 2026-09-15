cmake_minimum_required(VERSION 3.21)

project(lanpipe
    VERSION 0.1.0
    DESCRIPTION "LAN file transfer"
    LANGUAGES CXX)

# —— 语言标准 ——
# §2.2：C++23。工具链下限 GCC 13+ / Clang 17+ / MSVC 2022 17.8+ / Xcode 15+。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 生成 compile_commands.json，供 clangd 等工具使用。
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# QtTest 的测试类把 Q_OBJECT 宏与测试槽写在同一文件里，靠
# #include "tst_xxx.moc" 收尾（见 tests/*.cpp）。没有 AUTOMOC 就不会生成
# 那个 .moc 文件，报错是「找不到 tst_xxx.moc」，与 Q_OBJECT 本身无关。
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# —— 依赖 ——
# Qt 6.11。这里不找 Quick：Quick 要到 M5 才需要，而「core 不依赖 GUI」
# （§1.1 规则 2）在构建系统层面就应当是不可违反的，而不是靠代码评审。
find_package(Qt6 6.11 REQUIRED COMPONENTS Core Network)
find_package(Qt6 6.11 QUIET COMPONENTS Test)

# OpenSSL 3 是显式依赖，不是可选项：Qt 没有任何生成密钥对或自签证书的公共 API
# （§2.5），证书必须由 OpenSSL 生成。
#
# 注意 macOS：系统不自带 OpenSSL，Homebrew 的 openssl@3 需要显式给出
# OPENSSL_ROOT_DIR。这是已知的 macOS 打包事项，首次 CI 在此处失败属于预期，
# 不是构建脚本的问题。
find_package(OpenSSL 3 REQUIRED)

if(NOT Qt6Test_FOUND)
    message(WARNING "未找到 Qt6::Test，测试目标将被跳过")
endif()

# —— 编译告警 ——
# 一个接口目标，让 core / cli / tests 共用同一套告警设置。
add_library(lanpipe_warnings INTERFACE)
if(MSVC)
    target_compile_options(lanpipe_warnings INTERFACE /W4 /permissive-)
else()
    target_compile_options(lanpipe_warnings INTERFACE -Wall -Wextra -Wpedantic)
endif()

# enable_testing() 必须出现在顶层目录：子目录里的 add_test 只有在顶层
# 已经开启测试时才会被写进 CTestTestfile.cmake。漏掉它的症状是
# ctest 报 "No tests were found!!!" 而构建一切正常——很容易误判成测试没编出来。
enable_testing()

add_subdirectory(core)
add_subdirectory(cli)
if(Qt6Test_FOUND)
    add_subdirectory(tests)
endif()
