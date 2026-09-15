# lanpipe —— headless 命令行工具（§8 cli/）。
#
# 它是 CI 工具，也是 M1–M4 的验收驱动：所有里程碑的验收都靠它跑，
# 因此不能有任何 GUI 依赖。
#
# 用 add_executable 而不是 qt_add_executable：后者在 Windows 上可能把目标
# 标成 GUI 子系统，那样控制台不会有 stdout/stderr——对一个 CLI 是致命的。

add_executable(lanpipe
    main.cpp
)

target_link_libraries(lanpipe
    PRIVATE
        lanpipe_core
        lanpipe_warnings
)
