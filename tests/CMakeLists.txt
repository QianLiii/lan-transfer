# QtTest 单元测试（§8 tests/）。
#
# 用标准的 add_executable + add_test，不用 qt_add_test：后者的可用性随 Qt 版本
# 与模块配置变化，而这里只需要一个能被 ctest 发现的普通可执行文件。
#
# 每个测试类一个可执行文件，命名 tst_<模块>，与源文件名一致。

# 辅助函数：注册一个测试目标。额外的源文件（例如共用的测试助手头文件，
# AUTOMOC 需要它们在目标里才会被扫描）跟在名字后面传入。
function(lanpipe_add_test name)
    add_executable(${name} ${name}.cpp ${ARGN})
    target_link_libraries(${name}
        PRIVATE
            lanpipe_core
            Qt6::Test
            lanpipe_warnings
    )
    add_test(NAME ${name} COMMAND ${name})
    # 让 ctest 的输出默认可见：M0 的验收是「ctest 通过」，失败时要能直接看到原因。
    set_tests_properties(${name} PROPERTIES
        FAIL_REGULAR_EXPRESSION "FAIL!"
    )
endfunction()

lanpipe_add_test(tst_protocol)
lanpipe_add_test(tst_settings)
lanpipe_add_test(tst_identity)
lanpipe_add_test(tst_httprequest)
lanpipe_add_test(tst_sas)
lanpipe_add_test(tst_httptransport rawclient.h)
lanpipe_add_test(tst_ping rawclient.h)
lanpipe_add_test(tst_peerdirectory)
lanpipe_add_test(tst_peerconnector)
lanpipe_add_test(tst_truststore)
lanpipe_add_test(tst_broadcast)
lanpipe_add_test(tst_avahi)
lanpipe_add_test(tst_windnssd)
lanpipe_add_test(tst_sanitizer)
lanpipe_add_test(tst_localfiles)
lanpipe_add_test(tst_receiveservice rawclient.h)
lanpipe_add_test(tst_sendclient)
lanpipe_add_test(tst_policy)
lanpipe_add_test(tst_transfer)

# 跳过时以 77 退出，让 ctest 显示 ***Skipped 而不是 Passed。CI runner 的 mDNS
# 解析不出任何东西，这条往返只能在真机 Windows 上验收——不能让「没验过」看起来
# 像「验过了」。
set_tests_properties(tst_windnssd PROPERTIES SKIP_RETURN_CODE 77)
