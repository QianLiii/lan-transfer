// 协议常量的断言测试。
//
// core/protocol.h 刻意不依赖 Qt，所以这个测试也不需要起事件循环——
// 它守的是「协议里那些互相耦合的数字不能各自漂移」，而不是某个函数的实现。

#include <QtTest>

#include "protocol.h"

using namespace lanpipe::proto;

class TestProtocol : public QObject
{
    Q_OBJECT

private slots:
    // 版本自洽：本端版本必须被判定为兼容，相邻版本必须被拒绝。
    void versionIsSelfCompatible()
    {
        QVERIFY(isVersionCompatible(kVersion));
        QVERIFY(!isVersionCompatible(kVersion + 1));
        QVERIFY(!isVersionCompatible(kVersion - 1));
    }

    // §5.9 的核心不变量：发送方超时必须严格大于接收方的决策窗口。
    // 两者一旦相等或倒挂，接收方还没决定完，发送方就已经放弃——表现为
    // 「配对时好时坏、取决于手速」。这条断言就是为了让它不能悄悄发生。
    void senderTimeoutExceedsApprovalWindow()
    {
        QVERIFY(kSenderHttpTimeout > kApprovalWindow);
    }

    // 路径构造必须与常量前缀一致，否则收发两端有一端会拼出对方路由不认识的路径。
    void pathBuildersMatchPrefixes()
    {
        QCOMPARE(QString::fromStdString(uploadPath("s1", "f2")),
                 QString::fromStdString(std::string(kPathUploadPrefix) + "s1/f2"));

        QCOMPARE(QString::fromStdString(completePath("s1")),
                 QString::fromStdString(std::string(kPathCompletePrefix) + "s1"));

        QCOMPARE(QString::fromStdString(abortPath("s1")),
                 QString::fromStdString(std::string(kPathAbortPrefix) + "s1"));
    }

    // 解析器上限必须彼此协调：整块的上限小于单行的上限是自相矛盾的配置。
    void parserLimitsAreCoherent()
    {
        QVERIFY(kMaxHeaderFieldCount > 0);
        QVERIFY(kMaxHeaderLineLength > 0);
        QVERIFY(kMaxHeaderBlockSize >= kMaxHeaderLineLength);
        QVERIFY(kMaxConnections > 0);
    }

    // §5.7：临时目录名以点开头，在桌面文件管理器里默认隐藏，
    // 避免用户把半截文件当成正常结果。
    void tempDirIsHiddenAndNamed()
    {
        QVERIFY(!kTempDirName.empty());
        QCOMPARE(kTempDirName.front(), '.');
    }

    // §5.13：同一时刻只允许一个活动会话。这个值一旦被改成大于 1，
    // 接收端的审批 UI 与临时目录布局都要重新设计，所以在此显式钉住。
    void onlyOneActiveSession()
    {
        QCOMPARE(kMaxActiveSessions, std::size_t{1});
    }

    // §5.1：分块大小必须是有限且合理的，不能是 0（会死循环）或整MB 级
    // （会让「10 GB 内存持平」的验收失去意义）。
    void chunkSizeIsSane()
    {
        QVERIFY(kChunkSize >= 64 * 1024);
        QVERIFY(kChunkSize <= 1024 * 1024);
    }

    // 临时数据保留时长必须覆盖一次正常传输的时长量级。
    void tempRetentionIsHours()
    {
        QVERIFY(kTempRetention >= std::chrono::hours(1));
    }

    // 广播端口不能落在特权区间（<1024），否则非 root 绑定会失败。
    void broadcastPortIsUnprivileged()
    {
        QVERIFY(kBroadcastPort >= 1024);
    }

    // 临时端口用 0 表示，这是 §3.1 的约定：端口由系统分配并经 SRV 通告。
    void ephemeralPortIsZero()
    {
        QCOMPARE(kEphemeralPort, std::uint16_t{0});
    }

    // §5.9：三层的等待窗口必须层层放宽。倒挂或相等时，先到期的那一层会把
    // 「对方还在等」误报成失败，而症状是「有时好有时坏」。
    void waitWindowsAreNested()
    {
        QVERIFY(kSenderRequestTimeout > kApprovalWindow);
        QVERIFY(kSessionTtl > kSenderRequestTimeout);
        QVERIFY(kTempRetention > kSessionTtl);
    }

    // id 的字节数与十六进制字符数是同一个东西的两面，路径解析按后者校验。
    void idLengthsAreConsistent()
    {
        QVERIFY(kSessionIdBytes > 0);
        QVERIFY(kFileIdBytes > 0);
        QVERIFY(kSessionIdBytes >= kFileIdBytes); // 会话 id 要猜不出来，文件 id 只要唯一
    }

    // §5.13：一次只有一个活动会话，因此请求体与文件数的上限必须存在——
    // 没有它们，prepare 的内存占用由对端决定。
    void prepareLimitsAreBounded()
    {
        QVERIFY(kMaxPrepareBodySize > kMaxPingBodySize);
        QVERIFY(kMaxFilesPerSession > 0);
        QVERIFY(kMaxDisplayNameBytes > 0);
        QVERIFY(kFreeSpaceSlack > 0);
        QVERIFY(kMaxFinalNameAttempts > 1);
    }
};

QTEST_APPLESS_MAIN(TestProtocol)

#include "tst_protocol.moc"
