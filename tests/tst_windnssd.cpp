// Windows 的系统 DNS-SD 后端（§3.6）。
//
// 这份代码是在 Linux 上写的、**从未编译过**，所以这套测试的第一价值就是「能不能跑」：
// 在 Windows 上 `ctest -R tst_windnssd` 是验证它的最短路径。
//
// 与 Avahi 那套对应：一个实例注册、另一个浏览；自过滤；只浏览模式。

#include <QtTest>

#include <QElapsedTimer>
#include <QSignalSpy>

#include <cstdio>

#include "protocol.h"

#ifdef LANPIPE_HAVE_WINDNSSD

#include "discovery/windnssddiscovery.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

// 进度打到 stderr：它无缓冲，进程若在随后崩掉这一行也留得下。QtTest 自己的 stdout
// 带缓冲，进程一崩就什么都不剩——上一轮 CI 只看到「跑了 54 秒、没有任何输出」，
// 就是这么来的。有了这些标记，至少知道它死在哪一步。
void mark(const QString &text)
{
    std::fprintf(stderr, "[tst_windnssd] %s\n", qPrintable(text));
    std::fflush(stderr);
}

// 指定初始化漏字段会触发 -Wmissing-field-initializers，所以配置这样拼。
WinDnsSdDiscovery::Config configFor(const Advertisement &self, bool announce)
{
    WinDnsSdDiscovery::Config config;
    config.self = self;
    config.announce = announce;
    return config;
}

Advertisement advertisementOf(const QString &deviceId, const QString &name, quint16 port)
{
    Advertisement advertisement;
    advertisement.deviceId = deviceId;
    advertisement.name = name;
    advertisement.fingerprint = QString(64, QLatin1Char('a'));
    advertisement.version = proto::kVersion;
    advertisement.port = port;
    return advertisement;
}

} // namespace

class TestWinDnsSd : public QObject
{
    Q_OBJECT

private slots:
    // 一台实例注册、另一台浏览：浏览方应当拿到同样的 deviceId、名字、指纹与端口。
    void browseFindsAnAnnouncedPeer()
    {
        const QString announcerId = QStringLiteral("11111111111111111111111111111111");
        WinDnsSdDiscovery announcer(
            configFor(advertisementOf(announcerId, QStringLiteral("广播方"), 4455), true));
        WinDnsSdDiscovery browser(
            configFor(advertisementOf(QStringLiteral("22222222222222222222222222222222"),
                                      QStringLiteral("浏览方"), 0),
                      false));
        QSignalSpy found(&browser, &WinDnsSdDiscovery::announced);

        mark(QStringLiteral("announcer: starting"));
        announcer.start();
        if (!announcer.lastError().isEmpty())
            QSKIP(qPrintable(QStringLiteral("this machine cannot do system DNS-SD: %1")
                                .arg(announcer.lastError())));

        mark(QStringLiteral("browser: starting"));
        browser.start();
        if (!browser.lastError().isEmpty())
            mark(QStringLiteral("browser failed to start: %1").arg(browser.lastError()));
        QVERIFY2(browser.lastError().isEmpty(),
                 qPrintable(QStringLiteral("the browser failed to start: %1").arg(browser.lastError())));

        // 系统解析要走一次 mDNS 往返，比 Avahi 那条 D-Bus 路慢一些。
        //
        // 这里刻意不用 QTRY_VERIFY_WITH_TIMEOUT：它在超时时直接 return，
        // 下面那行诊断就永远打不出来——而诊断正是这条测试唯一的价值。
        mark(QStringLiteral("waiting for announcements..."));
        QElapsedTimer timer;
        timer.start();
        while (found.count() == 0 && timer.elapsed() < 15000)
            QTest::qWait(100);
        mark(QStringLiteral("got %1 announcement(s) after %2 ms")
                 .arg(found.count())
                 .arg(timer.elapsed()));

        bool matched = false;
        for (const QList<QVariant> &emission : found) {
            const auto announcement = emission.at(0).value<Announcement>();
            if (announcement.advertisement.deviceId != announcerId)
                continue;
            matched = true;
            QCOMPARE(announcement.advertisement.name, QStringLiteral("广播方"));
            QCOMPARE(announcement.advertisement.fingerprint, QString(64, QLatin1Char('a')));
            QCOMPARE(announcement.advertisement.version, proto::kVersion);
            QCOMPARE(announcement.advertisement.port, quint16{4455});
            QVERIFY(!announcement.address.isNull());
            break;
        }
        const QString diagnosis =
            QStringLiteral("the registered service never showed up in the browse results; "
                           "announcer lastError=%1; browser lastError=%2; announcements=%3; "
                           "browse callbacks=%4; records seen=%5")
                .arg(announcer.lastError().isEmpty() ? QStringLiteral("(empty)")
                                                     : announcer.lastError(),
                     browser.lastError().isEmpty() ? QStringLiteral("(empty)")
                                                   : browser.lastError(),
                     QString::number(found.count()),
                     QString::number(browser.browseCallbacks()),
                     QString::number(browser.recordsSeen()));
        if (!matched)
            mark(diagnosis); // stdout 会随崩溃丢掉，所以诊断也走 stderr

        // 「一条报文都没收到」与「收到了但没认出来」要分开：
        //   前者是这台机器的 DNS-SD 栈解析不出东西（CI runner 就是这样），
        //   后者是我们自己的解析或过滤有 bug——那必须失败。
        // 这条往返只在能真正做 mDNS 的机器上才有意义（本机 Windows 上跑它才是验收）。
        if (!matched && browser.recordsSeen() == 0) {
            QSKIP(qPrintable(QStringLiteral(
                "this machine's DNS-SD stack returned no records at all; skip rather than "
                "report a false failure. browse callbacks=%1")
                                 .arg(browser.browseCallbacks())));
        }
        QVERIFY2(matched, qPrintable(diagnosis));
    }

    void instanceDoesNotFindItself()
    {
        WinDnsSdDiscovery self(
            configFor(advertisementOf(QStringLiteral("33333333333333333333333333333333"),
                                      QStringLiteral("自己"), 4456),
                      true));
        QSignalSpy found(&self, &WinDnsSdDiscovery::announced);
        mark(QStringLiteral("self-filter case: starting"));
        self.start();
        if (!self.lastError().isEmpty())
            QSKIP(qPrintable(QStringLiteral("this machine cannot do system DNS-SD: %1")
                                 .arg(self.lastError())));

        QTest::qWait(3000);
        mark(QStringLiteral("self-filter case: done"));
        for (const QList<QVariant> &emission : found) {
            QVERIFY(emission.at(0).value<Announcement>().advertisement.deviceId
                    != QStringLiteral("33333333333333333333333333333333"));
        }
    }

    // 只浏览不通告：发送方没有在监听，没有端口也要能启动。
    void browseOnlyNeedsNoPort()
    {
        WinDnsSdDiscovery browser(
            configFor(advertisementOf(QStringLiteral("66666666666666666666666666666666"),
                                      QStringLiteral("只要浏览"), 0),
                      false));
        mark(QStringLiteral("browse-only case: starting"));
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(),
                 qPrintable(QStringLiteral("browse-only mode failed to start: %1").arg(browser.lastError())));
    }
};

QTEST_GUILESS_MAIN(TestWinDnsSd)

#else

using namespace lanpipe;

class TestWinDnsSd : public QObject
{
    Q_OBJECT
private slots:
    void windowsBackendNotBuilt() { QSKIP("非 Windows 平台，Win32 DNS-SD 后端未参与构建"); }
};

QTEST_GUILESS_MAIN(TestWinDnsSd)

#endif

#include "tst_windnssd.moc"
