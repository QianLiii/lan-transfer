// Windows 的系统 DNS-SD 后端（§3.6）。
//
// 这份代码是在 Linux 上写的、**从未编译过**，所以这套测试的第一价值就是「能不能跑」：
// 在 Windows 上 `ctest -R tst_windnssd` 是验证它的最短路径。
//
// 与 Avahi 那套对应：一个实例注册、另一个浏览；自过滤；只浏览模式。

#include <QtTest>

#include <QCoreApplication>
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

// 跳过要能被看见。ctest 只在失败时打印子进程输出，所以测试里打注解没用——
// 那些行根本进不了 CI 日志。改用退出码：跳过时以 77 退出，与 CMake 里的
// SKIP_RETURN_CODE 配对，ctest 就会显示 ***Skipped 而不是 Passed。
//
// 否则「系统 DNS-SD 在本机没被验证」这件事在 CI 上毫无痕迹：绿灯，而路径没验过。
bool g_skipped = false;

// 与 tests/CMakeLists.txt 里的 SKIP_RETURN_CODE 配对。
constexpr int kSkipExitCode = 77;

// 指定初始化漏字段会触发 -Wmissing-field-initializers，所以配置这样拼。
WinDnsSdDiscovery::Config configFor(const Advertisement &self, bool announce)
{
    WinDnsSdDiscovery::Config config;
    config.self = self;
    config.announce = announce;
    return config;
}

Advertisement advertisementOf(const QString &fingerprint, const QString &name, quint16 port)
{
    Advertisement advertisement;
    advertisement.name = name;
    advertisement.fingerprint = fingerprint;
    advertisement.version = proto::kVersion;
    advertisement.port = port;
    return advertisement;
}

// 通告里只有指纹，deviceId 由它现算，所以每个实例要有一份各不相同的指纹——
// 指纹相同的那份会被对方当成「自己的注册」滤掉。这些常量都是同一个字符重复
// 64 次，于是算出的 deviceId 就是同样的字符重复 32 次。
const QString kFingerprint1 = QString(64, QLatin1Char('1'));
const QString kFingerprint2 = QString(64, QLatin1Char('2'));
const QString kFingerprint3 = QString(64, QLatin1Char('3'));
const QString kFingerprint6 = QString(64, QLatin1Char('6'));

} // namespace

class TestWinDnsSd : public QObject
{
    Q_OBJECT

private slots:
    // 一台实例注册、另一台浏览：浏览方应当拿到同样的指纹、名字与端口，
    // 并从中算出同样的 deviceId。
    void browseFindsAnAnnouncedPeer()
    {
        const QString announcerId = deviceIdFromHex(kFingerprint1);
        WinDnsSdDiscovery announcer(
            configFor(advertisementOf(kFingerprint1, QStringLiteral("广播方"), 4455), true));
        WinDnsSdDiscovery browser(
            configFor(advertisementOf(kFingerprint2, QStringLiteral("浏览方"), 0), false));
        QSignalSpy found(&browser, &WinDnsSdDiscovery::announced);

        mark(QStringLiteral("announcer: starting"));
        announcer.start();
        if (!announcer.lastError().isEmpty()) {
            g_skipped = true;
            mark(QStringLiteral("skipping: registration failed to start: %1")
                     .arg(announcer.lastError()));
            QSKIP(qPrintable(QStringLiteral("this machine cannot do system DNS-SD: %1")
                                 .arg(announcer.lastError())));
        }

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
            if (announcement.advertisement.deviceId() != announcerId)
                continue;
            matched = true;
            QCOMPARE(announcement.advertisement.name, QStringLiteral("广播方"));
            QCOMPARE(announcement.advertisement.fingerprint, kFingerprint1);
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
            g_skipped = true;
            mark(QStringLiteral("skipping: browse callbacks=%1, records=0, announcements=0 — "
                                "this machine's DNS-SD stack resolved nothing")
                     .arg(browser.browseCallbacks()));
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
            configFor(advertisementOf(kFingerprint3, QStringLiteral("自己"), 4456), true));
        QSignalSpy found(&self, &WinDnsSdDiscovery::announced);
        mark(QStringLiteral("self-filter case: starting"));
        self.start();
        if (!self.lastError().isEmpty()) {
            g_skipped = true;
            mark(QStringLiteral("skipping: registration failed to start: %1").arg(self.lastError()));
            QSKIP(qPrintable(QStringLiteral("this machine cannot do system DNS-SD: %1")
                                 .arg(self.lastError())));
        }

        QTest::qWait(3000);
        mark(QStringLiteral("self-filter case: done"));
        for (const QList<QVariant> &emission : found) {
            QVERIFY(emission.at(0).value<Announcement>().advertisement.deviceId()
                    != deviceIdFromHex(kFingerprint3));
        }
    }

    // 只浏览不通告：发送方没有在监听，没有端口也要能启动。
    void browseOnlyNeedsNoPort()
    {
        WinDnsSdDiscovery browser(
            configFor(advertisementOf(kFingerprint6, QStringLiteral("只要浏览"), 0), false));
        mark(QStringLiteral("browse-only case: starting"));
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(),
                 qPrintable(QStringLiteral("browse-only mode failed to start: %1").arg(browser.lastError())));
    }
};

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestWinDnsSd test;
    const int failures = QTest::qExec(&test, argc, argv);
    return (failures == 0 && g_skipped) ? kSkipExitCode : failures;
}

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
