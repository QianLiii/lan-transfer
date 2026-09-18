// Windows 的系统 DNS-SD 后端（§3.6）。
//
// 这份代码是在 Linux 上写的、**从未编译过**，所以这套测试的第一价值就是「能不能跑」：
// 在 Windows 上 `ctest -R tst_windnssd` 是验证它的最短路径。
//
// 与 Avahi 那套对应：一个实例注册、另一个浏览；自过滤；只浏览模式。

#include <QtTest>

#include <QSignalSpy>

#include "protocol.h"

#ifdef LANPIPE_HAVE_WINDNSSD

#include "discovery/windnssddiscovery.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

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

        announcer.start();
        if (!announcer.lastError().isEmpty())
            QSKIP(qPrintable(QStringLiteral("本机不支持系统 DNS-SD：%1").arg(announcer.lastError())));
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(),
                 qPrintable(QStringLiteral("浏览方启动失败：%1").arg(browser.lastError())));

        // 系统解析要走一次 mDNS 往返，比 Avahi 那条 D-Bus 路慢一些。
        QTRY_VERIFY_WITH_TIMEOUT(found.count() > 0, 15000);

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
            QStringLiteral("没有从浏览结果里拿到注册的那条服务；注册方 lastError=%1；"
                           "浏览方 lastError=%2；收到的通告数=%3")
                .arg(announcer.lastError().isEmpty() ? QStringLiteral("（空）")
                                                     : announcer.lastError(),
                     browser.lastError().isEmpty() ? QStringLiteral("（空）")
                                                   : browser.lastError(),
                     QString::number(found.count()));
        QVERIFY2(matched, qPrintable(diagnosis));
    }

    void instanceDoesNotFindItself()
    {
        WinDnsSdDiscovery self(
            configFor(advertisementOf(QStringLiteral("33333333333333333333333333333333"),
                                      QStringLiteral("自己"), 4456),
                      true));
        QSignalSpy found(&self, &WinDnsSdDiscovery::announced);
        self.start();
        if (!self.lastError().isEmpty())
            QSKIP(qPrintable(QStringLiteral("本机不支持系统 DNS-SD：%1").arg(self.lastError())));

        QTest::qWait(3000);
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
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(),
                 qPrintable(QStringLiteral("只浏览模式启动失败：%1").arg(browser.lastError())));
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
