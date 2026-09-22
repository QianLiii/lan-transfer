// Linux 的 Avahi 后端（§3.6）。这里要的是真的守护进程，没有就跳过——
// CI 的 runner 上通常没有 avahi-daemon，跳过比失败诚实。
//
// 本文件测的是「注册出去的服务，另一个实例能不能按 TXT 与 SRV 拿到同样的东西」。

#include <QtTest>

#include <QSignalSpy>

#include "protocol.h"

#ifdef LANPIPE_HAVE_AVAHI

#include "discovery/avahidiscovery.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

// 指定初始化漏字段会触发 -Wmissing-field-initializers（GCC 对带默认成员的聚合
// 也照报），所以配置一律这样拼出来。
AvahiDiscovery::Config configFor(const Advertisement &self, bool announce)
{
    AvahiDiscovery::Config config;
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
const QString kFingerprint4 = QString(64, QLatin1Char('4'));
const QString kFingerprint5 = QString(64, QLatin1Char('5'));
const QString kFingerprint6 = QString(64, QLatin1Char('6'));

} // namespace

class TestAvahi : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        if (!AvahiDiscovery::isAvailable())
            QSKIP("这台机器上没有 avahi-daemon，跳过");
    }

    // 一个实例注册、另一个实例浏览：浏览方应当拿到同样的指纹、名字与端口，
    // 并从中算出同样的 deviceId。
    void browseFindsAnAnnouncedPeer()
    {
        const QString announcerId = deviceIdFromHex(kFingerprint1);
        AvahiDiscovery announcer(configFor(
            advertisementOf(kFingerprint1, QStringLiteral("广播方"), 4455), true));

        AvahiDiscovery browser(configFor(
            advertisementOf(kFingerprint2, QStringLiteral("浏览方"), 0), false));
        QSignalSpy found(&browser, &AvahiDiscovery::announced);

        announcer.start();
        QVERIFY2(announcer.lastError().isEmpty(), qPrintable(announcer.lastError()));
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(), qPrintable(browser.lastError()));

        // DNS-SD 的浏览结果不是每 2 秒自己响一次，得等守护进程把结果推过来。
        QTRY_VERIFY_WITH_TIMEOUT(found.count() > 0, 10000);

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
            // 地址来自解析结果，必须是可用的地址而不是空。
            QVERIFY(!announcement.address.isNull());
            break;
        }
        QVERIFY2(matched, "没有从浏览结果里拿到注册的那条服务");
    }

    // 自己的注册守护进程也会报回来，必须按指纹滤掉，否则目录里会出现自己。
    void instanceDoesNotFindItself()
    {
        AvahiDiscovery self(configFor(
            advertisementOf(kFingerprint3, QStringLiteral("自己"), 4456), true));
        QSignalSpy found(&self, &AvahiDiscovery::announced);
        self.start();
        QVERIFY2(self.lastError().isEmpty(), qPrintable(self.lastError()));

        QTest::qWait(1500);
        for (const QList<QVariant> &emission : found) {
            QVERIFY(emission.at(0).value<Announcement>().advertisement.deviceId()
                    != deviceIdFromHex(kFingerprint3));
        }
    }

    // 关掉之后注册要撤销：另一个实例不应再收到它。
    void stoppingWithdrawsTheService()
    {
        const QString id = deviceIdFromHex(kFingerprint4);
        {
            AvahiDiscovery announcer(
                configFor(advertisementOf(kFingerprint4, QStringLiteral("临时"), 4457), true));
            announcer.start();
            QVERIFY2(announcer.lastError().isEmpty(), qPrintable(announcer.lastError()));
            QTest::qWait(500);
            announcer.stop();
        }

        AvahiDiscovery browser(configFor(
            advertisementOf(kFingerprint5, QStringLiteral("浏览方"), 0), false));
        QSignalSpy found(&browser, &AvahiDiscovery::announced);
        browser.start();
        QTest::qWait(1500);

        for (const QList<QVariant> &emission : found) {
            QVERIFY(emission.at(0).value<Announcement>().advertisement.deviceId() != id);
        }
    }

    // 通告端口 0 没有意义：与广播后端一样，启动时就报错。
    void refusesToStartWithoutPort()
    {
        AvahiDiscovery announcing(configFor(
            advertisementOf(kFingerprint1, QStringLiteral("没有端口"), 0), true));
        announcing.start();
        QVERIFY(!announcing.lastError().isEmpty());
    }

    // 只浏览不通告：没有端口也要能启动（发送方没有在监听）。
    void browseOnlyNeedsNoPort()
    {
        AvahiDiscovery browser(configFor(
            advertisementOf(kFingerprint6, QStringLiteral("只要浏览"), 0), false));
        browser.start();
        QVERIFY2(browser.lastError().isEmpty(), qPrintable(browser.lastError()));
    }
};

QTEST_GUILESS_MAIN(TestAvahi)

#else

using namespace lanpipe;

class TestAvahi : public QObject
{
    Q_OBJECT
private slots:
    void avahiBackendNotBuilt() { QSKIP("这个 Qt 构建没有 QtDBus，Avahi 后端未参与构建"); }
};

QTEST_GUILESS_MAIN(TestAvahi)

#endif

#include "tst_avahi.moc"
