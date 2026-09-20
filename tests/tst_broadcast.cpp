// UDP 广播兜底（§3.4）。编解码是纯函数，收发靠真实 socket。
//
// 这里测不到的部分要说清楚：报文能不能穿过一个过滤了组播的网络，只有两台真机
// 才能验。本文件测的是「载荷对不对、自己发的会不会被当成别人、坏报文会不会被吃」。

#include <QtTest>

#include <QUdpSocket>

#include "discovery/broadcastdiscovery.h"
#include "discovery/peerdirectory.h"
#include "protocol.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

Advertisement sampleAdvertisement()
{
    Advertisement advertisement;
    advertisement.name = QStringLiteral("笔记本");
    // 64 个十六进制字符；它派生出的 deviceId 就是前 32 个。
    advertisement.fingerprint = QStringLiteral("0123456789abcdef").repeated(4);
    advertisement.version = proto::kVersion;
    advertisement.port = 4443;
    return advertisement;
}

// 一个只负责收的裸 socket，用来观察 BroadcastDiscovery 真正发出去了什么。
// 自动排空：QTRY_VERIFY 只会转事件循环，不会替我们调用 collect()。
class RawReceiver
{
public:
    bool open()
    {
        QObject::connect(&m_socket, &QUdpSocket::readyRead, &m_socket, [this] { collect(); });
        return m_socket.bind(QHostAddress::LocalHost, 0,
                             QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint);
    }

    [[nodiscard]] quint16 port() const { return m_socket.localPort(); }
    [[nodiscard]] int datagramCount() const { return m_received.size(); }

    [[nodiscard]] QByteArray last() const
    {
        return m_received.isEmpty() ? QByteArray() : m_received.last();
    }

    void collect()
    {
        while (m_socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<qsizetype>(m_socket.pendingDatagramSize()));
            m_socket.readDatagram(datagram.data(), datagram.size());
            m_received.append(datagram);
        }
    }

private:
    QUdpSocket m_socket;
    QList<QByteArray> m_received;
};

} // namespace

class TestBroadcast : public QObject
{
    Q_OBJECT

private slots:
    // —————————————— 编解码 ——————————————

    void codecRoundTrips()
    {
        const Advertisement original = sampleAdvertisement();
        const auto decoded = decodeAdvertisement(encodeAdvertisement(original));

        QVERIFY(decoded.has_value());
        QCOMPARE(decoded->name, original.name);
        QCOMPARE(decoded->fingerprint, original.fingerprint);
        QCOMPARE(decoded->version, original.version);
        QCOMPARE(decoded->port, original.port);
        // deviceId 不参与往返，两端各自从同一个指纹算出同一个值。
        QCOMPARE(decoded->deviceId(), original.deviceId());
        QCOMPARE(decoded->deviceId(),
                 QStringLiteral("0123456789abcdef0123456789abcdef"));
    }

    void codecRejectsMalformedPayloads()
    {
        const QList<QByteArray> bad{
            QByteArray(),
            QByteArray("not json"),
            QByteArray("[1,2,3]"),
            // 缺字段
            QByteArray(R"({"fp":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})"),
            // 指纹长度不对
            QByteArray(R"({"name":"x","fp":"..","ver":1,"port":4443})"),
            // 指纹含非十六进制字符
            QByteArray(R"({"name":"x",)"
                       R"("fp":"zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",)"
                       R"("ver":1,"port":4443})"),
            // 版本不是整数
            QByteArray(R"({"name":"x",)"
                       R"("fp":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",)"
                       R"("ver":"1","port":4443})"),
            // 端口 0 在通告里没有意义
            QByteArray(R"({"name":"x",)"
                       R"("fp":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",)"
                       R"("ver":1,"port":0})"),
            // 端口越界
            QByteArray(R"({"name":"x",)"
                       R"("fp":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",)"
                       R"("ver":1,"port":70000})"),
        };
        for (const QByteArray &payload : bad) {
            QVERIFY2(!decodeAdvertisement(payload).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(QString::fromUtf8(payload))));
        }
    }

    // §3.2 的 255 字节上限：超长名字按 UTF-8 边界截断，不截出半个字符。
    void longNameIsTruncatedOnUtf8Boundary()
    {
        Advertisement advertisement = sampleAdvertisement();
        advertisement.name = QString(200, QChar(0x4E2D)); // 每字 3 字节 → 600 字节

        const auto decoded = decodeAdvertisement(encodeAdvertisement(advertisement));
        QVERIFY(decoded.has_value());
        QVERIFY(decoded->name.toUtf8().size() <= 255);
        // 截断处必须仍是完整的字符：全部是同一个汉字，长度应是 3 的倍数。
        QCOMPARE(decoded->name.toUtf8().size() % 3, 0);
    }

    // —————————————— 收发 ——————————————

    // 收：别人发来的合法通告应当被报出来，地址取自来源而不是载荷。
    void receivesAnnouncementFromPeer()
    {
        BroadcastDiscovery discovery({.self = sampleAdvertisement(),
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = 0,
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::seconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        QSignalSpy spy(&discovery, &BroadcastDiscovery::announced);
        discovery.start();
        QVERIFY(discovery.lastError().isEmpty());
        QVERIFY(discovery.boundPort() != 0);

        Advertisement peer = sampleAdvertisement();
        peer.fingerprint = QStringLiteral("f").repeated(64);
        peer.name = QStringLiteral("台式机");

        QUdpSocket sender;
        QVERIFY(sender.bind(QHostAddress::LocalHost, 0));
        QCOMPARE(sender.writeDatagram(encodeAdvertisement(peer), QHostAddress::LocalHost,
                                      discovery.boundPort()),
                 qint64(encodeAdvertisement(peer).size()));

        QVERIFY(spy.wait(1000));
        const auto announcement = spy.first().at(0).value<Announcement>();
        QCOMPARE(announcement.advertisement.deviceId(), peer.deviceId());
        QCOMPARE(announcement.advertisement.name, QStringLiteral("台式机"));
        QCOMPARE(announcement.address, QHostAddress::LocalHost);
    }

    // 发：定时把通告发出去，内容能被解回来。
    void sendsAdvertisementPeriodically()
    {
        RawReceiver receiver;
        QVERIFY(receiver.open());

        BroadcastDiscovery discovery({.self = sampleAdvertisement(),
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = receiver.port(),
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::milliseconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        discovery.start();
        QVERIFY(discovery.lastError().isEmpty());

        QTRY_VERIFY_WITH_TIMEOUT(receiver.datagramCount() >= 2, 2000);
        receiver.collect();

        const auto decoded = decodeAdvertisement(receiver.last());
        QVERIFY(decoded.has_value());
        QCOMPARE(decoded->fingerprint, sampleAdvertisement().fingerprint);
    }

    // 只浏览不通告：发送方没有在监听，通告出去只会让别人连到一个不存在的端口。
    void browseOnlyModeSendsNothing()
    {
        RawReceiver receiver;
        QVERIFY(receiver.open());

        BroadcastDiscovery discovery({.self = sampleAdvertisement(),
                                      .announce = false,
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = receiver.port(),
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::milliseconds(20),
                                      .jitter = std::chrono::milliseconds(0)});
        discovery.start();
        QVERIFY(discovery.lastError().isEmpty());

        QTest::qWait(200); // 足够发好几轮
        QCOMPARE(receiver.datagramCount(), 0);
    }

    // 通告关掉之后，端口为 0 也不再是错误——本来就没有东西要通告。
    void browseOnlyModeStartsWithoutAPort()
    {
        Advertisement self = sampleAdvertisement();
        self.port = 0;

        BroadcastDiscovery discovery({.self = self,
                                      .announce = false,
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = 0,
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::seconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        discovery.start();
        QVERIFY(discovery.lastError().isEmpty());

        // 但通告开启时仍然要求有端口。
        BroadcastDiscovery announcing({.self = self,
                                       .bindAddress = QHostAddress::LocalHost,
                                       .bindPort = 0,
                                       .sendPort = 0,
                                       .targets = {QHostAddress::LocalHost},
                                       .interval = std::chrono::seconds(30),
                                       .jitter = std::chrono::milliseconds(0)});
        announcing.start();
        QVERIFY(!announcing.lastError().isEmpty());
    }

    // 自己发的广播会回环到本机，必须按指纹滤掉，否则目录里会出现自己。
    void ignoresOwnAnnouncements()
    {
        BroadcastDiscovery discovery({.self = sampleAdvertisement(),
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = 0,
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::milliseconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        QSignalSpy spy(&discovery, &BroadcastDiscovery::announced);
        discovery.start();

        QTest::qWait(200); // 足够发好几轮
        QCOMPARE(spy.count(), 0);
    }

    // 坏报文被丢掉，不产生任何通告，也不影响后续正常报文。
    void malformedDatagramIsIgnored()
    {
        BroadcastDiscovery discovery({.self = sampleAdvertisement(),
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = 0,
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::seconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        QSignalSpy spy(&discovery, &BroadcastDiscovery::announced);
        discovery.start();
        QVERIFY(discovery.boundPort() != 0);

        QUdpSocket sender;
        QVERIFY(sender.bind(QHostAddress::LocalHost, 0));
        for (const QByteArray &garbage : {QByteArray("not json"),
                                          QByteArray(R"({"name":"short"})"), QByteArray(2000, 'x')}) {
            sender.writeDatagram(garbage, QHostAddress::LocalHost, discovery.boundPort());
        }
        QTest::qWait(200);
        QCOMPARE(spy.count(), 0);

        // 正常报文仍然收得到——坏报文没有把 socket 弄坏。
        Advertisement peer = sampleAdvertisement();
        peer.fingerprint = QStringLiteral("f").repeated(64);
        sender.writeDatagram(encodeAdvertisement(peer), QHostAddress::LocalHost,
                             discovery.boundPort());
        QVERIFY(spy.wait(1000));
        QCOMPARE(spy.count(), 1);
    }

    // 端口没配好时不启动，而不是发一份没用的通告出去。
    void refusesToStartWithoutPort()
    {
        Advertisement self = sampleAdvertisement();
        self.port = 0;

        BroadcastDiscovery discovery({.self = self,
                                      .bindAddress = QHostAddress::LocalHost,
                                      .bindPort = 0,
                                      .sendPort = 0,
                                      .targets = {QHostAddress::LocalHost},
                                      .interval = std::chrono::milliseconds(30),
                                      .jitter = std::chrono::milliseconds(0)});
        discovery.start();

        QVERIFY(!discovery.lastError().isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestBroadcast)

#include "tst_broadcast.moc"
