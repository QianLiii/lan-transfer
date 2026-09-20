// 对端目录（§3.3）。重点在三条：同一 deviceId 跨后端合并成一组地址、
// 地址按最近见到排序、超期即掉线。
//
// deviceId 不在通告里，由目录从指纹现算——本文件因此全程只喂指纹。

#include <QtTest>

#include "discovery/discovery.h"
#include "discovery/peerdirectory.h"
#include "protocol.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

// 一个只会按测试要求发通告的后端。
class FakeDiscovery : public Discovery
{
public:
    using Discovery::Discovery;

    int version = proto::kVersion;

    void start() override { }
    void stop() override { }
    [[nodiscard]] QString backendName() const override { return QStringLiteral("fake"); }
    [[nodiscard]] QString lastError() const override { return {}; }

    void announce(const QString &fingerprint, const QString &name, const QHostAddress &address,
                  quint16 port, const QDateTime &seenAt)
    {
        Advertisement advertisement;
        advertisement.name = name;
        advertisement.fingerprint = fingerprint;
        advertisement.version = version;
        advertisement.port = port;

        Announcement announcement;
        announcement.advertisement = advertisement;
        announcement.address = address;
        announcement.seenAt = seenAt;
        emit announced(announcement);
    }
};

// 通告里只有指纹，deviceId 由指纹现算——这两个常量因此是同一条推导的两端。
const QString kFingerprintA = QString(64, QLatin1Char('a'));
const QString kFingerprintB = QString(64, QLatin1Char('b'));
const QString kDeviceA = kFingerprintA.left(32);
const QString kDeviceB = kFingerprintB.left(32);
const QDateTime kNow = QDateTime::currentDateTimeUtc();

} // namespace

class TestPeerDirectory : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase() { qRegisterMetaType<Announcement>(); }

    // 同一台设备经两个后端出现：一个对端，两个地址。
    void mergesSourcesIntoOnePeerWithAddressSet()
    {
        FakeDiscovery first;
        FakeDiscovery second;
        PeerDirectory directory;
        directory.addSource(&first);
        directory.addSource(&second);

        first.announce(kFingerprintA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                       kNow);
        first.announce(kFingerprintA, QStringLiteral("笔记本"), QHostAddress("10.0.0.7"), 4443, kNow);
        second.announce(kFingerprintA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                        kNow.addSecs(1));

        const QList<PeerDirectory::Peer> peers = directory.peers();
        QCOMPARE(peers.size(), 1);
        QCOMPARE(peers.first().addresses.size(), 2);
    }

    // 同一个地址反复出现不能越积越多。
    void repeatedAnnouncementDoesNotDuplicateAddress()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kFingerprintA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                        kNow);
        source.announce(kFingerprintA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                        kNow.addSecs(1));

        QCOMPARE(directory.peers().first().addresses.size(), 1);
    }

    // 同一个 IP 的不同端口是两个连接目标。
    void differentPortsAreDifferentAddresses()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 5000, kNow);

        QCOMPARE(directory.peers().first().addresses.size(), 2);
    }

    // 多网卡机器上先试哪个由 lastSeen 决定：刚听到过的排最前。
    void addressesAreOrderedByRecency()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kFingerprintA, QString(), QHostAddress("10.0.0.7"), 4443, kNow);
        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 4443, kNow.addSecs(1));

        const QList<PeerDirectory::Address> addresses = directory.peers().first().addresses;
        QCOMPARE(addresses.size(), 2);
        QCOMPARE(addresses.at(0).address, QHostAddress("192.168.31.5"));

        // 老的地址再次被听到，顺序随之翻转。
        source.announce(kFingerprintA, QString(), QHostAddress("10.0.0.7"), 4443, kNow.addSecs(2));
        QCOMPARE(directory.peers().first().addresses.at(0).address, QHostAddress("10.0.0.7"));
    }

    void addedAndUpdatedSignalsAreDistinct()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        QSignalSpy added(&directory, &PeerDirectory::peerAdded);
        QSignalSpy updated(&directory, &PeerDirectory::peerUpdated);

        source.announce(kFingerprintA, QStringLiteral("旧名"), QHostAddress("192.168.31.5"), 4443, kNow);
        QCOMPARE(added.count(), 1);
        QCOMPARE(updated.count(), 0);

        source.announce(kFingerprintA, QStringLiteral("新名"), QHostAddress("192.168.31.5"), 4443,
                        kNow.addSecs(1));
        QCOMPARE(added.count(), 1);
        QCOMPARE(updated.count(), 1);
        QCOMPARE(directory.peer(kDeviceA)->name, QStringLiteral("新名"));
    }

    void peerIsRemovedAfterExpiry()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);
        directory.setExpiry(std::chrono::seconds(10));

        QSignalSpy removed(&directory, &PeerDirectory::peerRemoved);
        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);

        directory.prune(kNow.addSecs(9));
        QCOMPARE(directory.peers().size(), 1);
        QCOMPARE(removed.count(), 0);

        directory.prune(kNow.addSecs(11));
        QCOMPARE(directory.peers().size(), 0);
        QCOMPARE(removed.count(), 1);
        QVERIFY(!directory.peer(kDeviceA).has_value());
    }

    void peersAreOrderedByLastSeen()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(kFingerprintB, QString(), QHostAddress("192.168.31.6"), 4443, kNow.addSecs(1));

        const QList<PeerDirectory::Peer> peers = directory.peers();
        QCOMPARE(peers.size(), 2);
        QCOMPARE(peers.at(0).deviceId, kDeviceB);
        QCOMPARE(peers.at(1).deviceId, kDeviceA);
    }

    // 版本不兼容的对端仍然列出来：界面需要能解释「为什么发不了」，
    // 而不是让它凭空消失。
    void incompatiblePeerIsStillListed()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);
        source.version = proto::kVersion + 1;
        source.announce(kFingerprintA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);

        const auto peer = directory.peer(kDeviceA);
        QVERIFY(peer.has_value());
        QVERIFY(!proto::isVersionCompatible(peer->version));
    }

    // 算不出 deviceId 的通告（指纹缺失或不是 64 个十六进制字符）与没有地址的通告
    // 一样，都不进目录。
    void announcementsWithoutFingerprintOrAddressAreIgnored()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(QString(), QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(QStringLiteral("不是指纹"), QString(), QHostAddress("192.168.31.5"), 4443,
                        kNow);
        source.announce(QString(64, QLatin1Char('z')), QString(), QHostAddress("192.168.31.5"), 4443,
                        kNow);
        source.announce(kFingerprintA, QString(), QHostAddress(), 4443, kNow);

        QCOMPARE(directory.peers().size(), 0);
    }
};

QTEST_GUILESS_MAIN(TestPeerDirectory)

#include "tst_peerdirectory.moc"
