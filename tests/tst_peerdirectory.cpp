// 对端目录（§3.3）。重点在三条：同一 deviceId 跨后端合并成一组地址、
// 地址按最近见到排序、超期即掉线。

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

    void announce(const QString &deviceId, const QString &name, const QHostAddress &address,
                  quint16 port, const QDateTime &seenAt)
    {
        Advertisement advertisement;
        advertisement.deviceId = deviceId;
        advertisement.name = name;
        advertisement.fingerprint = QString(64, QLatin1Char('a'));
        advertisement.version = version;
        advertisement.port = port;

        Announcement announcement;
        announcement.advertisement = advertisement;
        announcement.address = address;
        announcement.seenAt = seenAt;
        emit announced(announcement);
    }
};

const QString kDeviceA = QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
const QString kDeviceB = QStringLiteral("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
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

        first.announce(kDeviceA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                       kNow);
        first.announce(kDeviceA, QStringLiteral("笔记本"), QHostAddress("10.0.0.7"), 4443, kNow);
        second.announce(kDeviceA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
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

        source.announce(kDeviceA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                        kNow);
        source.announce(kDeviceA, QStringLiteral("笔记本"), QHostAddress("192.168.31.5"), 4443,
                        kNow.addSecs(1));

        QCOMPARE(directory.peers().first().addresses.size(), 1);
    }

    // 同一个 IP 的不同端口是两个连接目标。
    void differentPortsAreDifferentAddresses()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 5000, kNow);

        QCOMPARE(directory.peers().first().addresses.size(), 2);
    }

    // 多网卡机器上先试哪个由 lastSeen 决定：刚听到过的排最前。
    void addressesAreOrderedByRecency()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(kDeviceA, QString(), QHostAddress("10.0.0.7"), 4443, kNow);
        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 4443, kNow.addSecs(1));

        const QList<PeerDirectory::Address> addresses = directory.peers().first().addresses;
        QCOMPARE(addresses.size(), 2);
        QCOMPARE(addresses.at(0).address, QHostAddress("192.168.31.5"));

        // 老的地址再次被听到，顺序随之翻转。
        source.announce(kDeviceA, QString(), QHostAddress("10.0.0.7"), 4443, kNow.addSecs(2));
        QCOMPARE(directory.peers().first().addresses.at(0).address, QHostAddress("10.0.0.7"));
    }

    void addedAndUpdatedSignalsAreDistinct()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        QSignalSpy added(&directory, &PeerDirectory::peerAdded);
        QSignalSpy updated(&directory, &PeerDirectory::peerUpdated);

        source.announce(kDeviceA, QStringLiteral("旧名"), QHostAddress("192.168.31.5"), 4443, kNow);
        QCOMPARE(added.count(), 1);
        QCOMPARE(updated.count(), 0);

        source.announce(kDeviceA, QStringLiteral("新名"), QHostAddress("192.168.31.5"), 4443,
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
        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);

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

        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(kDeviceB, QString(), QHostAddress("192.168.31.6"), 4443, kNow.addSecs(1));

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
        source.announce(kDeviceA, QString(), QHostAddress("192.168.31.5"), 4443, kNow);

        const auto peer = directory.peer(kDeviceA);
        QVERIFY(peer.has_value());
        QVERIFY(!proto::isVersionCompatible(peer->version));
    }

    void announcementsWithoutDeviceIdOrAddressAreIgnored()
    {
        FakeDiscovery source;
        PeerDirectory directory;
        directory.addSource(&source);

        source.announce(QString(), QString(), QHostAddress("192.168.31.5"), 4443, kNow);
        source.announce(kDeviceA, QString(), QHostAddress(), 4443, kNow);

        QCOMPARE(directory.peers().size(), 0);
    }
};

QTEST_GUILESS_MAIN(TestPeerDirectory)

#include "tst_peerdirectory.moc"
