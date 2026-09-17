// 多地址回退（§3.3）。
//
// 它不碰网络，所以这里能一条条把状态走完：顺序、超时、以及**握手之后必须撤掉时限**
// ——ping 的响应要等接收方的用户输码，用连接时限去卡它会把合法连接当成死地址。

#include <QtTest>

#include <QSignalSpy>

#include "discovery/peerconnector.h"
#include "protocol.h"

using namespace lanpipe;
using namespace lanpipe::discovery;

namespace {

QList<PeerDirectory::Address> addressesOf(const QList<QPair<QString, quint16>> &list)
{
    QList<PeerDirectory::Address> addresses;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const auto &[host, port] : list)
        addresses.append({QHostAddress(host), port, now});
    return addresses;
}

} // namespace

class TestPeerConnector : public QObject
{
    Q_OBJECT

private slots:
    void walksThroughAddressesInOrder()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}, {"192.168.31.5", 4443}}),
                                std::chrono::seconds(30));
        QSignalSpy timedOut(&connector, &PeerConnector::attemptTimedOut);

        const auto first = connector.startNext();
        QVERIFY(first.has_value());
        QCOMPARE(first->address, QHostAddress("10.0.0.7"));
        QCOMPARE(first->port, quint16{4443});
        connector.failed(QStringLiteral("连接被拒绝"));

        const auto second = connector.startNext();
        QVERIFY(second.has_value());
        QCOMPARE(second->address, QHostAddress("192.168.31.5"));

        QCOMPARE(connector.triedCount(), 2);
        QCOMPARE(timedOut.count(), 0);
    }

    void succeededStopsTheWalk()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}, {"192.168.31.5", 4443}}),
                                std::chrono::seconds(30));

        QVERIFY(connector.startNext().has_value());
        connector.succeeded();
        QVERIFY(!connector.startNext().has_value());
        QVERIFY(connector.exhausted());
    }

    // 地址用完就是「全试过了」，此后不再给地址、也不再有信号。
    void exhaustedAfterEveryAddress()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}}), std::chrono::seconds(30));

        QVERIFY(connector.startNext().has_value());
        connector.failed(QStringLiteral("连接超时"));
        QVERIFY(!connector.startNext().has_value());
        QVERIFY(connector.exhausted());
        QVERIFY(connector.failureSummary().contains(QStringLiteral("10.0.0.7:4443")));
    }

    // 用满时限即判定这个地址不行，并把「超时」记进诊断。
    void timeoutCountsAsAFailureOfThatAddress()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}}),
                                std::chrono::milliseconds(30));
        QSignalSpy timedOut(&connector, &PeerConnector::attemptTimedOut);

        QVERIFY(connector.startNext().has_value());
        QTRY_COMPARE(timedOut.count(), 1);
        QVERIFY(connector.failureSummary().contains(QStringLiteral("连接超时")));

        // 超时之后再要地址：没有了。
        QVERIFY(!connector.startNext().has_value());
    }

    // 最关键的一条：握手一完成就撤掉时限。ping 的响应要等接收方的用户输码，
    // 可能长达两分钟，用连接时限去卡它会把合法连接当成死地址。
    void connectedLiftsTheDeadline()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}}),
                                std::chrono::milliseconds(20));
        QSignalSpy timedOut(&connector, &PeerConnector::attemptTimedOut);

        QVERIFY(connector.startNext().has_value());
        connector.connected();

        QTest::qWait(100); // 远超时限
        QCOMPARE(timedOut.count(), 0);
    }

    void failureSummaryNamesEveryAddressAndReason()
    {
        PeerConnector connector(addressesOf({{"10.0.0.7", 4443}, {"192.168.31.5", 4443}}),
                                std::chrono::seconds(30));

        QVERIFY(connector.startNext().has_value());
        connector.failed(QStringLiteral("连接被拒绝"));
        QVERIFY(connector.startNext().has_value());
        connector.failed(QStringLiteral("证书不符"));

        const QString summary = connector.failureSummary();
        QVERIFY(summary.contains(QStringLiteral("10.0.0.7:4443")));
        QVERIFY(summary.contains(QStringLiteral("连接被拒绝")));
        QVERIFY(summary.contains(QStringLiteral("192.168.31.5:4443")));
        QVERIFY(summary.contains(QStringLiteral("证书不符")));
    }

    void noAddressesMeansNoWork()
    {
        PeerConnector connector({}, std::chrono::seconds(3));
        QVERIFY(!connector.startNext().has_value());
        QVERIFY(connector.exhausted());
        QCOMPARE(connector.triedCount(), 0);
    }
};

QTEST_GUILESS_MAIN(TestPeerConnector)

#include "tst_peerconnector.moc"
