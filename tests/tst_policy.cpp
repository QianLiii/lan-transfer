// 接收策略（§4 接收策略）。纯函数，不需要事件循环。
//
// 这里只测判定本身；「身份变化优先于开放模式」那条顺序由调用方保证，
// 它的用例在 tst_receiveservice 里。

#include <QtTest>

#include <QDateTime>
#include <QTemporaryDir>

#include "identity.h"
#include "mtls.h"
#include "settings.h"
#include "trust/policy.h"
#include "trust/truststore.h"

using namespace lanpipe;
using namespace lanpipe::trust;

namespace {

const QString kPeerFingerprint = QString(64, QLatin1Char('a'));
const QString kOtherFingerprint = QString(64, QLatin1Char('b'));

net::PeerIdentity peerWith(const QString &fingerprintHex)
{
    const auto fingerprint = Fingerprint::fromHex(fingerprintHex);
    Q_ASSERT(fingerprint.has_value());
    return net::PeerIdentity{*fingerprint, deviceIdFrom(*fingerprint)};
}

} // namespace

class TestPolicy : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    Settings *m_settings = nullptr;
    TrustStore *m_trust = nullptr;

    void pair(const net::PeerIdentity &peer)
    {
        QString error;
        QVERIFY(m_trust->add({peer.deviceId, peer.fingerprint.toHex(), QStringLiteral("对端"),
                              QDateTime::currentDateTimeUtc()},
                             &error));
    }

private slots:
    void initTestCase() { QVERIFY(m_dir.isValid()); }

    void init()
    {
        delete m_settings;
        delete m_trust;
        QFile::remove(m_dir.filePath(QStringLiteral("settings.ini")));
        QFile::remove(m_dir.filePath(QStringLiteral("trust.json")));

        m_settings = new Settings(m_dir.filePath(QStringLiteral("settings.ini")));
        m_settings->setDeviceName(QStringLiteral("接收方"));

        auto trust = TrustStore::load(m_dir.filePath(QStringLiteral("trust.json")));
        if (!trust.has_value())
            QFAIL(qPrintable(trust.error()));
        m_trust = new TrustStore(*trust);
    }

    void cleanup()
    {
        delete m_settings;
        m_settings = nullptr;
        delete m_trust;
        m_trust = nullptr;
    }

    // 默认策略是 PromptAlways：连已配对设备也要问（§4）。
    void defaultPolicyPromptsEvenForAPairedPeer()
    {
        const net::PeerIdentity peer = peerWith(kPeerFingerprint);
        pair(peer);

        QCOMPARE(m_settings->receivePolicy(), ReceivePolicy::PromptAlways);
        QCOMPARE(decide(*m_settings, *m_trust, peer), Decision::Prompt);
    }

    void autoAcceptOnlyAppliesToPairedPeers()
    {
        const net::PeerIdentity paired = peerWith(kPeerFingerprint);
        const net::PeerIdentity stranger = peerWith(kOtherFingerprint);
        pair(paired);
        m_settings->setReceivePolicy(ReceivePolicy::AutoAcceptPaired);

        QCOMPARE(decide(*m_settings, *m_trust, paired), Decision::Accept);
        QCOMPARE(decide(*m_settings, *m_trust, stranger), Decision::Prompt);
    }

    void openModeAcceptsAnyone()
    {
        m_settings->setOpenMode(true);
        m_settings->setReceivePolicy(ReceivePolicy::PromptAlways);

        QCOMPARE(decide(*m_settings, *m_trust, peerWith(kOtherFingerprint)), Decision::Accept);
    }

    // 开放模式关掉之后一切照旧——开关只认我们写下去的那几种取值（settings.cpp）。
    void closingOpenModeRestoresPrompting()
    {
        m_settings->setOpenMode(true);
        m_settings->setOpenMode(false);

        QCOMPARE(decide(*m_settings, *m_trust, peerWith(kOtherFingerprint)), Decision::Prompt);
    }

    // —————————————— 黑名单（§4）——————————————

    // 屏蔽优先于一切：连开放模式都不该把它放回来。
    void blockedPeerIsRejectedEvenInOpenMode()
    {
        const net::PeerIdentity peer = peerWith(kPeerFingerprint);
        m_settings->setOpenMode(true);

        QString error;
        QVERIFY(m_trust->block({peer.deviceId, QStringLiteral("广告机"),
                                QDateTime::currentDateTimeUtc()},
                               &error));

        QCOMPARE(decide(*m_settings, *m_trust, peer), Decision::Reject);
    }

    // 自动接受也压不过黑名单。
    void blockedPairedPeerIsStillRejected()
    {
        const net::PeerIdentity peer = peerWith(kPeerFingerprint);
        pair(peer);
        m_settings->setReceivePolicy(ReceivePolicy::AutoAcceptPaired);
        QCOMPARE(decide(*m_settings, *m_trust, peer), Decision::Accept);

        QString error;
        QVERIFY(m_trust->block({peer.deviceId, QStringLiteral("对端"),
                                QDateTime::currentDateTimeUtc()},
                               &error));

        QCOMPARE(decide(*m_settings, *m_trust, peer), Decision::Reject);
    }

    // —————————————— 提示限流（§4）——————————————

    void promptLimiterAllowsUpToTheMaximum()
    {
        PromptLimiter limiter(3, std::chrono::seconds(60));
        const QDateTime now = QDateTime::currentDateTimeUtc();

        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now));
        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now));
        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now));
        QVERIFY(!limiter.allowPrompt(QStringLiteral("a"), now));

        // 限流是按设备分的：一台设备闹得凶，不该连累另一台。
        QVERIFY(limiter.allowPrompt(QStringLiteral("b"), now));

        // 窗口滑过去之后重新放行。
        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now.addSecs(61)));
    }

    // 键不能随「见过的设备数」无限增长：deviceId 是自签证书现算的，每个连接换一把
    // 密钥就是一个新键。窗口滑过去之后要把它们收掉。
    void promptLimiterDoesNotAccumulateDevices()
    {
        PromptLimiter limiter(3, std::chrono::seconds(60));
        const QDateTime now = QDateTime::currentDateTimeUtc();

        for (int i = 0; i < 1000; ++i)
            QVERIFY(limiter.allowPrompt(QStringLiteral("dev%1").arg(i), now));

        // 窗口内这些设备都还得留着——那是限流本身要记的东西，不是泄漏。
        QVERIFY(limiter.trackedDevices() > 500);

        // 窗口滑过去之后再问一台：顺带把陈旧的整批收掉。
        QVERIFY(limiter.allowPrompt(QStringLiteral("later"), now.addSecs(120)));
        QCOMPARE(limiter.trackedDevices(), 1);
    }

    void promptLimiterWindowSlides()
    {
        PromptLimiter limiter(2, std::chrono::seconds(60));
        const QDateTime now = QDateTime::currentDateTimeUtc();

        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now));
        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now.addSecs(30)));
        QVERIFY(!limiter.allowPrompt(QStringLiteral("a"), now.addSecs(31)));

        // 第一次已经滑出窗口，于是又有一个名额。
        QVERIFY(limiter.allowPrompt(QStringLiteral("a"), now.addSecs(61)));
    }
};

QTEST_APPLESS_MAIN(TestPolicy)

#include "tst_policy.moc"
