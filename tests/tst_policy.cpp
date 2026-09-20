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
};

QTEST_APPLESS_MAIN(TestPolicy)

#include "tst_policy.moc"
