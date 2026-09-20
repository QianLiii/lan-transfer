// /ping 与配对（§4）。M1/M4 的验收在这里。
//
// 这里的测试同时扮演两个用户：发送方那半从 peerAdopted 拿到，接收方那半从
// inputRequired 拿到，然后把「对方屏幕上显示的那半」输进去。
//
// 端到端用我们自己的客户端（PingClient）；协议边界的负向用例用裸 TLS 连接，
// 因为要发的正是客户端永远不会发的形态。

#include <QtTest>

#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>

#include "http/httpserver.h"
#include "identity.h"
#include "protocol.h"
#include "rawclient.h"
#include "settings.h"
#include "transfer/ping.h"
#include "transfer/pingclient.h"
#include "trust/truststore.h"

using namespace lanpipe;
using namespace lanpipe::http;
using namespace lanpipe::transfer;

class TestPing : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    QTemporaryDir m_settingsDir;
    QTemporaryDir m_senderDir;
    Identity m_identity;  // 接收方
    Identity m_sender;
    // 必须给路径：默认构造走的是 QSettings 的原生用户位置，测试会写进开发者真实的
    // ~/.config/lanpipe/。
    Settings m_settings{m_settingsDir.filePath(QStringLiteral("settings.ini"))};
    std::expected<trust::TrustStore, QString> m_trust;
    HttpServer m_server;
    PingService *m_service = nullptr;
    quint16 m_port = 0;

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid() && m_settingsDir.isValid() && m_senderDir.isValid());

        auto receiver = Identity::loadOrCreate(m_dir.filePath(QStringLiteral("receiver")));
        auto sender = Identity::loadOrCreate(m_senderDir.filePath(QStringLiteral("sender")));
        if (!receiver.has_value())
            QFAIL(qPrintable(receiver.error()));
        if (!sender.has_value())
            QFAIL(qPrintable(sender.error()));
        m_identity = *receiver;
        m_sender = *sender;

        m_settings.setDeviceName(QStringLiteral("接收方"));

        // 每条用例都从空的信任库开始。
        m_trust = trust::TrustStore::load(m_settingsDir.filePath(QStringLiteral("trust.json")));
        if (!m_trust.has_value())
            QFAIL(qPrintable(m_trust.error()));

        m_service = new PingService(m_identity, m_settings, *m_trust, &m_server);
        m_server.setHandler([this](HttpConnection &connection) {
            if (PingService::handles(connection.head().target)) {
                m_service->handle(connection);
                return;
            }
            connection.respond(Response::text(Status::NotFound, QStringLiteral("未知目标")));
        });

        auto port = m_server.listen(m_identity, 0);
        if (!port.has_value())
            QFAIL(qPrintable(port.error()));
        m_port = *port;
    }

    void init()
    {
        QString error;
        QVERIFY(m_trust->clear(&error) || error.isEmpty());
        m_service->setInputWindow(proto::kSasInputWindow);
    }

    [[nodiscard]] QUrl serverUrl() const
    {
        return QUrl(QStringLiteral("https://127.0.0.1:%1").arg(m_port));
    }

    // —————————————— 端到端 ——————————————

    // 一次往返里两端各自完成比对，且**接收方是在响应之前等它的用户输入**：
    // 发送方那半必须先显示出来，接收方才有东西可输入。
    void bothSidesVerifyWithinOneRoundTrip()
    {
        PingClient client(*m_trust);
        QSignalSpy adopted(&client, &PingClient::peerAdopted);
        QSignalSpy finished(&client, &PingClient::finished);
        QSignalSpy inputRequired(m_service, &PingService::inputRequired);
        QSignalSpy pairingFinished(m_service, &PingService::pairingFinished);

        client.start(serverUrl(), m_sender, QStringLiteral("发送方"));

        // 发送方那半在握手完成时就显示了；此刻接收方正在等它的用户。
        QTRY_COMPARE(adopted.count(), 1);
        QTRY_COMPARE(inputRequired.count(), 1);
        QCOMPARE(finished.count(), 0); // 响应被推迟到接收方的用户给出答案之后

        const SasCode senderCode = adopted.first().at(0).value<SasCode>();
        const SasCode receiverCode = inputRequired.first().at(2).value<SasCode>();
        QCOMPARE(inputRequired.first().at(1).toString(), QStringLiteral("发送方"));

        // 每一端要输入的，正是对方屏幕上显示的那半。
        QCOMPARE(receiverCode.asked, senderCode.shown);
        QCOMPARE(receiverCode.shown, senderCode.asked);

        m_service->submitInput(senderCode.shown); // 接收方的用户照做

        QTRY_COMPARE(pairingFinished.count(), 1);
        QCOMPARE(pairingFinished.first().at(1).value<PingService::Outcome>(),
                 PingService::Outcome::Accepted);

        QTRY_COMPARE(finished.count(), 1);
        const auto result = finished.first().at(0).value<PingClient::Result>();
        if (!result.ok)
            QFAIL(qPrintable(result.error));

        // 发送方回应的那半 = 接收方显示的那半。
        QVERIFY(result.code.matches(receiverCode.shown));
        // deviceId 不在响应里，由握手指纹现算——算出来就是接收方的身份。
        QCOMPARE(deviceIdFrom(result.peerFingerprint), m_identity.deviceId());
        QCOMPARE(result.info.name, QStringLiteral("接收方"));
        QCOMPARE(result.info.version, proto::kVersion);
        QCOMPARE(result.info.fingerprint.toHex(), m_identity.fingerprint().toHex());
        QCOMPARE(result.peerFingerprint.toHex(), m_identity.fingerprint().toHex());
        QVERIFY(result.info.reachable);

        // 接收方这边写下了配对，写的是握手时观察到的指纹。
        const auto entry = m_trust->find(m_sender.deviceId());
        QVERIFY(entry.has_value());
        QCOMPARE(entry->fingerprint, m_sender.fingerprint().toHex());
        QCOMPARE(entry->name, QStringLiteral("发送方"));
    }

    // 接收方那边输错了：它当场拒绝，结论随响应回去，且不写入信任库。
    void receiverMismatchIsReportedToTheSender()
    {
        PingClient client(*m_trust);
        QSignalSpy finished(&client, &PingClient::finished);
        QSignalSpy inputRequired(m_service, &PingService::inputRequired);
        QSignalSpy pairingFinished(m_service, &PingService::pairingFinished);

        client.start(serverUrl(), m_sender, QStringLiteral("发送方"));
        QTRY_COMPARE(inputRequired.count(), 1);

        m_service->submitInput(QStringLiteral("000000")); // 除了巧合，必然不等

        QTRY_COMPARE(pairingFinished.count(), 1);
        QCOMPARE(pairingFinished.first().at(1).value<PingService::Outcome>(),
                 PingService::Outcome::Mismatch);

        QTRY_COMPARE(finished.count(), 1);
        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(!m_trust->contains(m_sender.deviceId()));
    }

    // 接收方的用户始终没给答案：超时后拒绝，不留下任何记录。
    void receiverInputTimeoutRejectsPairing()
    {
        m_service->setInputWindow(std::chrono::milliseconds(50));

        PingClient client(*m_trust);
        QSignalSpy finished(&client, &PingClient::finished);
        QSignalSpy pairingFinished(m_service, &PingService::pairingFinished);

        client.start(serverUrl(), m_sender, QStringLiteral("发送方"));

        QTRY_COMPARE(pairingFinished.count(), 1);
        QCOMPARE(pairingFinished.first().at(1).value<PingService::Outcome>(),
                 PingService::Outcome::TimedOut);

        QTRY_COMPARE(finished.count(), 1);
        QVERIFY(!finished.first().at(0).value<PingClient::Result>().ok);
        QVERIFY(!m_trust->contains(m_sender.deviceId()));
    }

    // 一次只处理一条 ping：第二条在第一条还等输入时直接 409，不排队。
    void secondPairingIsRejectedWhileOneIsPending()
    {
        PingClient first(*m_trust);
        QSignalSpy inputRequired(m_service, &PingService::inputRequired);
        QSignalSpy firstFinished(&first, &PingClient::finished);

        first.start(serverUrl(), m_sender, QStringLiteral("发送方"));
        QTRY_COMPARE(inputRequired.count(), 1);

        PingClient second(*m_trust);
        QSignalSpy secondFinished(&second, &PingClient::finished);
        second.start(serverUrl(), m_sender, QStringLiteral("发送方"));

        QTRY_COMPARE(secondFinished.count(), 1);
        const auto result = secondFinished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("409")));

        m_service->submitInput(inputRequired.first().at(2).value<SasCode>().asked);
        QTRY_COMPARE(firstFinished.count(), 1);
        QVERIFY(firstFinished.first().at(0).value<PingClient::Result>().ok);
    }

    // 信任库里已有这个 deviceId 但指纹不同：拒绝，且不进入输入环节。
    void identityChangedIsRejectedWithoutAskingTheUser()
    {
        // deviceId 就是指纹的截断，所以「同一个 deviceId、不同指纹」只可能是记录被
        // 篡改或截断前缀相撞——正是这条检查要兜住的情形。
        QString error;
        QVERIFY(m_trust->add({m_sender.deviceId(), QString(64, QLatin1Char('a')),
                              QStringLiteral("冒名者"), QDateTime::currentDateTimeUtc()},
                             &error));

        PingClient client(*m_trust);
        QSignalSpy finished(&client, &PingClient::finished);
        QSignalSpy inputRequired(m_service, &PingService::inputRequired);
        QSignalSpy pairingFinished(m_service, &PingService::pairingFinished);

        client.start(serverUrl(), m_sender, QStringLiteral("发送方"));

        QTRY_COMPARE(pairingFinished.count(), 1);
        QCOMPARE(pairingFinished.first().at(1).value<PingService::Outcome>(),
                 PingService::Outcome::Rejected);
        QCOMPARE(inputRequired.count(), 0); // 没到输入那一步

        QTRY_COMPARE(finished.count(), 1);
        QVERIFY(!finished.first().at(0).value<PingClient::Result>().ok);
        // 记录没有被覆盖
        QCOMPARE(m_trust->find(m_sender.deviceId())->fingerprint, QString(64, QLatin1Char('a')));
    }

    void rejectsUnexpectedFingerprint()
    {
        const auto wrong = Fingerprint::fromHex(QString(64, QLatin1Char('a')));
        QVERIFY(wrong.has_value());

        PingClient client(*m_trust);
        QSignalSpy adopted(&client, &PingClient::peerAdopted);
        QSignalSpy finished(&client, &PingClient::finished);
        client.start(serverUrl(), m_sender, QStringLiteral("发送方"), *wrong);

        QTRY_COMPARE(finished.count(), 1);
        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("指纹")));
        // 没通过比对就不该算出码，也不该显示出去
        QVERIFY(result.code.shown.isEmpty());
        QCOMPARE(adopted.count(), 0);
    }

    // 响应里的 fp 与握手所见不符：对端要么有 bug，要么有人在改包。
    void rejectsResponseWithMismatchedFingerprint()
    {
        HttpServer liar;
        liar.setHandler([](HttpConnection &connection) {
            PingInfo info;
            info.name = QStringLiteral("冒名者");
            info.version = proto::kVersion;
            info.fingerprint = *Fingerprint::fromHex(QString(64, QLatin1Char('c')));
            info.reachable = true;
            connection.respond(Response::json(Status::Ok, toJson(info)));
        });
        auto port = liar.listen(m_identity, 0);
        if (!port.has_value())
            QFAIL(qPrintable(port.error()));

        PingClient client(*m_trust);
        QSignalSpy finished(&client, &PingClient::finished);
        client.start(QUrl(QStringLiteral("https://127.0.0.1:%1").arg(*port)), m_sender,
                     QStringLiteral("发送方"));

        QTRY_COMPARE(finished.count(), 1);
        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("指纹")));
    }

    // —————————————— 协议边界（裸连接） ——————————————

    void rejectsNonPostRequest()
    {
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send("GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void rejectsMalformedBody()
    {
        const QList<QByteArray> bad{
            QByteArray(),
            QByteArray("not json"),
            QByteArray(R"({"cnonce":"abcd","name":"x"})"),            // cnonce 太短
            QByteArray(R"({"cnonce":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","name":"x"})"), // 非十六进制
            QByteArray(R"({"cnonce":"0123456789abcdef0123456789abcdef"})"),            // 缺 name
        };

        for (const QByteArray &body : bad) {
            RawClient client(rawclient::withCertificate(m_sender), this);
            client.connectTo(m_port);
            client.send("POST /api/v1/ping HTTP/1.1\r\nHost: x\r\nContent-Length: "
                        + QByteArray::number(body.size()) + "\r\n\r\n" + body);

            QTRY_VERIFY(client.finished());
            QVERIFY2(client.statusCode() == 400,
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(QString::fromUtf8(body))));
        }
    }

    // 路径必须完全相等：cnonce 现在走请求体，路径上不该再挂任何东西。
    void pathMustMatchExactly()
    {
        QVERIFY(PingService::handles(QByteArrayView("/api/v1/ping")));
        QVERIFY(!PingService::handles(QByteArrayView("/api/v1/ping?cnonce=x")));
        QVERIFY(!PingService::handles(QByteArrayView("/api/v1/pingX")));
    }

    // 被屏蔽的设备连配对请求也拒：屏蔽的意义就是不再被它打扰，而它同样会弹框。
    void blockedPeerCannotPair()
    {
        QString error;
        QVERIFY(m_trust->block({m_sender.deviceId(), QStringLiteral("发送方"),
                                QDateTime::currentDateTimeUtc()},
                               &error));

        PingClient client(*m_trust);
        QSignalSpy finished(&client, &PingClient::finished);
        QSignalSpy inputRequired(m_service, &PingService::inputRequired);

        client.start(serverUrl(), m_sender, QStringLiteral("发送方"));

        QTRY_COMPARE(finished.count(), 1);
        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("403")));
        // 关键的一条：接收方连用户都没问。peerAdopted 会在握手时照常发出去
        // （发送方那半要先显示出来），所以它不能用来判断配对成没成。
        QCOMPARE(inputRequired.count(), 0);
    }

    void jsonRoundTripsAndRejectsJunk()
    {
        const PingRequest request{QString(32, QLatin1Char('a')), QStringLiteral("笔记本")};
        const auto decoded = pingRequestFromJson(QJsonDocument(toJson(request))
                                                     .toJson(QJsonDocument::Compact));
        QVERIFY(decoded.has_value());
        QCOMPARE(decoded->cnonce, request.cnonce);
        QCOMPARE(decoded->name, request.name);
        QVERIFY(!pingRequestFromJson(QByteArray("[]")).has_value());

        PingInfo info;
        info.name = QStringLiteral("接收方");
        info.version = proto::kVersion;
        info.fingerprint = m_identity.fingerprint();
        info.reachable = false;
        const auto roundTripped = pingInfoFromJson(QJsonDocument(toJson(info))
                                                       .toJson(QJsonDocument::Compact));
        QVERIFY(roundTripped.has_value());
        QCOMPARE(roundTripped->reachable, false);
        QCOMPARE(roundTripped->fingerprint.toHex(), info.fingerprint.toHex());

        // 缺字段一律拒绝。deviceId 不是响应里的字段，写进去也不会被认。
        QVERIFY(!pingInfoFromJson(QByteArray(R"({"name":"x","ver":1,"reachable":true})"))
                     .has_value());
        QVERIFY(!pingInfoFromJson(QByteArray(R"({"deviceId":"x"})")).has_value());
    }
};

QTEST_GUILESS_MAIN(TestPing)

#include "tst_ping.moc"
