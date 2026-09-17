// /ping 与 SAS（§4 配对）。M1 的验收在这里：两端的码必须相等，指纹必须对得上。
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
#include "random.h"
#include "rawclient.h"
#include "settings.h"
#include "transfer/ping.h"
#include "transfer/pingclient.h"

using namespace lanpipe;
using namespace lanpipe::http;
using namespace lanpipe::transfer;

namespace {

QByteArray bodyOf(const QByteArray &response)
{
    const qsizetype separator = response.indexOf("\r\n\r\n");
    return separator < 0 ? QByteArray() : response.mid(separator + 4);
}

} // namespace

class TestPing : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    QTemporaryDir m_settingsDir;
    Identity m_identity;
    Settings m_settings;
    SasCache m_sasCache;
    HttpServer m_server;
    PingService *m_service = nullptr;
    quint16 m_port = 0;

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid() && m_settingsDir.isValid());

        auto identity = Identity::loadOrCreate(m_dir.filePath(QStringLiteral("receiver")));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));
        m_identity = *identity;

        m_settings.setDeviceName(QStringLiteral("接收方"));

        m_service = new PingService(m_identity, m_settings, m_sasCache, &m_server);
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
        // 每条用例都从空缓存开始，否则「码是否被写进缓存」这类断言会互相干扰。
        m_sasCache.clear();
    }

    [[nodiscard]] QUrl serverUrl() const
    {
        return QUrl(QStringLiteral("https://127.0.0.1:%1").arg(m_port));
    }

    // —————————————— 端到端：两端的码必须相等 ——————————————

    void bothEndsAgreeOnTheCode()
    {
        QTemporaryDir senderDir;
        QVERIFY(senderDir.isValid());
        auto sender = Identity::loadOrCreate(senderDir.filePath(QStringLiteral("sender")));
        if (!sender.has_value())
            QFAIL(qPrintable(sender.error()));

        QSignalSpy settled(m_service, &PingService::codeSettled);
        PingClient client;
        QSignalSpy finished(&client, &PingClient::finished);

        client.start(serverUrl(), *sender);
        QTRY_COMPARE(finished.count(), 1);

        const auto result = finished.first().at(0).value<PingClient::Result>();
        if (!result.ok)
            QFAIL(qPrintable(result.error));

        // 发送方看到的：接收方的身份与握手所用的指纹
        QCOMPARE(result.info.deviceId, m_identity.deviceId());
        QCOMPARE(result.info.name, QStringLiteral("接收方"));
        QCOMPARE(result.info.version, proto::kVersion);
        QCOMPARE(result.info.fingerprint.toHex(), m_identity.fingerprint().toHex());
        QCOMPARE(result.peerFingerprint.toHex(), m_identity.fingerprint().toHex());
        QCOMPARE(result.info.snonce.size(), proto::kNonceBytes * 2);
        QVERIFY(result.info.reachable);

        // 接收方看到的：发送方的 deviceId 与它自己算出的两半
        QCOMPARE(settled.count(), 1);
        QCOMPARE(settled.first().at(0).toString(), sender->deviceId());
        const SasCode receiverCode = settled.first().at(1).value<SasCode>();

        // 这就是配对时两端各自要做的事：发送方显示的那半，正是接收方要求输入的
        // 那半，反之亦然（§4 配对）。
        QCOMPARE(receiverCode.asked, result.code.shown);
        QCOMPARE(receiverCode.shown, result.code.asked);
        QVERIFY(result.code.matches(receiverCode.shown));
        QVERIFY(receiverCode.matches(result.code.shown));
        QCOMPARE(result.code.shown.size(), 6);

        // 码已经落缓存：prepare 走另一条连接，到时从这里读（§4 规则 3）。
        const auto cached = m_sasCache.lookup(sender->deviceId());
        QVERIFY(cached.has_value());
        QCOMPARE(cached->code.shown, receiverCode.shown);
        QCOMPARE(cached->code.asked, receiverCode.asked);
        QCOMPARE(cached->peerFingerprint.toHex(), sender->fingerprint().toHex());
    }

    void rejectsUnexpectedFingerprint()
    {
        QTemporaryDir senderDir;
        QVERIFY(senderDir.isValid());
        auto sender = Identity::loadOrCreate(senderDir.filePath(QStringLiteral("sender")));
        if (!sender.has_value())
            QFAIL(qPrintable(sender.error()));

        const auto wrong = Fingerprint::fromHex(QString(64, QLatin1Char('a')));
        QVERIFY(wrong.has_value());

        PingClient client;
        QSignalSpy finished(&client, &PingClient::finished);
        client.start(serverUrl(), *sender, *wrong);
        QTRY_COMPARE(finished.count(), 1);

        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("指纹")));
        // 没通过比对就不该算出码
        QVERIFY(result.code.shown.isEmpty());
        QVERIFY(result.code.asked.isEmpty());
    }

    // 响应里的 fp 与握手所见不符：对端要么有 bug，要么有人在改包。
    void rejectsResponseWithMismatchedFingerprint()
    {
        HttpServer liar;
        liar.setHandler([](HttpConnection &connection) {
            PingInfo info;
            info.deviceId = QString(32, QLatin1Char('b'));
            info.name = QStringLiteral("冒名者");
            info.version = proto::kVersion;
            info.fingerprint = *Fingerprint::fromHex(QString(64, QLatin1Char('c')));
            info.snonce = randomHex(proto::kNonceBytes);
            info.reachable = true;
            connection.respond(Response::json(Status::Ok, toJson(info)));
        });

        auto port = liar.listen(m_identity, 0);
        if (!port.has_value())
            QFAIL(qPrintable(port.error()));

        QTemporaryDir senderDir;
        auto sender = Identity::loadOrCreate(senderDir.filePath(QStringLiteral("sender")));
        if (!sender.has_value())
            QFAIL(qPrintable(sender.error()));

        PingClient client;
        QSignalSpy finished(&client, &PingClient::finished);
        client.start(QUrl(QStringLiteral("https://127.0.0.1:%1").arg(*port)), *sender);
        QTRY_COMPARE(finished.count(), 1);

        const auto result = finished.first().at(0).value<PingClient::Result>();
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("指纹")));
    }

    // —————————————— 服务端的拒绝路径 ——————————————

    void rejectsNonGetMethod()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("POST " + pingTarget() + " HTTP/1.1\r\nContent-Length: 0\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void rejectsMissingCnonce()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("GET " + QByteArray(proto::kPathPing.data(), proto::kPathPing.size())
                    + " HTTP/1.1\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void rejectsNonHexCnonce()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("GET " + QByteArray(proto::kPathPing.data(), proto::kPathPing.size())
                    + "?cnonce=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz HTTP/1.1\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void answersWithTheFullPingPayload()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("GET " + pingTarget() + " HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 200);

        const auto info = pingInfoFromJson(bodyOf(client.response()));
        if (!info.has_value())
            QFAIL(qPrintable(info.error()));
        QCOMPARE(info->deviceId, m_identity.deviceId());
        QCOMPARE(info->fingerprint.toHex(), m_identity.fingerprint().toHex());
        QCOMPARE(info->snonce.size(), proto::kNonceBytes * 2);
        QCOMPARE(info->version, proto::kVersion);
    }

    // —————————————— 纯函数 ——————————————

    void cnonceIsRequiredAndStrict()
    {
        const QByteArray path(proto::kPathPing.data(), proto::kPathPing.size());
        const QByteArray good = QByteArray(proto::kNonceBytes * 2, 'a');

        QCOMPARE(cnonceFromTarget(QByteArrayView(path + "?cnonce=" + good)).value(),
                 QString::fromLatin1(good));

        const QList<QByteArray> rejected{
            path,                                       // 没有查询串
            path + "?cnonce=",                          // 空值
            path + "?cnonce=" + good + "a",             // 太长
            path + "?cnonce=" + good.left(31),          // 太短
            path + "?cnonce=" + QByteArray(32, 'z'),    // 非十六进制
            path + "?cnonce=" + good + "&x=1",          // 多余参数
            path + "/extra?cnonce=" + good,             // 路径不对
            QByteArray(proto::kPathPing.data(), proto::kPathPing.size()) + "?cnonce=%41%42",
        };
        for (const QByteArray &target : rejected) {
            QVERIFY2(!cnonceFromTarget(QByteArrayView(target)).has_value(),
                     qPrintable(QStringLiteral("竟然接受了 %1").arg(QString::fromLatin1(target))));
        }
    }

    void pingInfoRejectsMalformedJson()
    {
        const QByteArray valid = QJsonDocument(toJson(validInfo())).toJson(QJsonDocument::Compact);
        QVERIFY(pingInfoFromJson(valid).has_value());

        QVERIFY(!pingInfoFromJson(QByteArray()).has_value());
        QVERIFY(!pingInfoFromJson(QByteArray("[1,2,3]")).has_value());

        // 每个字段缺失一次
        const QJsonObject base = toJson(validInfo());
        for (const auto &key : {"deviceId", "name", "ver", "fp", "snonce", "reachable"}) {
            QJsonObject copy = base;
            copy.remove(QLatin1String(key));
            QVERIFY2(!pingInfoFromJson(QJsonDocument(copy).toJson(QJsonDocument::Compact)).has_value(),
                     key);
        }

        // 长度不对的十六进制字段
        QJsonObject short_ = base;
        short_.insert(QStringLiteral("snonce"), QStringLiteral("abcd"));
        QVERIFY(!pingInfoFromJson(QJsonDocument(short_).toJson(QJsonDocument::Compact)).has_value());

        QJsonObject nonHex = base;
        nonHex.insert(QStringLiteral("deviceId"), QString(32, QLatin1Char('z')));
        QVERIFY(!pingInfoFromJson(QJsonDocument(nonHex).toJson(QJsonDocument::Compact)).has_value());
    }

private:
    [[nodiscard]] static PingInfo validInfo()
    {
        PingInfo info;
        info.deviceId = QString(32, QLatin1Char('a'));
        info.name = QStringLiteral("某设备");
        info.version = proto::kVersion;
        info.fingerprint = *Fingerprint::fromHex(QString(64, QLatin1Char('b')));
        info.snonce = QString(32, QLatin1Char('c'));
        info.reachable = true;
        return info;
    }

    [[nodiscard]] QByteArray pingTarget() const
    {
        return QByteArray(proto::kPathPing.data(), proto::kPathPing.size()) + "?cnonce="
            + randomHex(proto::kNonceBytes).toLatin1();
    }
};

QTEST_GUILESS_MAIN(TestPing)

#include "tst_ping.moc"
