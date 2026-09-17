// 连接层与 mTLS（§4、§5.13、§5.15）。
//
// 这里测的是「服务端对一条 TLS 连接做什么裁定」：没有证书的连接一律拒绝、
// 解析器的负向用例全部以 400 断连、请求体超过批准值就中途切断、
// 不说话的连接被空闲超时关掉、并发连接不越过上限。
//
// 客户端一律用裸 TLS 连接（rawclient.h）：解析器的负向用例要发的正是
// 合法客户端永远不会发的字节。

#include <QtTest>

#include <QDir>
#include <QTemporaryDir>

#include "http/httpserver.h"
#include "identity.h"
#include "mtls.h"
#include "protocol.h"
#include "rawclient.h"

using namespace lanpipe;
using namespace lanpipe::http;

class TestHttpTransport : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    Identity m_identity;
    HttpServer m_server;
    quint16 m_port = 0;
    quint64 m_bodyCap = 1024;
    QByteArray m_received;

    void installHandler()
    {
        m_server.setHandler([this](HttpConnection &connection) {
            const QByteArray target = connection.head().target;

            if (target == "/ok") {
                connection.respond(Response::text(Status::Ok, QStringLiteral("ok")));
                return;
            }
            if (target == "/silent") {
                return; // 故意不回答：用于空闲超时与并发上限
            }
            if (target == "/whoami") {
                connection.respond(Response::text(Status::Ok, connection.peer().deviceId));
                return;
            }
            if (target.startsWith("/body")) {
                QObject::connect(&connection, &HttpConnection::bodyComplete, &connection,
                                 [&connection] {
                                     connection.respond(Response::text(Status::Ok,
                                                                       QStringLiteral("done")));
                                 });
                connection.readBody(m_bodyCap, [this](QByteArrayView chunk) {
                    m_received.append(chunk);
                    return true;
                });
                return;
            }
            connection.respond(Response::text(Status::NotFound, QStringLiteral("未知目标")));
        });
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid());
        auto identity = Identity::loadOrCreate(m_dir.filePath(QStringLiteral("receiver")));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));
        m_identity = *identity;

        installHandler();
        auto port = m_server.listen(m_identity, 0);
        if (!port.has_value())
            QFAIL(qPrintable(port.error()));
        m_port = *port;
    }

    // —————————————— mTLS ——————————————

    void acceptsClientWithCertificate()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 200);
        QVERIFY(client.response().contains("Connection: close\r\n"));
    }

    // 没有客户端证书的连接必须在握手期就被拒，且一个响应字节都不发。
    void rejectsClientWithoutCertificate()
    {
        RawClient client(rawclient::withoutCertificate(), this);
        client.connectTo(m_port);
        client.send("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QVERIFY(!client.response().startsWith("HTTP/1.1"));
        // 被拒的连接不会进入连接表
        QTRY_COMPARE(m_server.connectionCount(), qsizetype{0});
    }

    // 服务端从对端证书重算的身份，得到的就是对端自己声称的那个值。
    // 这是 §4 信任模型的地基：deviceId 由公钥导出，因此可以自己证明自己。
    void peerIdentityMatchesTheCertificateOwner()
    {
        QTemporaryDir peerDir;
        QVERIFY(peerDir.isValid());
        auto peer = Identity::loadOrCreate(peerDir.filePath(QStringLiteral("peer")));
        if (!peer.has_value())
            QFAIL(qPrintable(peer.error()));

        const auto recomputed = net::peerIdentity(peer->certificate());
        if (!recomputed.has_value())
            QFAIL(qPrintable(recomputed.error()));

        QCOMPARE(recomputed->deviceId, peer->deviceId());
        QCOMPARE(recomputed->fingerprint.toHex(), peer->fingerprint().toHex());
        QVERIFY(recomputed->isValid());
        QVERIFY(recomputed->deviceId != m_identity.deviceId());
    }

    // 身份判定只发生在连接层，处理器读到的就是那次判定的结果——这条断言的用意是
    // 让「处理器自己解析证书」或「漏掉判定」这两种写法都不再有存在的理由。
    void handlerSeesThePeerIdentityResolvedAtTheConnectionLayer()
    {
        QTemporaryDir peerDir;
        QVERIFY(peerDir.isValid());
        auto peer = Identity::loadOrCreate(peerDir.filePath(QStringLiteral("peer")));
        if (!peer.has_value())
            QFAIL(qPrintable(peer.error()));

        RawClient client(rawclient::withCertificate(*peer), this);
        client.connectTo(m_port);
        client.send("GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 200);
        QCOMPARE(client.body(), peer->deviceId().toUtf8());
    }

    // —————————————— 解析器：负向用例全部 400 并断连 ——————————————

    void rejectsChunkedRequest()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("PUT /ok HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                    "5\r\nhello\r\n0\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
        // 请求体一个字节都没被当成请求处理：响应里只有一条状态行。
        QCOMPARE(client.response().count("HTTP/1.1 "), qsizetype{1});
    }

    void rejectsDuplicateContentLength()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("PUT /body HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void rejectsOverflowingContentLength()
    {
        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("PUT /body HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    void rejectsOversizedHeaderBlock()
    {
        QByteArray request = "GET /ok HTTP/1.1\r\n";
        while (request.size() <= static_cast<qsizetype>(proto::kMaxHeaderBlockSize))
            request += "X-Fill: 0123456789012345678901234567890123456789\r\n";

        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send(request);

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 400);
    }

    // —————————————— 请求体上限 ——————————————

    void acceptsBodyWithinCap()
    {
        m_bodyCap = 16;
        m_received.clear();

        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        client.send("PUT /body HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 200);
        QCOMPARE(m_received, QByteArray("hello"));
    }

    // 声明的长度超过批准值：409 并中途断连，一个字节都不读（§5.3）。
    void cutsOffOversizedBodyMidStream()
    {
        m_bodyCap = 16;
        m_received.clear();

        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(m_port);
        // 客户端还在发，服务端在这一批字节之后就会切断连接。
        client.send("PUT /body HTTP/1.1\r\nContent-Length: 100000\r\n\r\n");
        client.send(QByteArray(4096, 'a'));

        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 409);
        QVERIFY(m_received.isEmpty());
    }

    // —————————————— 超时与上限 ——————————————

    void idleTimeoutClosesStalledConnection()
    {
        // 这条用例要一条很短的超时，所以单独起一个服务端：超时值在连接建立时
        // 就固定下来，改共享的那个会影响其它用例。
        HttpServer server;
        server.setIdleTimeout(std::chrono::milliseconds(300));
        server.setHandler([](HttpConnection &connection) {
            if (connection.head().target != "/silent")
                connection.respond(Response::text(Status::Ok, QStringLiteral("ok")));
        });

        auto port = server.listen(m_identity, 0);
        if (!port.has_value())
            QFAIL(qPrintable(port.error()));

        RawClient client(rawclient::withCertificate(m_identity), this);
        client.connectTo(*port);
        // 头收完了，但请求体一个字节都不发。
        client.send("PUT /silent HTTP/1.1\r\nContent-Length: 100\r\n\r\n");

        QTRY_VERIFY(client.finished());
        QVERIFY(client.response().isEmpty());
    }

    void capsConcurrentConnections()
    {
        // 先让上一条用例的连接全部退场，否则计数起点不确定。
        QTRY_COMPARE(m_server.connectionCount(), qsizetype{0});

        QObject scope;
        QList<RawClient *> silent;
        for (std::size_t i = 0; i < proto::kMaxConnections; ++i) {
            auto *client = new RawClient(rawclient::withCertificate(m_identity), &scope);
            client->connectTo(m_port);
            client->send("PUT /silent HTTP/1.1\r\nContent-Length: 100\r\n\r\n");
            silent.append(client);
        }
        QTRY_COMPARE(m_server.connectionCount(), static_cast<qsizetype>(proto::kMaxConnections));

        // 第 N+1 条连握手都不做，直接拒绝。
        RawClient extra(rawclient::withCertificate(m_identity), this);
        extra.connectTo(m_port);
        extra.send("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");

        QTRY_VERIFY(extra.finished());
        QVERIFY(extra.response().isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestHttpTransport)

#include "tst_httptransport.moc"
