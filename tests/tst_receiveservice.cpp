// 接收方的四个传输端点（§5）。真 HttpServer、真接收目录，负向用例走裸连接。
//
// 这里守的是四条最容易写错的东西：批准的大小就是硬上限、每个文件在自己的 PUT
// 返回 200 时就位、会话同时在且只在一个、取消之后不留临时数据。

#include <QtTest>

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>

#include "http/httpserver.h"
#include "identity.h"
#include "protocol.h"
#include "rawclient.h"
#include "settings.h"
#include "transfer/receiveservice.h"
#include "trust/truststore.h"

using namespace lanpipe;
using namespace lanpipe::http;
using namespace lanpipe::transfer;

namespace {

const QString kFileId = QString(proto::kFileIdBytes * 2, QLatin1Char('b'));
const QString kOtherFileId = QString(proto::kFileIdBytes * 2, QLatin1Char('c'));
const QString kUnknownSession = QString(proto::kSessionIdBytes * 2, QLatin1Char('9'));

QByteArray json(const QJsonObject &object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QByteArray fileEntry(const QString &id, const QString &name, quint64 size)
{
    QJsonObject entry;
    entry.insert(QStringLiteral("id"), id);
    entry.insert(QStringLiteral("name"), name);
    entry.insert(QStringLiteral("size"), static_cast<double>(size));
    return json(entry);
}

QByteArray prepareBody(const QList<QByteArray> &files, quint64 totalSize)
{
    QJsonArray array;
    for (const QByteArray &file : files)
        array.append(QJsonDocument::fromJson(file).object());

    QJsonObject sender;
    sender.insert(QStringLiteral("name"), QStringLiteral("发送方"));

    QJsonObject root;
    root.insert(QStringLiteral("sender"), sender);
    root.insert(QStringLiteral("files"), array);
    root.insert(QStringLiteral("totalSize"), static_cast<double>(totalSize));
    return json(root);
}

QByteArray target(std::string_view prefix, const QString &sessionId)
{
    return QByteArray(prefix.data(), prefix.size()) + sessionId.toLatin1();
}

QByteArray uploadTarget(const QString &sessionId, const QString &fileId)
{
    return QByteArray(proto::kPathUploadPrefix.data(), proto::kPathUploadPrefix.size())
        + sessionId.toLatin1() + '/' + fileId.toLatin1();
}

QByteArray postRequest(const QByteArray &target, const QByteArray &body = {})
{
    QByteArray request = "POST " + target + " HTTP/1.1\r\nHost: x\r\n";
    if (!body.isEmpty()) {
        request += "Content-Type: application/json\r\nContent-Length: "
            + QByteArray::number(body.size()) + "\r\n";
    }
    return request + "\r\n" + body;
}

QByteArray putRequest(const QByteArray &target, const QByteArray &body,
                      const QByteArray &extra = {})
{
    return "PUT " + target + " HTTP/1.1\r\nHost: x\r\n" + extra + "Content-Length: "
        + QByteArray::number(body.size()) + "\r\n\r\n" + body;
}

// 服务端先发 100 Continue 再发真响应时，RawClient 的 body() 会把两段一起端出来。
int lastStatus(const QByteArray &response)
{
    const qsizetype marker = response.lastIndexOf("HTTP/1.1 ");
    return marker < 0 ? 0 : response.mid(marker + 9, 3).toInt();
}

} // namespace

class TestReceiveService : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    QTemporaryDir m_receiveDir;
    Identity m_receiver;
    Identity m_sender;
    Settings *m_settings = nullptr;
    trust::TrustStore *m_trust = nullptr;
    ReceiveService *m_service = nullptr;
    HttpServer m_server;
    quint16 m_port = 0;

    QString receiveDir() const { return m_receiveDir.path(); }

    QString tempRoot() const
    {
        return QDir(receiveDir()).filePath(QString::fromLatin1(proto::kTempDirName));
    }

    QString tempDirFor(const QString &sessionId) const
    {
        return QDir(tempRoot()).filePath(sessionId);
    }

    // 有返回值的辅助函数里不能用 QVERIFY/QCOMPARE——它们展开成 `return;`。
    // 这里用 qWaitFor（返回 bool）+ qFail（不返回），失败路径自己收尾。
    //
    // 15 秒而不是 QtTest 默认的 5 秒：每个用例都要走一次真的 TLS 往返，而 CI 的
    // macOS 机器是共享的、慢得多。
    static bool waitFor(std::function<bool()> predicate)
    {
        return QTest::qWaitFor(std::move(predicate), 15000);
    }

    static void fail(const QString &why)
    {
        QTest::qFail(qPrintable(why), __FILE__, __LINE__);
    }

    // 一次请求走一次往返：连接由服务端结束，所以 finished 就是同步点。
    int exchange(const QByteArray &request, QByteArray *body = nullptr)
    {
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(request);
        if (!waitFor([&] { return client.finished(); }))
            fail(QStringLiteral("连接没有被服务端结束"));
        if (body)
            *body = client.body();
        return client.statusCode();
    }

    // prepare 挂起等审批，所以它不能走 exchange：要先把答案喂回去。
    QString acceptSession(const QList<QByteArray> &files, quint64 totalSize)
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(), prepareBody(files, totalSize)));

        if (!waitFor([&] { return approval.count() == 1; })) {
            fail(QStringLiteral("没有收到审批请求"));
            return {};
        }
        m_service->submitApproval(true);
        if (!waitFor([&] { return client.finished(); })) {
            fail(QStringLiteral("审批之后连接没有结束"));
            return {};
        }
        if (client.statusCode() != 200) {
            fail(QStringLiteral("prepare 返回了 %1").arg(client.statusCode()));
            return {};
        }

        const auto sessionId = sessionIdFromJson(client.body());
        if (!sessionId.has_value()) {
            fail(sessionId.error());
            return {};
        }
        return *sessionId;
    }

    QString acceptSingleFile(quint64 size, const QString &name = QStringLiteral("photo.jpg"))
    {
        return acceptSession({fileEntry(kFileId, name, size)}, size);
    }

    void pairSender(const QString &fingerprint)
    {
        QString error;
        QVERIFY(m_trust->add({m_sender.deviceId(), fingerprint, QStringLiteral("发送方"),
                              QDateTime::currentDateTimeUtc()},
                             &error));
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid());
        QVERIFY(m_receiveDir.isValid());
        qRegisterMetaType<TransferRequest>();

        auto receiver = Identity::loadOrCreate(m_dir.filePath(QStringLiteral("receiver")));
        if (!receiver.has_value())
            QFAIL(qPrintable(receiver.error()));
        m_receiver = *receiver;

        auto sender = Identity::loadOrCreate(m_dir.filePath(QStringLiteral("sender")));
        if (!sender.has_value())
            QFAIL(qPrintable(sender.error()));
        m_sender = *sender;
    }

    void init()
    {
        delete m_service;
        m_service = nullptr;
        delete m_trust;
        m_trust = nullptr;
        delete m_settings;
        m_settings = nullptr;

        QFile::remove(m_dir.filePath(QStringLiteral("trust.json")));
        QFile::remove(m_dir.filePath(QStringLiteral("settings.ini")));

        // 每个用例都从干净的接收目录开始：上一个用例落下的同名文件会让冲突改名的
        // 断言读出别的用例写的内容。
        const QDir dir(receiveDir());
        const QFileInfoList leftovers =
            dir.entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
        for (const QFileInfo &entry : leftovers)
            removeTreeSafely(entry.absoluteFilePath());

        m_settings = new Settings(m_dir.filePath(QStringLiteral("settings.ini")));
        m_settings->setDeviceName(QStringLiteral("接收方"));

        auto trust = trust::TrustStore::load(m_dir.filePath(QStringLiteral("trust.json")));
        if (!trust.has_value())
            QFAIL(qPrintable(trust.error()));
        m_trust = new trust::TrustStore(*trust);

        m_service = new ReceiveService(*m_settings, *m_trust, receiveDir(), this);

        m_server.setHandler([this](HttpConnection &connection) {
            if (ReceiveService::handles(connection.head().target)) {
                m_service->handle(connection);
                return;
            }
            connection.respond(Response::text(Status::BadRequest, QStringLiteral("未知目标")));
        });
        if (m_port == 0) {
            const auto port = m_server.listen(m_receiver, 0);
            if (!port.has_value())
                QFAIL(qPrintable(port.error()));
            m_port = *port;
        }
    }

    // —————————————— 正向 ——————————————

    void transferRoundTripLandsTheFile()
    {
        const QByteArray payload("hello");
        const QString sessionId = acceptSingleFile(payload.size());
        QVERIFY(!sessionId.isEmpty());

        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), payload), &body), 200);

        // 文件在自己的 PUT 返回 200 时就位（§5.2），不需要等 complete。
        QFile landed(QDir(receiveDir()).filePath(QStringLiteral("photo.jpg")));
        QVERIFY(landed.open(QIODevice::ReadOnly));
        QCOMPARE(landed.readAll(), payload);

        QCOMPARE(exchange(postRequest(target(proto::kPathCompletePrefix, sessionId)), &body), 200);
        const auto report = completeReportFromJson(body);
        if (!report.has_value())
            QFAIL(qPrintable(report.error()));
        QCOMPARE(report->bytesFor(kFileId), quint64{5});

        // complete 是终点：会话与临时数据都收了。
        QVERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());
    }

    void emptyFileCommitsZeroBytes()
    {
        const QString sessionId = acceptSingleFile(0, QStringLiteral("empty.txt"));
        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), {}), &body), 200);

        QFile landed(QDir(receiveDir()).filePath(QStringLiteral("empty.txt")));
        QVERIFY(landed.exists());
        QCOMPARE(landed.size(), qint64{0});
    }

    void multipleFilesLandUnderTheirOwnNames()
    {
        const QString sessionId =
            acceptSession({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3),
                           fileEntry(kOtherFileId, QStringLiteral("报告.txt"), 6)},
                          9);

        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), QByteArray("abc")), &body),
                 200);
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kOtherFileId), QByteArray("报告")),
                          &body),
                 200);

        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("photo.jpg"))));
        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("报告.txt"))));
    }

    // 同名冲突不改写已有的那一份（§5.11）。
    void existingFileIsNeverOverwritten()
    {
        const QString existing = QDir(receiveDir()).filePath(QStringLiteral("photo.jpg"));
        QFile first(existing);
        QVERIFY(first.open(QIODevice::WriteOnly));
        first.write("old");
        first.close();

        const QString sessionId = acceptSingleFile(3);
        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), QByteArray("new")), &body),
                 200);

        QVERIFY(first.open(QIODevice::ReadOnly));
        QCOMPARE(first.readAll(), QByteArray("old"));
        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("photo (1).jpg"))));
    }

    // §5.15：声明了 Expect: 100-continue 就要先答应再读体。
    void expectContinueIsAnsweredBeforeTheBody()
    {
        const QString sessionId = acceptSingleFile(5);

        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send("PUT " + uploadTarget(sessionId, kFileId)
                    + " HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n");
        QTRY_VERIFY(client.response().contains("100 Continue"));
        QCOMPARE(lastStatus(client.response()), 100);

        client.send(QByteArray("hello"));
        QTRY_VERIFY(client.finished());
        QCOMPARE(lastStatus(client.response()), 200);
    }

    // 重传从零开始：第一次只发了一半就断，第二次发完整的，落地的必须是后者。
    void retriedUploadDoesNotAppendToTheOldFragment()
    {
        const QString sessionId = acceptSingleFile(10);
        const QByteArray path = uploadTarget(sessionId, kFileId);

        {
            RawClient half(rawclient::withCertificate(m_sender), this);
            half.connectTo(m_port);
            half.send("PUT " + path + " HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n");
            half.send(QByteArray("half"));
            QTest::qWait(200); // 让服务端真的收下这几个字节
            half.abort();
        }

        QByteArray body;
        QCOMPARE(exchange(putRequest(path, QByteArray("0123456789")), &body), 200);

        QFile landed(QDir(receiveDir()).filePath(QStringLiteral("photo.jpg")));
        QVERIFY(landed.open(QIODevice::ReadOnly));
        QCOMPARE(landed.readAll(), QByteArray("0123456789"));
    }

    // —————————————— 审批与策略 ——————————————

    void rejectingTheApprovalIs403AndLeavesNothing()
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(),
                                prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_COMPARE(approval.count(), 1);

        m_service->submitApproval(false);
        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 403);
        QVERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(tempRoot()).exists()); // 没接受就没留下任何目录
    }

    void approvalTimeoutIs504()
    {
        m_service->setApprovalWindow(std::chrono::milliseconds(50));

        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(),
                                prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 504);
        QVERIFY(!m_service->hasActiveSession());
    }

    void autoAcceptPairedSkipsThePrompt()
    {
        pairSender(m_sender.fingerprint().toHex());
        m_settings->setReceivePolicy(ReceivePolicy::AutoAcceptPaired);

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 200);
        QCOMPARE(approval.count(), 0);
        QVERIFY(m_service->hasActiveSession());
    }

    // 默认策略一律提示，哪怕已经配对过（§4）。
    void defaultPolicyStillPromptsForAPairedPeer()
    {
        pairSender(m_sender.fingerprint().toHex());

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(),
                                prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_COMPARE(approval.count(), 1);
        m_service->submitApproval(false);
        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 403);
    }

    // 已配对却换过密钥：拒绝，且优先于开放模式。
    void identityChangedIsRejectedEvenInOpenMode()
    {
        m_settings->setOpenMode(true);
        pairSender(QString(64, QLatin1Char('f'))); // 记录里的指纹与它现在出示的不符

        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 403);
        QVERIFY(body.contains("身份已变"));
        QVERIFY(!m_service->hasActiveSession());
    }

    void freeSpaceIsCheckedBeforeAskingTheUser()
    {
        m_service->setFreeSpaceProbe([](const QString &) { return quint64{16}; });

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 1024)}, 1024)),
                          &body),
                 507);
        QCOMPARE(approval.count(), 0); // 用户不该为一个注定失败的传输点「接受」
    }

    // 问不出可用空间时不拒收：那是提示，不是安全门（§5.4）。
    void unknownFreeSpaceDoesNotBlock()
    {
        m_service->setFreeSpaceProbe([](const QString &) { return quint64{0}; });

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(),
                                prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_COMPARE(approval.count(), 1);
        m_service->submitApproval(true);
        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 200);
    }

    // 净化在弹框之前：连名字都过不去的请求不该打扰用户。
    void namesThatCannotBeSanitizedAreRejectedBeforeThePrompt()
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral(".."), 3)}, 3)),
                          &body),
                 400);
        QCOMPARE(approval.count(), 0);
    }

    // 两条连接同时 PUT 不同文件：第二条要被挡掉。上传状态是单份的（一个 sink、
    // 一个设备、一个连接指针），放进来就会互相踩——字节写进错误的临时文件。
    void concurrentUploadsAreRefused()
    {
        const QString sessionId =
            acceptSession({fileEntry(kFileId, QStringLiteral("a.bin"), 8),
                           fileEntry(kOtherFileId, QStringLiteral("b.bin"), 8)},
                          16);
        QSignalSpy progress(m_service, &ReceiveService::fileProgress);

        // 第一条：发头 + 一半的体，挂着不收尾。
        RawClient first(rawclient::withCertificate(m_sender), this);
        first.connectTo(m_port);
        first.send("PUT " + uploadTarget(sessionId, kFileId)
                   + " HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n");
        first.send(QByteArray("1234"));
        QVERIFY(waitFor([&] { return progress.count() > 0; }));

        // 第二条：另一个文件，必须被挡。
        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kOtherFileId), QByteArray("abcdefgh")),
                          &body),
                 409);
        QVERIFY(body.contains("正在传输"));

        // 第一条照常收尾，文件 2 之后仍然能传。
        first.send(QByteArray("5678"));
        QVERIFY(waitFor([&] { return first.finished(); }));
        QCOMPARE(first.statusCode(), 200);

        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kOtherFileId), QByteArray("abcdefgh")),
                          &body),
                 200);
        QFile a(QDir(receiveDir()).filePath(QStringLiteral("a.bin")));
        QVERIFY(a.open(QIODevice::ReadOnly));
        QCOMPARE(a.readAll(), QByteArray("12345678"));
    }

    // —————————————— 黑名单与限流（§4）——————————————

    // 被屏蔽的设备连框都不弹——否则局域网里任何一台设备都能无限打扰用户。
    void blockedSenderIsRejectedWithoutPrompting()
    {
        QString error;
        QVERIFY(m_trust->block({m_sender.deviceId(), QStringLiteral("发送方"),
                                QDateTime::currentDateTimeUtc()},
                               &error));

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 403);
        QVERIFY(body.contains("屏蔽"));
        QCOMPARE(approval.count(), 0);
        QVERIFY(!m_service->hasActiveSession());
    }

    // 另一个进程写的黑名单也要生效：`lanpipe block` 与 `serve` 不是一个进程，
    // 而用户期望「屏蔽之后它再来就被拒」。接收方在每次 prepare 前重读信任库。
    void blockWrittenByAnotherProcessTakesEffect()
    {
        auto other = trust::TrustStore::load(m_dir.filePath(QStringLiteral("trust.json")));
        if (!other.has_value())
            QFAIL(qPrintable(other.error()));
        QString error;
        QVERIFY(other->block({m_sender.deviceId(), QStringLiteral("外面屏蔽的"),
                              QDateTime::currentDateTimeUtc()},
                             &error));

        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 403);
        QVERIFY(body.contains("屏蔽"));
        QCOMPARE(approval.count(), 0);
    }

    // 同一条设备反复来，超过限流额度就不再问用户。
    void promptingTooOftenIsRejectedWithoutAskingAgain()
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        const QByteArray body =
            prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3);

        for (int i = 0; i < proto::kMaxPromptsPerWindow; ++i) {
            RawClient client(rawclient::withCertificate(m_sender), this);
            client.connectTo(m_port);
            client.send(postRequest(proto::kPathPrepare.data(), body));
            QTRY_COMPARE(approval.count(), i + 1);
            m_service->submitApproval(false);
            QTRY_VERIFY(client.finished());
            QCOMPARE(client.statusCode(), 403);
        }

        QByteArray rejected;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(), body), &rejected), 403);
        QVERIFY(rejected.contains("频繁"));
        QCOMPARE(approval.count(), proto::kMaxPromptsPerWindow); // 没有再弹
    }

    // 审批框上的「拒绝并屏蔽」要把决定留在盘上，之后连框都不弹。
    void blockingFromThePromptPersists()
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        QSignalSpy blocked(m_service, &ReceiveService::peerBlocked);

        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send(postRequest(proto::kPathPrepare.data(),
                                prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_COMPARE(approval.count(), 1);

        m_service->submitBlock();
        QTRY_VERIFY(client.finished());
        QCOMPARE(client.statusCode(), 403);
        QCOMPARE(blocked.count(), 1);
        QVERIFY(m_trust->isBlocked(m_sender.deviceId()));

        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 403);
        QCOMPARE(approval.count(), 1); // 第二次没再打扰用户
    }

    void secondPrepareIs409WithRetryAfter()
    {
        QVERIFY(!acceptSingleFile(3).isEmpty());

        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 409);
        QVERIFY(body.contains("retryAfter"));
    }

    void secondPrepareWhileAwaitingApprovalIs409()
    {
        QSignalSpy approval(m_service, &ReceiveService::approvalRequired);
        RawClient first(rawclient::withCertificate(m_sender), this);
        first.connectTo(m_port);
        first.send(postRequest(proto::kPathPrepare.data(),
                               prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)));
        QTRY_COMPARE(approval.count(), 1);

        QByteArray body;
        QCOMPARE(exchange(postRequest(proto::kPathPrepare.data(),
                                      prepareBody({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3)}, 3)),
                          &body),
                 409);

        m_service->submitApproval(false);
        QTRY_VERIFY(first.finished());
    }

    // —————————————— 协议边界 ——————————————

    void rejectsWrongMethods()
    {
        QByteArray body;
        QCOMPARE(exchange("GET " + QByteArray(proto::kPathPrepare.data())
                              + " HTTP/1.1\r\nHost: x\r\n\r\n",
                          &body),
                 400);
        const QString sessionId = acceptSingleFile(3);
        QCOMPARE(exchange(postRequest(uploadTarget(sessionId, kFileId)), &body), 400);
    }

    void rejectsMalformedPaths()
    {
        const QList<QByteArray> bad{
            QByteArray(proto::kPathUploadPrefix.data()) + "zzzz/aaaa",  // 非十六进制
            QByteArray(proto::kPathUploadPrefix.data()) + "short/aaaa", // 长度不对
            QByteArray(proto::kPathUploadPrefix.data()) + kUnknownSession.toLatin1(), // 少一段
            QByteArray(proto::kPathUploadPrefix.data()) + kUnknownSession.toLatin1() + '/'
                + kFileId.toLatin1() + "/extra", // 多一段
            QByteArray(proto::kPathCompletePrefix.data()) + "nothex",
            QByteArray(proto::kPathAbortPrefix.data()) + kUnknownSession.toLatin1() + "/extra",
        };
        for (const QByteArray &path : bad) {
            QByteArray body;
            QVERIFY2(exchange(putRequest(path, {}), &body) == 400,
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(QString::fromUtf8(path))));
        }
    }

    void unknownSessionIsGone()
    {
        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(kUnknownSession, kFileId), QByteArray()), &body),
                 410);
    }

    void undeclaredFileIs409()
    {
        const QString sessionId = acceptSingleFile(3);
        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kOtherFileId), QByteArray("abc")),
                          &body),
                 409);
    }

    // §5.3：声明的长度必须正好等于批准的大小，两个方向都要挡。
    void contentLengthMustMatchTheApprovedSize()
    {
        const QString sessionId = acceptSingleFile(3);
        const QByteArray path = uploadTarget(sessionId, kFileId);

        QByteArray body;
        QCOMPARE(exchange(putRequest(path, QByteArray("abcd")), &body), 409); // 多一个字节
        QCOMPARE(exchange(putRequest(path, QByteArray("ab")), &body), 409);   // 少一个字节
        // 没有 Content-Length 的请求按 0 算，非空文件自然被拒。
        QCOMPARE(exchange("PUT " + path + " HTTP/1.1\r\nHost: x\r\n\r\n" + QByteArray("abc"), &body),
                 409);
        // 声明对了才收。
        QCOMPARE(exchange(putRequest(path, QByteArray("abc")), &body), 200);
    }

    void completeReportsZeroForFilesThatNeverArrived()
    {
        const QString sessionId =
            acceptSession({fileEntry(kFileId, QStringLiteral("photo.jpg"), 3),
                           fileEntry(kOtherFileId, QStringLiteral("报告.txt"), 6)},
                          9);

        QByteArray body;
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), QByteArray("abc")), &body),
                 200);
        QCOMPARE(exchange(postRequest(target(proto::kPathCompletePrefix, sessionId)), &body), 200);

        const auto report = completeReportFromJson(body);
        if (!report.has_value())
            QFAIL(qPrintable(report.error()));
        QCOMPARE(report->files.size(), 2); // 每个声明过的文件都出现
        QCOMPARE(report->bytesFor(kFileId), quint64{3});
        QCOMPARE(report->bytesFor(kOtherFileId), quint64{0});

        // 会话已结束，后续 PUT 拿到 410。
        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kOtherFileId), QByteArray("报告")),
                          &body),
                 410);
    }

    // —————————————— 取消与超时 ——————————————

    void abortDeletesTempDataAndEndsTheSession()
    {
        const QString sessionId = acceptSingleFile(3);
        QVERIFY(QDir(tempDirFor(sessionId)).exists());

        QByteArray body;
        QCOMPARE(exchange(postRequest(target(proto::kPathAbortPrefix, sessionId)), &body), 200);
        QVERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());

        QCOMPARE(exchange(putRequest(uploadTarget(sessionId, kFileId), QByteArray("abc")), &body),
                 410);
    }

    // 取消是幂等的：别人已经清过了，不该报错。
    void abortOnUnknownSessionIs200()
    {
        QByteArray body;
        QCOMPARE(exchange(postRequest(target(proto::kPathAbortPrefix, kUnknownSession)), &body),
                 200);
    }

    // 接收方取消：在途的 PUT 连接被直接关掉，不发响应（§5.5）。
    void cancellingClosesTheUploadWithoutAResponse()
    {
        const QString sessionId = acceptSingleFile(64 * 1024, QStringLiteral("big.bin"));
        QSignalSpy progress(m_service, &ReceiveService::fileProgress);

        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send("PUT " + uploadTarget(sessionId, kFileId)
                    + " HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n");
        client.send(QByteArray(4096, 'x'));
        QTRY_VERIFY(progress.count() > 0); // 已经在收字节了

        m_service->cancelActive();
        QTRY_VERIFY(client.finished());
        QVERIFY(client.response().isEmpty());
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());
    }

    // 对端在传输中途消失之后，那条连接会被 deleteLater()。此时任何拆除路径都不能
    // 再去碰它——曾经这里是一个 use-after-free，症状是「对端断连五分钟之后接收方
    // 自己崩掉」（TTL 到点拆除时踩了那条已经销毁的连接）。
    void teardownAfterTheUploadConnectionDiedIsSafe()
    {
        m_service->setSessionTtl(std::chrono::milliseconds(500));
        const QString sessionId = acceptSingleFile(64 * 1024, QStringLiteral("died.bin"));
        QSignalSpy progress(m_service, &ReceiveService::fileProgress);

        {
            RawClient client(rawclient::withCertificate(m_sender), this);
            client.connectTo(m_port);
            client.send("PUT " + uploadTarget(sessionId, kFileId)
                        + " HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n");
            client.send(QByteArray(4096, 'x'));
            // 等到真的在收字节再断：不然可能断在 PUT 到达之前，测的就不是这条路了
            // （那条连接根本没建起来，也就没有悬垂的指针）。
            QVERIFY(waitFor([&] { return progress.count() > 0; }));
            client.abort(); // 硬断
        }

        QTRY_VERIFY(!m_service->hasActiveSession()); // TTL 到点 → 拆除 → 不能崩
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());
    }

    void cancelAfterTheUploadConnectionDiedIsSafe()
    {
        const QString sessionId = acceptSingleFile(64 * 1024, QStringLiteral("died.bin"));
        QSignalSpy progress(m_service, &ReceiveService::fileProgress);

        {
            RawClient client(rawclient::withCertificate(m_sender), this);
            client.connectTo(m_port);
            client.send("PUT " + uploadTarget(sessionId, kFileId)
                        + " HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n");
            client.send(QByteArray(4096, 'x'));
            QVERIFY(waitFor([&] { return progress.count() > 0; }));
            client.abort();
        }

        QTest::qWait(100); // 让那条连接的 finished/deleteLater 走完
        m_service->cancelActive();
        QTRY_VERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());
    }

    // TTL 到点就把临时数据删掉。
    //
    // 窗口留得比「够快就行」宽：从会话建好到这条断言之间还要走一次事件循环，慢的 CI
    // 机器上几十毫秒就过去了——TTL 设成 50ms 时，那台机器上会在断言之前先把目录删掉。
    void sessionTtlExpiryDeletesTempData()
    {
        m_service->setSessionTtl(std::chrono::milliseconds(400));
        const QString sessionId = acceptSingleFile(3);
        QVERIFY(QDir(tempDirFor(sessionId)).exists());

        QTRY_VERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(tempDirFor(sessionId)).exists());
    }

    // PUT 在途时 TTL 挂起：否则一个几分钟的大文件会被从中间打断，
    // 而它删的正是正在写的那个临时文件。
    //
    // 先等到真的收到字节（证明 PUT 已经在途、TTL 已被挂起），再睡过 TTL——直接睡一个
    // 固定的短时间，在慢机器上会把「PUT 还没到」误判成「TTL 没挂起」。
    void uploadInFlightSuspendsTheSessionTtl()
    {
        m_service->setSessionTtl(std::chrono::milliseconds(500));
        const QString sessionId = acceptSingleFile(4, QStringLiteral("slow.bin"));
        QSignalSpy progress(m_service, &ReceiveService::fileProgress);

        RawClient client(rawclient::withCertificate(m_sender), this);
        client.connectTo(m_port);
        client.send("PUT " + uploadTarget(sessionId, kFileId)
                    + " HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n");
        client.send(QByteArray("ab"));

        QVERIFY(waitFor([&] { return progress.count() > 0; })); // 在途了
        QTest::qWait(1200);                                     // 远超 TTL，但传输还在进行

        client.send(QByteArray("cd"));
        QVERIFY(waitFor([&] { return client.finished(); }));
        QCOMPARE(client.statusCode(), 200);
        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("slow.bin"))));
    }

    // 清扫只删超过保留期的孤儿（§5.7）。把「现在」推后 25 小时，同一条目就从
    // 「刚建的」变成「孤儿」——这样不必去改文件时间。
    void sweepRemovesOnlyEntriesOlderThanRetention()
    {
        const QString entry = QDir(tempRoot()).filePath(kUnknownSession);
        QVERIFY(QDir().mkpath(entry));

        QCOMPARE(m_service->sweepStaleTempData(QDateTime::currentDateTimeUtc()), 0);
        QVERIFY(QDir(entry).exists());

        QCOMPARE(m_service->sweepStaleTempData(
                     QDateTime::currentDateTimeUtc().addSecs(25 * 3600)),
                 1);
        QVERIFY(!QDir(entry).exists());
    }

    // 删树不跟随符号链接：那是全仓唯一一处按目录名删东西的代码。
    void removingATreeDoesNotFollowSymlinks()
    {
        const QString outside = QDir(receiveDir()).filePath(QStringLiteral("别删我"));
        QVERIFY(QDir().mkpath(outside));
        QFile marker(QDir(outside).filePath(QStringLiteral("keep.txt")));
        QVERIFY(marker.open(QIODevice::WriteOnly));
        marker.write("keep");
        marker.close();

        const QString tree = QDir(tempRoot()).filePath(kUnknownSession);
        QVERIFY(QDir().mkpath(tree));
        if (!QFile::link(outside, QDir(tree).filePath(QStringLiteral("link"))))
            QSKIP("这个平台不支持符号链接，跳过");

        removeTreeSafely(tree);
        QVERIFY(!QDir(tree).exists());  // 树本身删掉了
        QVERIFY(QDir(outside).exists()); // 链接指向的东西一个字节没动
        QVERIFY(QFile::exists(QDir(outside).filePath(QStringLiteral("keep.txt"))));
    }

    // —————————————— 路由 ——————————————

    void handlesOnlyItsOwnPaths()
    {
        QVERIFY(ReceiveService::handles(
            QByteArrayView(proto::kPathPrepare.data(), proto::kPathPrepare.size())));
        QVERIFY(ReceiveService::handles(uploadTarget(kUnknownSession, kFileId)));
        QVERIFY(!ReceiveService::handles(
            QByteArrayView(proto::kPathPing.data(), proto::kPathPing.size())));
        QVERIFY(!ReceiveService::handles("/api/v1/upload"));
        QVERIFY(!ReceiveService::handles("/api/v1/prepare/extra"));
        QVERIFY(!ReceiveService::handles("/"));
    }
};

QTEST_GUILESS_MAIN(TestReceiveService)

#include "tst_receiveservice.moc"
