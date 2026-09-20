// 发送方（§5）。真 HttpServer + 真 ReceiveService 当对端，本地文件当来源。
//
// 这里守的是三条：没配对不发、prepare 之后文件变了不发、complete 的核对结果要
// 如实报出去（它是这次传输唯一的端到端校验）。

#include <QtTest>

#include <QBuffer>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>

#include "files/localsource.h"
#include "http/httpserver.h"
#include "identity.h"
#include "protocol.h"
#include "settings.h"
#include "transfer/receiveservice.h"
#include "transfer/sendclient.h"
#include "trust/truststore.h"

using namespace lanpipe;
using namespace lanpipe::files;
using namespace lanpipe::http;
using namespace lanpipe::transfer;

namespace {

// 大小会在中途变的来源：第一次问报 100 字节，之后报 50。用来钉住「prepare 之后
// 文件被换掉了」那条检查——真文件要做出这个效果得靠别的进程同时改它。
class ShrinkingSource : public FileSource
{
public:
    [[nodiscard]] std::unique_ptr<QIODevice> open() override
    {
        auto buffer = std::make_unique<QBuffer>();
        buffer->setData(QByteArray(50, 's'));
        buffer->open(QIODevice::ReadOnly);
        return buffer;
    }

    [[nodiscard]] std::optional<quint64> size() const override
    {
        return m_asked++ == 0 ? std::optional<quint64>{100} : std::optional<quint64>{50};
    }

    [[nodiscard]] QString displayName() const override { return QStringLiteral("shrinking.bin"); }

private:
    mutable int m_asked = 0;
};

// 大小定不下来的来源（Android 的部分 provider 是常态，§5.14）。
class SizelessSource : public FileSource
{
public:
    [[nodiscard]] std::unique_ptr<QIODevice> open() override { return nullptr; }
    [[nodiscard]] std::optional<quint64> size() const override { return std::nullopt; }
    [[nodiscard]] QString displayName() const override { return QStringLiteral("cloud.bin"); }
};

} // namespace

class TestSendClient : public QObject
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

    QUrl url() const { return QUrl(QStringLiteral("https://127.0.0.1:%1").arg(m_port)); }

    QString receiveDir() const { return m_receiveDir.path(); }

    // 写一个内容已知的源文件，返回它的路径。
    QString writeSource(const QString &name, const QByteArray &content)
    {
        const QString path = m_dir.filePath(name);
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly))
            QTest::qFail("无法写测试文件", __FILE__, __LINE__);
        file.write(content);
        file.close();
        return path;
    }

    std::shared_ptr<files::FileSource> localSource(const QString &name, const QByteArray &content)
    {
        return std::make_shared<LocalFileSource>(writeSource(name, content));
    }

    void pairReceiver()
    {
        QString error;
        QVERIFY(m_trust->add({m_receiver.deviceId(), m_receiver.fingerprint().toHex(),
                              QStringLiteral("接收方"), QDateTime::currentDateTimeUtc()},
                             &error));
    }

    // 有返回值的辅助函数里不能用 QVERIFY/QCOMPARE——它们展开成 `return;`。
    SendClient::Result runSend(const QList<std::shared_ptr<files::FileSource>> &sources,
                               std::optional<Fingerprint> expected = std::nullopt)
    {
        SendClient client(*m_trust);
        QSignalSpy finished(&client, &SendClient::finished);
        client.start(url(), m_sender, QStringLiteral("发送方"), sources, expected);

        if (!QTest::qWaitFor([&] { return finished.count() == 1; }, 15000)) {
            QTest::qFail("发送没有结束", __FILE__, __LINE__);
            return {};
        }
        return finished.first().at(0).value<SendClient::Result>();
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid());
        QVERIFY(m_receiveDir.isValid());
        qRegisterMetaType<SendClient::Result>();
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
        const QDir dir(receiveDir());
        for (const QFileInfo &entry : dir.entryInfoList(QDir::AllEntries | QDir::Hidden
                                                        | QDir::NoDotAndDotDot)) {
            removeTreeSafely(entry.absoluteFilePath());
        }

        m_settings = new Settings(m_dir.filePath(QStringLiteral("settings.ini")));
        m_settings->setDeviceName(QStringLiteral("接收方"));
        m_settings->setOpenMode(true); // 测试里不弹框：审批本身在 tst_receiveservice 里测

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

    void sendsOneFileAndTheReceiverLandsIt()
    {
        pairReceiver();
        const QByteArray content(64 * 1024, 'a');

        const SendClient::Result result = runSend({localSource(QStringLiteral("payload.bin"), content)});
        QVERIFY2(result.ok, qPrintable(result.error));
        QCOMPARE(result.totalBytes, static_cast<quint64>(content.size()));

        QFile landed(QDir(receiveDir()).filePath(QStringLiteral("payload.bin")));
        QVERIFY(landed.open(QIODevice::ReadOnly));
        QCOMPARE(landed.readAll(), content);
        QVERIFY(!m_service->hasActiveSession()); // 会话在 complete 之后收尾
    }

    void sendsSeveralFilesInOneSession()
    {
        pairReceiver();
        QSignalSpy prepared(m_service, &ReceiveService::fileCommitted);

        const SendClient::Result result =
            runSend({localSource(QStringLiteral("a.txt"), QByteArray("aaa")),
                     localSource(QStringLiteral("b.txt"), QByteArray("bbbb"))});
        QVERIFY2(result.ok, qPrintable(result.error));
        QCOMPARE(prepared.count(), 2);

        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("a.txt"))));
        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("b.txt"))));
    }

    // 没配对的设备不发：传输没有比对码兜底，凭据只有信任库。
    void refusesToSendToAnUnpairedPeer()
    {
        const SendClient::Result result =
            runSend({localSource(QStringLiteral("payload.bin"), QByteArray("x"))});
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("尚未配对")));
        QVERIFY(!m_service->hasActiveSession()); // 一个请求都没发出去
    }

    // --pin 直接给了指纹时不再要求配对过：那比信任库里的记录更强。
    void explicitPinIsEnoughWithoutPairing()
    {
        const auto expected = m_receiver.fingerprint();
        const SendClient::Result result =
            runSend({localSource(QStringLiteral("pinned.bin"), QByteArray("pinned"))}, expected);
        QVERIFY2(result.ok, qPrintable(result.error));
        QVERIFY(QFile::exists(QDir(receiveDir()).filePath(QStringLiteral("pinned.bin"))));
    }

    void refusesAPeerWhoseFingerprintIsNotThePinned()
    {
        const auto wrong = Fingerprint::fromHex(QString(64, QLatin1Char('e')));
        QVERIFY(wrong.has_value());

        const SendClient::Result result =
            runSend({localSource(QStringLiteral("payload.bin"), QByteArray("x"))}, *wrong);
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("指纹")));
    }

    // §5.14：大小定不下来就在 prepare 之前拒绝，一个请求都不发。
    void refusesASourceWithoutAKnownSize()
    {
        pairReceiver();
        const SendClient::Result result = runSend({std::make_shared<SizelessSource>()});
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("无法确定")));
        QVERIFY(!m_service->hasActiveSession());
    }

    // prepare 之后文件变了：不发 PUT，直接中止会话（§5.3）。
    void refusesAFileThatChangedAfterPrepare()
    {
        pairReceiver();
        const SendClient::Result result = runSend({std::make_shared<ShrinkingSource>()});
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("变了")));
        // 会话已经开着：要通知对方收尾，别让它等到 TTL。
        QTRY_VERIFY(!m_service->hasActiveSession());
    }

    // 接收方拒绝（策略或用户）：错误原样带回来。
    void surfacesTheReceiverRejection()
    {
        m_settings->setOpenMode(false); // 回到「一律提示」，而测试里没人回答 → 超时
        m_service->setApprovalWindow(std::chrono::milliseconds(100));
        pairReceiver();

        const SendClient::Result result =
            runSend({localSource(QStringLiteral("payload.bin"), QByteArray("x"))});
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QStringLiteral("504")));
    }

    void cancelEndsTheSessionOnBothSides()
    {
        pairReceiver();
        // 大到足以在中途取消。
        const auto source = localSource(QStringLiteral("big.bin"), QByteArray(8 * 1024 * 1024, 'z'));

        SendClient client(*m_trust);
        QSignalSpy progress(&client, &SendClient::fileProgress);
        QSignalSpy finished(&client, &SendClient::finished);
        client.start(url(), m_sender, QStringLiteral("发送方"), {source});

        QVERIFY(QTest::qWaitFor([&] { return progress.count() > 0; }, 10000));
        client.cancel();
        QVERIFY(QTest::qWaitFor([&] { return finished.count() == 1; }, 10000));

        const auto result = finished.first().at(0).value<SendClient::Result>();
        QVERIFY(result.cancelled);
        // 接收方那边的会话也该收了，临时数据一并删掉。
        QTRY_VERIFY(!m_service->hasActiveSession());
        QVERIFY(!QDir(QDir(receiveDir()).filePath(QString::fromLatin1(proto::kTempDirName))).exists());
    }
};

QTEST_GUILESS_MAIN(TestSendClient)

#include "tst_sendclient.moc"
