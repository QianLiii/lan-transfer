// prepare / complete 的线格式（§5）。纯函数，不需要事件循环。
//
// 请求体是对端的声明，整份不可信：这一套用例守的是「声明里的每一个数字与名字都
// 被检查过」，尤其是 totalSize 与各文件大小之和的关系（§5.3）。

#include <QtTest>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "protocol.h"
#include "transfer/transfer.h"

using namespace lanpipe;
using namespace lanpipe::transfer;

namespace {

const QString kFileId = QString(proto::kFileIdBytes * 2, QLatin1Char('b'));
const QString kOtherFileId = QString(proto::kFileIdBytes * 2, QLatin1Char('c'));
const QString kSessionId = QString(proto::kSessionIdBytes * 2, QLatin1Char('d'));

QByteArray prepareBody(const QString &filesJson, const QString &totalSizeJson = QStringLiteral("3"))
{
    return QStringLiteral(R"({"sender":{"name":"发送方"},"files":[%1],"totalSize":%2})")
        .arg(filesJson, totalSizeJson)
        .toUtf8();
}

QString fileJson(const QString &id = kFileId, const QString &name = QStringLiteral("photo.jpg"),
                 const QString &size = QStringLiteral("3"))
{
    return QStringLiteral(R"({"id":"%1","name":"%2","size":%3})").arg(id, name, size);
}

} // namespace

class TestTransfer : public QObject
{
    Q_OBJECT

private:
    static TransferRequest parse(const QByteArray &body)
    {
        const auto result = transferRequestFromJson(body);
        if (!result.has_value()) {
            QTest::qFail(qPrintable(result.error()), __FILE__, __LINE__);
            return {};
        }
        return *result;
    }

private slots:
    void prepareRoundTrips()
    {
        TransferRequest original;
        original.senderName = QStringLiteral("笔记本");
        original.files = {TransferFile{kFileId, QStringLiteral("photo.jpg"), 100, QStringLiteral("image/jpeg")},
                          TransferFile{kOtherFileId, QStringLiteral("报告.pdf"), 200, QString()}};
        original.totalSize = 300;

        const auto decoded = transferRequestFromJson(
            QJsonDocument(toJson(original)).toJson(QJsonDocument::Compact));
        if (!decoded.has_value())
            QFAIL(qPrintable(decoded.error()));

        QCOMPARE(decoded->senderName, original.senderName);
        QCOMPARE(decoded->totalSize, original.totalSize);
        QCOMPARE(decoded->files.size(), 2);
        QCOMPARE(decoded->files.at(0).id, kFileId);
        QCOMPARE(decoded->files.at(0).name, QStringLiteral("photo.jpg"));
        QCOMPARE(decoded->files.at(0).size, quint64{100});
        QCOMPARE(decoded->files.at(0).mime, QStringLiteral("image/jpeg"));
        QCOMPARE(decoded->files.at(1).id, kOtherFileId);
        QCOMPARE(decoded->files.at(1).size, quint64{200});
    }

    // 零字节文件是合法的：size 为 0、总数也为 0。
    void acceptsZeroByteFiles()
    {
        const TransferRequest request =
            parse(prepareBody(fileJson(kFileId, QStringLiteral("empty.txt"), QStringLiteral("0")),
                              QStringLiteral("0")));
        QCOMPARE(request.files.size(), 1);
        QCOMPARE(request.files.first().size, quint64{0});
        QCOMPARE(request.totalSize, quint64{0});
    }

    void rejectsMissingFields()
    {
        const QList<QByteArray> bad{
            QByteArray(),
            QByteArray("not json"),
            QByteArray("[]"),
            QByteArray(R"({"files":[],"totalSize":0})"),                       // 缺 sender
            QByteArray(R"({"sender":{"name":"x"},"totalSize":0})"),            // 缺 files
            QByteArray(R"({"sender":{"name":"x"},"files":[]})"),               // 缺 totalSize
            QByteArray(R"({"sender":"x","files":[],"totalSize":0})"),          // sender 不是对象
            QByteArray(R"({"sender":{},"files":[],"totalSize":0})"),           // 缺 sender.name
            prepareBody(QString()),                                            // files 为空
            prepareBody(QStringLiteral("{}")),                                 // 元素不是对象
            prepareBody(fileJson(kFileId, QStringLiteral("a.txt"), QStringLiteral("1")),
                        QStringLiteral("1")),
        };
        // 最后一条是合法的，单独确认它没被误伤。
        QVERIFY(transferRequestFromJson(bad.last()).has_value());

        for (qsizetype i = 0; i < bad.size() - 1; ++i) {
            QVERIFY2(!transferRequestFromJson(bad.at(i)).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(QString::fromUtf8(bad.at(i)))));
        }
    }

    void rejectsBadFileIds()
    {
        const QList<QString> bad{
            QString(proto::kFileIdBytes * 2, QLatin1Char('z')), // 非十六进制
            QString(proto::kFileIdBytes * 2 - 1, QLatin1Char('a')), // 太短
            QString(proto::kFileIdBytes * 2 + 1, QLatin1Char('a')), // 太长
            QString(),
        };
        for (const QString &id : bad) {
            QVERIFY2(!transferRequestFromJson(
                          prepareBody(fileJson(id, QStringLiteral("a.txt"), QStringLiteral("1")),
                                      QStringLiteral("1")))
                          .has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(id)));
        }
    }

    void rejectsDuplicateFileIds()
    {
        const QByteArray body = prepareBody(fileJson(kFileId, QStringLiteral("a.txt"), QStringLiteral("1"))
                                                + QLatin1Char(',')
                                                + fileJson(kFileId, QStringLiteral("b.txt"),
                                                           QStringLiteral("2")),
                                            QStringLiteral("3"));
        QVERIFY(!transferRequestFromJson(body).has_value());
    }

    void rejectsBadNames()
    {
        const QByteArray emptyName =
            prepareBody(fileJson(kFileId, QString(), QStringLiteral("1")), QStringLiteral("1"));
        QVERIFY(!transferRequestFromJson(emptyName).has_value());

        const QString tooLong(static_cast<qsizetype>(proto::kMaxDisplayNameBytes) + 1,
                              QLatin1Char('n'));
        const QByteArray longName =
            prepareBody(fileJson(kFileId, tooLong, QStringLiteral("1")), QStringLiteral("1"));
        QVERIFY(!transferRequestFromJson(longName).has_value());
    }

    // JSON 的数字都是 double：非整数、负数、超出精确表示范围都要挡（§5.3）。
    void rejectsSizesThatAreNotExactNonNegativeIntegers()
    {
        const QList<QString> bad{
            QStringLiteral("-1"),
            QStringLiteral("1.5"),
            QStringLiteral("1e300"),
            QStringLiteral("9007199254740994"),   // 2^53 + 2
            QStringLiteral("\"3\""),              // 字符串
            QStringLiteral("true"),
        };
        for (const QString &size : bad) {
            QVERIFY2(!transferRequestFromJson(
                          prepareBody(fileJson(kFileId, QStringLiteral("a.txt"), size), size))
                          .has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(size)));
        }

        // 2^53 本身是精确可表示的，放行。
        QVERIFY(transferRequestFromJson(
                    prepareBody(fileJson(kFileId, QStringLiteral("a.txt"),
                                         QStringLiteral("9007199254740992")),
                                QStringLiteral("9007199254740992")))
                    .has_value());
    }

    // 最要紧的一条：总数必须等于各项之和，否则批准的 1 字节可以变成 100 GB（§5.3）。
    void rejectsTotalSizeThatDisagreesWithTheFiles()
    {
        const QByteArray smaller =
            prepareBody(fileJson(kFileId, QStringLiteral("a.txt"), QStringLiteral("100")),
                        QStringLiteral("1"));
        QVERIFY(!transferRequestFromJson(smaller).has_value());

        const QByteArray larger =
            prepareBody(fileJson(kFileId, QStringLiteral("a.txt"), QStringLiteral("1")),
                        QStringLiteral("100"));
        QVERIFY(!transferRequestFromJson(larger).has_value());
    }

    void rejectsTooManyFiles()
    {
        QStringList entries;
        quint64 total = 0;
        for (std::size_t i = 0; i <= proto::kMaxFilesPerSession; ++i) {
            const QString id = QStringLiteral("%1").arg(i, proto::kFileIdBytes * 2, 16, QLatin1Char('0'));
            entries.append(fileJson(id, QStringLiteral("a.txt"), QStringLiteral("1")));
            ++total;
        }
        const QByteArray body = prepareBody(entries.join(QLatin1Char(',')), QString::number(total));
        QVERIFY(!transferRequestFromJson(body).has_value());
    }

    void sessionIdRoundTrips()
    {
        const QByteArray body = QJsonDocument(prepareResponse(kSessionId)).toJson(QJsonDocument::Compact);
        const auto decoded = sessionIdFromJson(body);
        if (!decoded.has_value())
            QFAIL(qPrintable(decoded.error()));
        QCOMPARE(*decoded, kSessionId);

        QVERIFY(!sessionIdFromJson(QByteArray(R"({"sessionId":"short"})")).has_value());
        QVERIFY(!sessionIdFromJson(QByteArray(R"({"sessionId":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"})"))
                     .has_value());
        QVERIFY(!sessionIdFromJson(QByteArray("{}")).has_value());
    }

    void completeReportRoundTrips()
    {
        CompleteReport report;
        report.files = {{kFileId, 100}, {kOtherFileId, 0}};

        const auto decoded = completeReportFromJson(
            QJsonDocument(toJson(report)).toJson(QJsonDocument::Compact));
        if (!decoded.has_value())
            QFAIL(qPrintable(decoded.error()));

        QCOMPARE(decoded->files.size(), 2);
        QCOMPARE(decoded->bytesFor(kFileId), quint64{100});
        QCOMPARE(decoded->bytesFor(kOtherFileId), quint64{0});
        // 没报上来的文件按 0 算——发送方的比较据此判定「没收到」。
        QCOMPARE(decoded->bytesFor(QString(proto::kFileIdBytes * 2, QLatin1Char('e'))), quint64{0});

        QVERIFY(!completeReportFromJson(QByteArray("{}")).has_value());
        QVERIFY(!completeReportFromJson(QByteArray(R"({"files":[{"id":"x","bytes":1}]})")).has_value());
        QVERIFY(!completeReportFromJson(QByteArray(R"({"files":[{"id":"cccccccccccccccc","bytes":-1}]})"))
                     .has_value());
    }

    void errorBodyCarriesReasonAndRetryAfter()
    {
        const QJsonObject plain = errorBody(QStringLiteral("忙"));
        QCOMPARE(plain.value(QStringLiteral("reason")).toString(), QStringLiteral("忙"));
        QVERIFY(!plain.contains(QStringLiteral("retryAfter")));

        const QJsonObject withRetry = errorBody(QStringLiteral("忙"), 42);
        QCOMPARE(withRetry.value(QStringLiteral("retryAfter")).toInt(), 42);

        // 0 与负数都不写出去：没有可等的秒数时说「稍后重试」是空话。
        QVERIFY(!errorBody(QStringLiteral("忙"), 0).contains(QStringLiteral("retryAfter")));
    }

    // 对端可控的字节进终端之前必须剥掉控制字符：一段 ANSI 序列就能在运维者终端里
    // 伪造出整行输出（比如一行「已接收」）。
    void reasonFromStripsControlCharacters()
    {
        const QByteArray hostile("boom\x1b[2K\r已接收");
        const QString reason = reasonFrom(hostile);
        QVERIFY(!reason.contains(QChar(0x1B)));
        QVERIFY(!reason.contains(QLatin1Char('\r')));
        QVERIFY(reason.startsWith(QStringLiteral("boom")));

        // 走 JSON 的 reason 字段那条路同样要剥。
        const QByteArray json =
            QJsonDocument(errorBody(QStringLiteral("忙\x1b[31m"))).toJson(QJsonDocument::Compact);
        QVERIFY(!reasonFrom(json).contains(QChar(0x1B)));
    }

    void reasonFromFallsBackToRawText()
    {
        const QByteArray json = QJsonDocument(errorBody(QStringLiteral("对端忙"))).toJson(QJsonDocument::Compact);
        QCOMPARE(reasonFrom(json), QStringLiteral("对端忙"));

        // 对端不是按我们的格式回话时，原文比「未知错误」有用。
        QCOMPARE(reasonFrom(QByteArray("  raw text \n")), QStringLiteral("raw text"));
    }
};

QTEST_APPLESS_MAIN(TestTransfer)

#include "tst_transfer.moc"
