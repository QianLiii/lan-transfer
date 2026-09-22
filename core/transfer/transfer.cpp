#include "transfer.h"

#include "trust/sanitizer.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QSet>

#include <cmath>
#include <limits>

namespace lanpipe::transfer {

namespace {

// JSON 的数字都是 double，超过 2^53 就不再是精确整数。整数性、非负、上界三件事
// 必须一起挡：少挡一条，声明的体积就能绕过后面每一道与它有关的检查（§5.3）。
constexpr double kMaxExactInteger = 9007199254740992.0; // 2^53

std::expected<quint64, QString> nonNegativeInteger(const QJsonObject &object, const char *key)
{
    const QString name = QLatin1String(key);
    const QJsonValue value = object.value(name);
    if (!value.isDouble())
        return std::unexpected(QStringLiteral("字段 %1 缺失或不是数字").arg(name));

    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 0 || number > kMaxExactInteger)
        return std::unexpected(QStringLiteral("字段 %1 超出可表示范围").arg(name));
    if (std::floor(number) != number)
        return std::unexpected(QStringLiteral("字段 %1 不是整数").arg(name));

    return static_cast<quint64>(number);
}

// 定长十六进制字段。长度不符或含非十六进制字符都算失败。
std::expected<QString, QString> hexField(const QJsonObject &object, const char *key, int characters)
{
    const QString name = QLatin1String(key);
    const QJsonValue value = object.value(name);
    if (!value.isString())
        return std::unexpected(QStringLiteral("字段 %1 缺失或不是字符串").arg(name));

    const QString text = value.toString();
    if (text.size() != characters)
        return std::unexpected(QStringLiteral("字段 %1 长度应为 %2").arg(name).arg(characters));

    for (const QChar c : text) {
        if (!((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f') || (c >= u'A' && c <= u'F')))
            return std::unexpected(QStringLiteral("字段 %1 含非十六进制字符").arg(name));
    }
    return text;
}

// 有上限的字符串字段。上限按 UTF-8 字节算——它最终要落到文件系统上。
std::expected<QString, QString> stringField(const QJsonObject &object, const char *key,
                                            std::size_t maxBytes, bool allowEmpty)
{
    const QString name = QLatin1String(key);
    const QJsonValue value = object.value(name);
    if (!value.isString())
        return std::unexpected(QStringLiteral("字段 %1 缺失或不是字符串").arg(name));

    const QString text = value.toString();
    if (text.isEmpty() && !allowEmpty)
        return std::unexpected(QStringLiteral("字段 %1 为空").arg(name));
    if (text.toUtf8().size() > static_cast<qsizetype>(maxBytes))
        return std::unexpected(QStringLiteral("字段 %1 超过 %2 字节").arg(name).arg(maxBytes));
    return text;
}

std::expected<QJsonObject, QString> parseObject(const QByteArray &body, const QString &what)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (document.isNull())
        return std::unexpected(QStringLiteral("%1不是合法 JSON：%2").arg(what, parseError.errorString()));
    if (!document.isObject())
        return std::unexpected(QStringLiteral("%1不是 JSON 对象").arg(what));
    return document.object();
}

} // namespace

QJsonObject toJson(const TransferRequest &request)
{
    QJsonArray files;
    for (const TransferFile &file : request.files) {
        QJsonObject entry;
        entry.insert(QStringLiteral("id"), file.id);
        entry.insert(QStringLiteral("name"), file.name);
        entry.insert(QStringLiteral("size"), static_cast<double>(file.size));
        if (!file.mime.isEmpty())
            entry.insert(QStringLiteral("mime"), file.mime);
        files.append(entry);
    }

    QJsonObject sender;
    sender.insert(QStringLiteral("name"), request.senderName);

    QJsonObject object;
    object.insert(QStringLiteral("sender"), sender);
    object.insert(QStringLiteral("files"), files);
    object.insert(QStringLiteral("totalSize"), static_cast<double>(request.totalSize));
    return object;
}

std::expected<TransferRequest, QString> transferRequestFromJson(const QByteArray &body)
{
    const auto parsed = parseObject(body, QStringLiteral("prepare 请求体"));
    if (!parsed.has_value())
        return std::unexpected(parsed.error());
    const QJsonObject object = *parsed;

    const QJsonValue senderValue = object.value(QStringLiteral("sender"));
    if (!senderValue.isObject())
        return std::unexpected(QStringLiteral("字段 sender 缺失或不是对象"));
    const auto senderName =
        stringField(senderValue.toObject(), "name", proto::kMaxDisplayNameBytes, true);
    if (!senderName.has_value())
        return std::unexpected(senderName.error());

    const QJsonValue filesValue = object.value(QStringLiteral("files"));
    if (!filesValue.isArray())
        return std::unexpected(QStringLiteral("字段 files 缺失或不是数组"));

    const QJsonArray array = filesValue.toArray();
    if (array.isEmpty())
        return std::unexpected(QStringLiteral("files 为空"));
    if (static_cast<std::size_t>(array.size()) > proto::kMaxFilesPerSession)
        return std::unexpected(
            QStringLiteral("文件数超过上限 %1").arg(proto::kMaxFilesPerSession));

    TransferRequest request;
    request.senderName = *senderName;

    QSet<QString> seenIds;
    quint64 sum = 0;
    for (const QJsonValue &value : array) {
        if (!value.isObject())
            return std::unexpected(QStringLiteral("files 的元素不是对象"));
        const QJsonObject entry = value.toObject();

        TransferFile file;

        const auto id = hexField(entry, "id", proto::kFileIdBytes * 2);
        if (!id.has_value())
            return std::unexpected(id.error());
        // 统一成小写：下面按 id 建的档、以及 PUT 路径里的 id 都用小写形态，
        // 不归一化的话一个声明了大写 fileId 的对端永远传不上那个文件。
        file.id = id->toLower();
        if (seenIds.contains(file.id))
            return std::unexpected(QStringLiteral("fileId %1 重复").arg(file.id));
        seenIds.insert(file.id);

        const auto name = stringField(entry, "name", proto::kMaxDisplayNameBytes, false);
        if (!name.has_value())
            return std::unexpected(name.error());
        file.name = *name;

        const auto size = nonNegativeInteger(entry, "size");
        if (!size.has_value())
            return std::unexpected(size.error());
        file.size = *size;

        const QJsonValue mime = entry.value(QStringLiteral("mime"));
        if (!mime.isUndefined()) {
            if (!mime.isString())
                return std::unexpected(QStringLiteral("字段 mime 不是字符串"));
            if (mime.toString().toUtf8().size() > static_cast<qsizetype>(proto::kMaxDisplayNameBytes))
                return std::unexpected(QStringLiteral("字段 mime 过长"));
            file.mime = mime.toString();
        }

        // 单条已经 ≤ 2^53，条数上限相乘也到不了 quint64 的上限；显式写出来是为了
        // 将来放宽任一条时不会静默回绕。
        if (sum > std::numeric_limits<quint64>::max() - file.size)
            return std::unexpected(QStringLiteral("各文件大小之和溢出"));
        sum += file.size;

        request.files.append(file);
    }

    const auto totalSize = nonNegativeInteger(object, "totalSize");
    if (!totalSize.has_value())
        return std::unexpected(totalSize.error());

    // 总数必须等于各项之和。少了这一条，用户可以批准 1 字节而实际传 100 GB,
    // 审批界面就成了装饰（§5.3）。有了它，逐文件的 Content-Length 核对就足以
    // 封住会话总量，不需要再维护一个累计计数器。
    if (*totalSize != sum) {
        return std::unexpected(QStringLiteral("totalSize（%1）与各文件大小之和（%2）不符")
                                   .arg(*totalSize)
                                   .arg(sum));
    }
    request.totalSize = *totalSize;

    return request;
}

QJsonObject prepareResponse(const QString &sessionId)
{
    QJsonObject object;
    object.insert(QStringLiteral("sessionId"), sessionId);
    return object;
}

std::expected<QString, QString> sessionIdFromJson(const QByteArray &body)
{
    const auto parsed = parseObject(body, QStringLiteral("prepare 应答"));
    if (!parsed.has_value())
        return std::unexpected(parsed.error());

    return hexField(*parsed, "sessionId", proto::kSessionIdBytes * 2);
}

quint64 CompleteReport::bytesFor(const QString &id) const
{
    for (const Entry &entry : files) {
        if (entry.id == id)
            return entry.bytes;
    }
    return 0;
}

QJsonObject toJson(const CompleteReport &report)
{
    QJsonArray files;
    for (const CompleteReport::Entry &entry : report.files) {
        QJsonObject item;
        item.insert(QStringLiteral("id"), entry.id);
        item.insert(QStringLiteral("bytes"), static_cast<double>(entry.bytes));
        files.append(item);
    }

    QJsonObject object;
    object.insert(QStringLiteral("files"), files);
    return object;
}

std::expected<CompleteReport, QString> completeReportFromJson(const QByteArray &body)
{
    const auto parsed = parseObject(body, QStringLiteral("complete 应答"));
    if (!parsed.has_value())
        return std::unexpected(parsed.error());

    const QJsonValue filesValue = parsed->value(QStringLiteral("files"));
    if (!filesValue.isArray())
        return std::unexpected(QStringLiteral("字段 files 缺失或不是数组"));

    CompleteReport report;
    for (const QJsonValue &value : filesValue.toArray()) {
        if (!value.isObject())
            return std::unexpected(QStringLiteral("files 的元素不是对象"));
        const QJsonObject item = value.toObject();

        CompleteReport::Entry entry;
        const auto id = hexField(item, "id", proto::kFileIdBytes * 2);
        if (!id.has_value())
            return std::unexpected(id.error());
        entry.id = *id;

        const auto bytes = nonNegativeInteger(item, "bytes");
        if (!bytes.has_value())
            return std::unexpected(bytes.error());
        entry.bytes = *bytes;

        report.files.append(entry);
    }
    return report;
}

QJsonObject errorBody(const QString &reason, int retryAfterSeconds)
{
    QJsonObject object;
    object.insert(QStringLiteral("reason"), reason);
    if (retryAfterSeconds > 0)
        object.insert(QStringLiteral("retryAfter"), retryAfterSeconds);
    return object;
}

QString reasonFrom(const QByteArray &body)
{
    QString text;
    const QJsonDocument document = QJsonDocument::fromJson(body);
    if (document.isObject()) {
        const QJsonValue reason = document.object().value(QStringLiteral("reason"));
        if (reason.isString())
            text = reason.toString();
    }
    // 对端没按我们的格式回话（另一个实现，或中途被改过）时用原文，总比回一句
    // 「未知错误」有用。
    if (text.isEmpty())
        text = QString::fromUtf8(body).trimmed();

    // 两条路都要过 displaySafe：这段字节完全由对端控制，而它最终会打到用户的终端上
    // ——一个 ANSI 序列就能伪造出一行「已接收」。
    return trust::displaySafe(text);
}

} // namespace lanpipe::transfer
