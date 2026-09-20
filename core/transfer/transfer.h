#pragma once

// prepare 与 complete 的线格式（§5）。
//
// 请求体是发送方的**声明**，整份都不可信：名字要净化、大小要交叉核对、总数要
// 等于各项之和。校验集中在本文件，处理器不各自解析 JSON——理由与身份判定相同：
// 散开的校验漏一处就是一条不设防的路径。
//
// prepare 的体里没有发送方身份，也没有 deviceId（protocol.h 约束 3）：身份取自
// 客户端证书，deviceId 由指纹现算。senderName 只用于显示。

#include "protocol.h"

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>

#include <expected>

namespace lanpipe::transfer {

// prepare 里声明的一个文件。
struct TransferFile
{
    QString id;       // 十六进制，会话内唯一（kFileIdBytes * 2 个字符）
    QString name;     // 发送方给的原始名，**未经净化**（§5.11）
    quint64 size = 0; // 声明大小。用户批准的就是它，也是硬上限（§5.3）
    QString mime;     // 仅用于显示，不参与任何判断
};

struct TransferRequest
{
    QString senderName; // 仅用于显示
    QList<TransferFile> files;
    quint64 totalSize = 0; // 必须等于各 size 之和
};

[[nodiscard]] QJsonObject toJson(const TransferRequest &request);

// 任何字段缺失、类型不对、超限、id 重复、总数与各项之和不符，一律失败。
[[nodiscard]] std::expected<TransferRequest, QString> transferRequestFromJson(const QByteArray &body);

// prepare 的 200 应答。
[[nodiscard]] QJsonObject prepareResponse(const QString &sessionId);
[[nodiscard]] std::expected<QString, QString> sessionIdFromJson(const QByteArray &body);

// complete 的 200 应答：**每个声明过的文件都出现**，bytes 只统计已落位的字节。
// 未传、在途、只剩临时分片的一律是 0——这样发送方的比较是精确的（§5.2）。
struct CompleteReport
{
    struct Entry
    {
        QString id;
        quint64 bytes = 0;
    };

    QList<Entry> files;

    [[nodiscard]] quint64 bytesFor(const QString &id) const;
};

[[nodiscard]] QJsonObject toJson(const CompleteReport &report);
[[nodiscard]] std::expected<CompleteReport, QString> completeReportFromJson(const QByteArray &body);

// 错误应答的体：{ reason, retryAfter? }。retryAfter 是秒数，只在 409 上出现
// （§5.13）——它只能进体里：响应的序列化只产生 Content-Type / Content-Length /
// Connection 三个头，没有可自定义头的地方。
[[nodiscard]] QJsonObject errorBody(const QString &reason, int retryAfterSeconds = 0);

// 从错误体里取可读原因。取不到就退回整段文本（对端可能是别的实现）。
[[nodiscard]] QString reasonFrom(const QByteArray &body);

} // namespace lanpipe::transfer

Q_DECLARE_METATYPE(lanpipe::transfer::TransferFile)
Q_DECLARE_METATYPE(lanpipe::transfer::TransferRequest)
Q_DECLARE_METATYPE(lanpipe::transfer::CompleteReport)
