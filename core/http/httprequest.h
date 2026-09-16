#pragma once

// HTTP/1.1 请求头解析（§5.15）。
//
// 这是一个封闭子集：只接受 Content-Length 分帧，其余一切——chunked、trailer、
// 压缩体、multipart、Range、折行——一律拒绝而不是忽略。解析器不做任何解码。

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace lanpipe::http {

// 「数据不够」与「非法」必须分开：前者继续等，后者立刻 400 并断连。
enum class HeadParseResult {
    Incomplete,
    Complete,
    Invalid,
};

struct RequestHead
{
    QByteArray method;
    QByteArray target;
    int httpMajor = 0;
    int httpMinor = 0;
    QList<QPair<QByteArray, QByteArray>> headers; // 保序，便于诊断输出

    bool hasContentLength = false;
    quint64 contentLength = 0;
    bool expectContinue = false;

    // 字段名大小写不敏感，重复字段返回第一个。
    [[nodiscard]] QByteArray header(const char *name) const;
    [[nodiscard]] QList<QByteArray> headerValues(const char *name) const;
    [[nodiscard]] bool hasHeader(const char *name) const;
};

struct HeadParseOutcome
{
    HeadParseResult result = HeadParseResult::Incomplete;
    RequestHead head;
    qsizetype consumed = 0; // Complete 时：头部占用的字节数，之后是请求体
    QString error;          // Invalid 时：可读原因，写进日志
};

// 从 buffer 开头解析请求头。buffer 应包含尚未消费的全部已收字节。
[[nodiscard]] HeadParseOutcome parseRequestHead(const QByteArray &buffer);

} // namespace lanpipe::http
