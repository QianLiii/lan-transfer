#include "httprequest.h"

#include "protocol.h"

#include <limits>

namespace lanpipe::http {

namespace {

HeadParseOutcome invalid(QString reason)
{
    HeadParseOutcome outcome;
    outcome.result = HeadParseResult::Invalid;
    outcome.error = std::move(reason);
    return outcome;
}

// RFC 9110 tchar
bool isTokenChar(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        return true;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default:
        return false;
    }
}

// proto 的上限是 std::size_t，而 Qt 容器的 size() 是 qsizetype（有符号）。
// 统一转一次，免得每处比较都写 static_cast。
constexpr qsizetype limit(std::size_t value) { return static_cast<qsizetype>(value); }

bool isVisibleAscii(const QByteArray &value)
{
    for (char c : value) {
        if (c < 0x21 || c > 0x7E)
            return false;
    }
    return true;
}

} // namespace

QByteArray RequestHead::header(const char *name) const
{
    const QList<QByteArray> values = headerValues(name);
    return values.isEmpty() ? QByteArray() : values.first();
}

QList<QByteArray> RequestHead::headerValues(const char *name) const
{
    const QByteArray wanted = QByteArray(name).toLower();
    QList<QByteArray> values;
    for (const auto &[key, value] : headers) {
        if (key.toLower() == wanted)
            values.append(value);
    }
    return values;
}

bool RequestHead::hasHeader(const char *name) const
{
    const QByteArray wanted = QByteArray(name).toLower();
    for (const auto &[key, value] : headers) {
        if (key.toLower() == wanted)
            return true;
    }
    return false;
}

HeadParseOutcome parseRequestHead(const QByteArray &buffer)
{
    HeadParseOutcome outcome;

    const qsizetype headEnd = buffer.indexOf("\r\n\r\n");
    if (headEnd < 0) {
        // 还没收完。上限必须在这里就检查，否则一个永不发空行的客户端
        // 能让我们无限缓冲——这正是 bounded header block 要防的。
        if (buffer.size() > limit(proto::kMaxHeaderBlockSize))
            return invalid(QStringLiteral("请求头超过大小上限"));
        const qsizetype lastLf = buffer.lastIndexOf('\n');
        if (buffer.size() - lastLf - 1 > limit(proto::kMaxHeaderLineLength))
            return invalid(QStringLiteral("请求行或头部字段超过长度上限"));
        return outcome; // Incomplete
    }

    if (headEnd > limit(proto::kMaxHeaderBlockSize))
        return invalid(QStringLiteral("请求头超过大小上限"));

    // headBlock 不含结尾的空行。
    const QByteArray headBlock = buffer.left(headEnd);
    const QList<QByteArray> rawLines = headBlock.split('\n');

    QList<QByteArray> lines;
    lines.reserve(rawLines.size());
    for (qsizetype i = 0; i < rawLines.size(); ++i) {
        QByteArray line = rawLines.at(i);
        if (line.size() > limit(proto::kMaxHeaderLineLength))
            return invalid(QStringLiteral("请求行或头部字段超过长度上限"));
        if (i == rawLines.size() - 1) {
            // 最后一行紧邻结尾空行，因此不带 CRLF。
            if (line.endsWith('\r'))
                return invalid(QStringLiteral("请求头中出现多余的空行"));
        } else {
            // 只接受 CRLF：宽松地接受裸 LF 会让分帧在不同实现间产生歧义。
            if (!line.endsWith('\r'))
                return invalid(QStringLiteral("请求行或头部字段没有以 CRLF 结束"));
            line.chop(1);
        }
        lines.append(line);
    }

    // ———— 请求行：严格三段 ————
    const QList<QByteArray> parts = lines.first().split(' ');
    if (parts.size() != 3)
        return invalid(QStringLiteral("请求行不是 METHOD / TARGET / VERSION 三段"));

    const QByteArray &method = parts.at(0);
    const QByteArray &target = parts.at(1);
    const QByteArray &version = parts.at(2);

    if (method.isEmpty() || method.size() > 16)
        return invalid(QStringLiteral("请求方法长度非法"));
    for (char c : method) {
        if (!isTokenChar(c))
            return invalid(QStringLiteral("请求方法含非法字符"));
    }

    if (target.isEmpty() || !target.startsWith('/'))
        return invalid(QStringLiteral("请求目标必须以 / 开头"));
    if (!isVisibleAscii(target))
        return invalid(QStringLiteral("请求目标含不可见字符"));

    // 只接受 HTTP/1.1。本项目的两端都是自己的实现，不需要迁就其它版本。
    if (version != "HTTP/1.1")
        return invalid(QStringLiteral("只支持 HTTP/1.1"));

    RequestHead head;
    head.method = method;
    head.target = target;
    head.httpMajor = 1;
    head.httpMinor = 1;

    // ———— 头部字段 ————
    if (lines.size() - 1 > limit(proto::kMaxHeaderFieldCount))
        return invalid(QStringLiteral("头部字段数量超过上限"));

    for (qsizetype i = 1; i < lines.size(); ++i) {
        const QByteArray &line = lines.at(i);
        if (line.isEmpty())
            return invalid(QStringLiteral("头部块中间出现空行"));
        // 折行（obs-fold）是经典的走私向量，直接拒绝。
        if (line.startsWith(' ') || line.startsWith('\t'))
            return invalid(QStringLiteral("不接受折行的头部字段"));

        const qsizetype colon = line.indexOf(':');
        if (colon <= 0)
            return invalid(QStringLiteral("头部字段缺少字段名"));

        const QByteArray name = line.left(colon);
        // 字段名与冒号之间不允许空白（RFC 9112）；宽松地接受会让不同实现
        // 对同一请求的解释产生分歧。
        if (name.endsWith(' ') || name.endsWith('\t'))
            return invalid(QStringLiteral("字段名与冒号之间不允许空白"));
        for (char c : name) {
            if (!isTokenChar(c))
                return invalid(QStringLiteral("头部字段名含非法字符"));
        }

        QByteArray value = line.mid(colon + 1);
        while (value.startsWith(' ') || value.startsWith('\t'))
            value.remove(0, 1);
        while (value.endsWith(' ') || value.endsWith('\t'))
            value.chop(1);
        for (char c : value) {
            if (c != '\t' && (c < 0x20 || c > 0x7E))
                return invalid(QStringLiteral("头部字段值只接受可见 ASCII 与制表符"));
        }

        head.headers.append({name, value});
    }

    // ———— 分帧与体积：§5.15 的强制检查 ————

    // 任何 Transfer-Encoding 都拒绝。chunked 是各类 HTTP 解析器里最大的
    // 漏洞来源类，而 QNetworkAccessManager 只用 Content-Length 分帧。
    if (head.hasHeader("Transfer-Encoding"))
        return invalid(QStringLiteral("不支持 Transfer-Encoding"));

    if (head.hasHeader("Trailer"))
        return invalid(QStringLiteral("不支持 trailer"));

    if (head.hasHeader("Content-Encoding"))
        return invalid(QStringLiteral("不支持压缩的请求体"));

    if (head.hasHeader("Range"))
        return invalid(QStringLiteral("不支持 Range 请求"));

    if (head.header("Content-Type").toLower().startsWith("multipart/"))
        return invalid(QStringLiteral("不支持 multipart 请求体"));

    const QList<QByteArray> contentLengths = head.headerValues("Content-Length");
    if (contentLengths.size() > 1)
        return invalid(QStringLiteral("重复的 Content-Length"));
    if (contentLengths.size() == 1) {
        const QByteArray &raw = contentLengths.first();
        if (raw.isEmpty())
            return invalid(QStringLiteral("Content-Length 为空"));

        quint64 value = 0;
        for (char c : raw) {
            if (c < '0' || c > '9')
                return invalid(QStringLiteral("Content-Length 不是纯数字"));
            const auto digit = static_cast<quint64>(c - '0');
            // 无符号运算 + 显式溢出检查。不要照抄 Qt 的 toULongLong() → qint64
            // 写法（QTBUG-150275：超过 INT64_MAX 回绕为负，绕过体积检查并
            // 把剩余字节当成下一个请求，成为走私原语）。
            if (value > (std::numeric_limits<quint64>::max() - digit) / 10)
                return invalid(QStringLiteral("Content-Length 溢出"));
            value = value * 10 + digit;
        }
        head.hasContentLength = true;
        head.contentLength = value;
    }

    // 重复的头一律拒：header() 只返回第一个值，而其它值同样会被对端和中间设备按各自
    // 的规矩解释——「只认第一个」正是请求走私的经典入口。Content-Length 一直这么查，
    // Expect 是我们另外唯一会解释的头。
    const QList<QByteArray> expects = head.headerValues("Expect");
    if (expects.size() > 1)
        return invalid(QStringLiteral("重复的 Expect"));

    if (!expects.isEmpty()) {
        if (expects.first().compare("100-continue", Qt::CaseInsensitive) != 0)
            return invalid(QStringLiteral("只支持 Expect: 100-continue"));
        head.expectContinue = true;
    }

    outcome.result = HeadParseResult::Complete;
    outcome.head = std::move(head);
    outcome.consumed = headEnd + 4; // 含结尾的 CRLF CRLF
    return outcome;
}

} // namespace lanpipe::http
