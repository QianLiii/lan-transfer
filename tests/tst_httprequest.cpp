// HTTP 请求头解析（§5.15）。
//
// 这个文件里负向用例的数量远多于正向——解析器的规格主要就是「拒绝什么」。

#include <QtTest>

#include "http/httprequest.h"
#include "protocol.h"

using namespace lanpipe::http;

namespace {

QByteArray build(const QByteArray &requestLine, const QList<QByteArray> &headers = {},
                 const QByteArray &body = {})
{
    QByteArray out = requestLine + "\r\n";
    for (const QByteArray &header : headers)
        out += header + "\r\n";
    out += "\r\n";
    out += body;
    return out;
}

const QByteArray kGetLine = "GET /api/v1/ping HTTP/1.1";

} // namespace

class TestHttpRequest : public QObject
{
    Q_OBJECT

private slots:
    // —————————————— 正向 ——————————————

    void parsesSimpleRequest()
    {
        const HeadParseOutcome outcome = parseRequestHead(build(kGetLine));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.method, QByteArray("GET"));
        QCOMPARE(outcome.head.target, QByteArray("/api/v1/ping"));
        QCOMPARE(outcome.head.httpMajor, 1);
        QCOMPARE(outcome.head.httpMinor, 1);
        QVERIFY(!outcome.head.hasContentLength);
        QCOMPARE(outcome.consumed, build(kGetLine).size());
    }

    void parsesContentLength()
    {
        const HeadParseOutcome outcome = parseRequestHead(
            build("PUT /api/v1/upload/s1/f2 HTTP/1.1", {"Content-Length: 1048576"}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QVERIFY(outcome.head.hasContentLength);
        QCOMPARE(outcome.head.contentLength, quint64{1048576});
    }

    // 解析器不设自己的体积上限——上限是用户批准的那个数字，由连接层强制（§5.3）。
    void acceptsLargeContentLength()
    {
        const HeadParseOutcome outcome =
            parseRequestHead(build("PUT /api/v1/upload/s1/f2 HTTP/1.1",
                                   {"Content-Length: 10737418240"})); // 10 GiB

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.contentLength, quint64{10737418240});
    }

    void contentLengthZeroIsValid()
    {
        const HeadParseOutcome outcome =
            parseRequestHead(build("POST /api/v1/complete/s1 HTTP/1.1", {"Content-Length: 0"}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QVERIFY(outcome.head.hasContentLength);
        QCOMPARE(outcome.head.contentLength, quint64{0});
    }

    // consumed 必须指向请求体的第一个字节，连接层据此切换阶段。
    void consumedPointsAtBodyStart()
    {
        const QByteArray buffer =
            build("PUT /api/v1/upload/s1/f2 HTTP/1.1", {"Content-Length: 5"}, "hello");

        const HeadParseOutcome outcome = parseRequestHead(buffer);
        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(buffer.mid(outcome.consumed), QByteArray("hello"));
    }

    void headerLookupIsCaseInsensitive()
    {
        const HeadParseOutcome outcome = parseRequestHead(
            build(kGetLine, {"content-LENGTH: 42", "X-Custom: value"}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.header("Content-Length"), QByteArray("42"));
        QCOMPARE(outcome.head.header("x-custom"), QByteArray("value"));
        QVERIFY(outcome.head.hasHeader("CONTENT-length"));
        QCOMPARE(outcome.head.header("Missing"), QByteArray());
    }

    void stripsOptionalWhitespaceAroundValue()
    {
        const HeadParseOutcome outcome =
            parseRequestHead(build(kGetLine, {"X-Padded:    spaced   "}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.header("X-Padded"), QByteArray("spaced"));
    }

    void emptyValueIsAllowed()
    {
        const HeadParseOutcome outcome = parseRequestHead(build(kGetLine, {"X-Empty:"}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QVERIFY(outcome.head.hasHeader("X-Empty"));
        QCOMPARE(outcome.head.header("X-Empty"), QByteArray());
    }

    void targetWithQueryIsAccepted()
    {
        const HeadParseOutcome outcome =
            parseRequestHead(build("GET /api/v1/ping?cnonce=deadbeef HTTP/1.1"));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.target, QByteArray("/api/v1/ping?cnonce=deadbeef"));
    }

    void expectContinueIsReported()
    {
        const HeadParseOutcome outcome = parseRequestHead(
            build("PUT /api/v1/upload/s1/f2 HTTP/1.1",
                  {"Content-Length: 10", "Expect: 100-continue"}));

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QVERIFY(outcome.head.expectContinue);
    }

    // —————————————— 不完整：继续等，不是错误 ——————————————

    void partialHeadIsIncomplete()
    {
        QCOMPARE(parseRequestHead("GET /api/v1/pi").result, HeadParseResult::Incomplete);
        QCOMPARE(parseRequestHead("GET /api/v1/ping HTTP/1.1\r\n").result,
                 HeadParseResult::Incomplete);
        QCOMPARE(parseRequestHead("GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n").result,
                 HeadParseResult::Incomplete);
    }

    // —————————————— 负向：必须拒绝 ——————————————

    // chunked 是各类解析器里最大的漏洞来源类，整体拒绝。
    void rejectsTransferEncoding()
    {
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {"Transfer-Encoding: chunked"})).result,
                 HeadParseResult::Invalid);
        // 与 Content-Length 并存也要拒绝（CL/TE 歧义）
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1",
                                        {"Transfer-Encoding: chunked", "Content-Length: 5"}))
                     .result,
                 HeadParseResult::Invalid);
        // 即使是 identity 也不接受：本协议没有它的位置
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {"Transfer-Encoding: identity"})).result,
                 HeadParseResult::Invalid);
    }

    void rejectsDuplicateContentLength()
    {
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1",
                                        {"Content-Length: 5", "Content-Length: 5"}))
                     .result,
                 HeadParseResult::Invalid);
        // 大小写不同也算重复
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1",
                                        {"Content-Length: 5", "content-length: 6"}))
                     .result,
                 HeadParseResult::Invalid);
    }

    void rejectsMalformedContentLength()
    {
        const QList<QByteArray> bad{
            "Content-Length: 5a",     "Content-Length: abc",
            "Content-Length: -1",     "Content-Length: +5",
            "Content-Length: 0x10",   "Content-Length: 1.5",
            "Content-Length: 5 5",    "Content-Length:",
        };
        for (const QByteArray &header : bad) {
            QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {header})).result,
                     HeadParseResult::Invalid);
        }
    }

    // 溢出必须被拒绝，而不是回绕。QTBUG-150275 就是漏了这一步。
    void rejectsOverflowingContentLength()
    {
        const QList<QByteArray> overflow{
            "Content-Length: 18446744073709551616",     // 2^64
            "Content-Length: 99999999999999999999999",
            "Content-Length: 340282366920938463463374607431768211456", // 2^128
        };
        for (const QByteArray &header : overflow) {
            QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {header})).result,
                     HeadParseResult::Invalid);
        }
    }

    // QUINT64_MAX 本身不溢出，应当被接受。
    void acceptsMaximumContentLength()
    {
        const HeadParseOutcome outcome = parseRequestHead(
            build("PUT /x HTTP/1.1", {"Content-Length: 18446744073709551615"}));
        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.contentLength, std::numeric_limits<quint64>::max());
    }

    // 大于 INT64_MAX 但仍在 quint64 范围内：必须接受，且绝不能回绕成负数。
    // 这正是与 QTBUG-150275 的分界——那边把值读进 qint64，于是 2^63 变成负数，
    // 体积检查被绕过，剩余字节被当成下一个请求。
    void acceptsValuesAboveInt64MaxWithoutWrapping()
    {
        const HeadParseOutcome outcome = parseRequestHead(
            build("PUT /x HTTP/1.1", {"Content-Length: 9223372036854775808"})); // 2^63

        QCOMPARE(outcome.result, HeadParseResult::Complete);
        QCOMPARE(outcome.head.contentLength, quint64{9223372036854775808ULL});
    }

    void rejectsUnsupportedBodyEncodings()
    {
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {"Content-Encoding: gzip"})).result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead(
                     build("PUT /x HTTP/1.1", {"Content-Type: multipart/form-data; boundary=x"}))
                     .result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {"Trailer: X-Sum"})).result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead(build("GET /x HTTP/1.1", {"Range: bytes=0-1023"})).result,
                 HeadParseResult::Invalid);
    }

    void rejectsNonContinueExpect()
    {
        QCOMPARE(parseRequestHead(build("PUT /x HTTP/1.1", {"Expect: something-else"})).result,
                 HeadParseResult::Invalid);
    }

    // 只接受 CRLF。宽松地接受裸 LF 会让分帧在不同实现间产生歧义。
    void rejectsBareLineFeed()
    {
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1\nHost: y\r\n\r\n").result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1\r\nHost: y\n\r\n\r\n").result,
                 HeadParseResult::Invalid);
    }

    // 折行是经典的走私向量。
    void rejectsObsFold()
    {
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1\r\nHost: y\r\n continued\r\n\r\n").result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1\r\nHost: y\r\n\tcontinued\r\n\r\n").result,
                 HeadParseResult::Invalid);
    }

    // 字段名与冒号之间的空白会让不同实现产生分歧。
    void rejectsSpaceBeforeColon()
    {
        QCOMPARE(parseRequestHead(build(kGetLine, {"Host : y"})).result, HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead(build(kGetLine, {"Host\t: y"})).result, HeadParseResult::Invalid);
    }

    void rejectsControlCharactersInHeaderValue()
    {
        QByteArray buffer = build(kGetLine, {"X-Bad: a"});
        buffer.insert(buffer.indexOf("\r\n\r\n"), '\x01');
        QCOMPARE(parseRequestHead(buffer).result, HeadParseResult::Invalid);
    }

    void rejectsMalformedRequestLine()
    {
        QCOMPARE(parseRequestHead("GET  /x HTTP/1.1\r\n\r\n").result, HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x\r\n\r\n").result, HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1 extra\r\n\r\n").result,
                 HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GE\x01T /x HTTP/1.1\r\n\r\n").result, HeadParseResult::Invalid);
    }

    void rejectsUnsupportedHttpVersion()
    {
        QCOMPARE(parseRequestHead("GET /x HTTP/1.0\r\n\r\n").result, HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x HTTP/2.0\r\n\r\n").result, HeadParseResult::Invalid);
        QCOMPARE(parseRequestHead("GET /x HTTP/1.1x\r\n\r\n").result, HeadParseResult::Invalid);
    }

    void rejectsTargetNotStartingWithSlash()
    {
        QCOMPARE(parseRequestHead("GET x HTTP/1.1\r\n\r\n").result, HeadParseResult::Invalid);
        // 绝对形式的目标（代理式请求）同样不在子集内
        QCOMPARE(parseRequestHead("GET http://a/b HTTP/1.1\r\n\r\n").result,
                 HeadParseResult::Invalid);
    }

    // —————————————— 上限 ——————————————

    void rejectsTooManyHeaders()
    {
        QList<QByteArray> headers;
        for (qsizetype i = 0; i <= static_cast<qsizetype>(lanpipe::proto::kMaxHeaderFieldCount); ++i)
            headers.append("X-" + QByteArray::number(i) + ": v");

        QCOMPARE(parseRequestHead(build(kGetLine, headers)).result, HeadParseResult::Invalid);
    }

    void rejectsOverlongHeaderLine()
    {
        const QByteArray huge(static_cast<qsizetype>(lanpipe::proto::kMaxHeaderLineLength) + 1, 'a');
        QCOMPARE(parseRequestHead(build(kGetLine, {"X-Long: " + huge})).result,
                 HeadParseResult::Invalid);
    }

    // 单行超长必须在收完整个头部块之前就被拒绝，否则只是把缓冲上限往后挪。
    void rejectsOverlongLineBeforeHeadIsComplete()
    {
        QByteArray buffer = kGetLine + "\r\nX-Long: ";
        buffer += QByteArray(static_cast<qsizetype>(lanpipe::proto::kMaxHeaderLineLength) + 1, 'a');
        QCOMPARE(parseRequestHead(buffer).result, HeadParseResult::Invalid);
    }

    // 永不发空行的客户端必须在上限处被拒绝，而不是让我们无限缓冲。
    void rejectsOversizedBlockBeforeHeadIsComplete()
    {
        QByteArray buffer = kGetLine + "\r\n";
        while (buffer.size() <= static_cast<qsizetype>(lanpipe::proto::kMaxHeaderBlockSize))
            buffer += "X-Fill: 0123456789012345678901234567890123456789\r\n";
        QCOMPARE(parseRequestHead(buffer).result, HeadParseResult::Invalid);
    }
};

QTEST_APPLESS_MAIN(TestHttpRequest)

#include "tst_httprequest.moc"
