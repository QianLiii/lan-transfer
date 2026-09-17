#include "httpconnection.h"

#include "protocol.h"

#include <QSslCertificate>
#include <QSslSocket>
#include <QTimer>

#include <algorithm>

namespace lanpipe::http {

HttpConnection::HttpConnection(QSslSocket *socket, net::PeerIdentity peer, Handler handler,
                               std::chrono::milliseconds idleTimeout, QObject *parent)
    : QObject(parent), m_socket(socket), m_peer(std::move(peer)), m_handler(std::move(handler))
{
    // socket 原本是 QSslServer 的子对象；挂到本对象下面，两者的生命周期就一致了。
    m_socket->setParent(this);

    m_idleTimer = new QTimer(this);
    m_idleTimer->setSingleShot(true);
    m_idleTimer->setInterval(idleTimeout);
    connect(m_idleTimer, &QTimer::timeout, this, &HttpConnection::onIdleTimeout);

    connect(m_socket, &QSslSocket::readyRead, this, &HttpConnection::onReadyRead);
    connect(m_socket, &QSslSocket::disconnected, this, &HttpConnection::onDisconnected);
    connect(m_socket, &QSslSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        // 对端消失、连接被重置都走这里。不等 disconnected：错误路径上这条连接
        // 已经没有用了，而 finished() 必须发出去，否则连接对象永远不会被回收。
        m_socket->abort();
        close();
    });

    m_idleTimer->start();
}

QString HttpConnection::peerDescription() const
{
    return QStringLiteral("%1:%2")
        .arg(m_socket->peerAddress().toString())
        .arg(m_socket->peerPort());
}

void HttpConnection::sendContinue()
{
    if (m_responded || !m_head.expectContinue)
        return;
    m_socket->write("HTTP/1.1 100 Continue\r\n\r\n");
}

void HttpConnection::readBody(quint64 cap, BodySink sink)
{
    if (m_responded || m_phase != Phase::Handling)
        return;

    if (!m_head.hasContentLength) {
        // 封闭子集里只有 Content-Length 一种分帧方式，没有它就没有体。
        emit bodyComplete();
        return;
    }

    if (m_head.contentLength > cap) {
        // 声明的长度已经超过批准值，一个字节都不必读（§5.3）。
        respond(Response::text(Status::Conflict, QStringLiteral("请求体超过批准的大小")));
        return;
    }

    m_bodySink = std::move(sink);
    m_bodyRemaining = m_head.contentLength;
    m_phase = Phase::ReadingBody;
    pumpBody();
}

void HttpConnection::respond(const Response &response)
{
    if (m_responded)
        return; // 一个请求只有一个响应，后到的直接丢

    m_responded = true;
    m_phase = Phase::Responded;
    m_bodySink = nullptr;
    m_buffer.clear();

    m_socket->write(serializeResponse(response));
    // disconnectFromHost() 会等明文写缓冲排空再发 close_notify；close() 直接清空它。
    m_socket->disconnectFromHost();
}

void HttpConnection::abort()
{
    m_responded = true;
    m_phase = Phase::Responded;
    m_socket->abort();
}

void HttpConnection::pauseIdleTimeout()
{
    m_idlePaused = true;
    m_idleTimer->stop();
}

void HttpConnection::resumeIdleTimeout()
{
    if (!m_idlePaused)
        return;
    m_idlePaused = false;
    m_idleTimer->start();
}

void HttpConnection::onReadyRead()
{
    if (!m_idlePaused)
        m_idleTimer->start(); // 每收到一批数据就是一次进度

    switch (m_phase) {
    case Phase::ReadingHead:
        m_buffer += m_socket->readAll();
        parseHead();
        return;
    case Phase::ReadingBody:
        m_buffer += m_socket->readAll();
        pumpBody();
        return;
    case Phase::Handling:
    case Phase::Responded:
        // 处理器要么已经在返回前读完了体，要么已经回答过。剩下的字节直接丢弃：
        // 连接不复用，它们不可能被当成下一个请求。
        m_socket->readAll();
        return;
    }
}

void HttpConnection::parseHead()
{
    const HeadParseOutcome outcome = parseRequestHead(m_buffer);

    switch (outcome.result) {
    case HeadParseResult::Incomplete:
        return; // 上限检查在解析器里，这里只管继续等

    case HeadParseResult::Invalid:
        // 400 并关连接，请求体一个字节都不读（§5.15）。
        qInfo("lanpipe: 拒绝 %s 的请求：%s", qPrintable(peerDescription()),
              qPrintable(outcome.error));
        respond(Response::text(Status::BadRequest, outcome.error));
        return;

    case HeadParseResult::Complete:
        break;
    }

    m_head = outcome.head;
    m_buffer.remove(0, outcome.consumed);
    m_phase = Phase::Handling;

    if (m_handler)
        m_handler(*this);
    // 处理器没回答就返回：要么它稍后异步调用 respond()，要么空闲超时兜底。
    // M3 的 prepare 属于前者——等待用户审批期间没有字节流动，30 秒的空闲计时
    // 会误杀它，那时必须在这里暂停计时器（§5.8）。
}

void HttpConnection::pumpBody()
{
    while (m_bodyRemaining > 0 && !m_buffer.isEmpty()) {
        const auto take = static_cast<qsizetype>(
            std::min<quint64>(m_bodyRemaining, static_cast<quint64>(m_buffer.size())));

        const bool keepGoing =
            !m_bodySink || m_bodySink(QByteArrayView(m_buffer.constData(), take));

        m_buffer.remove(0, take);
        m_bodyRemaining -= static_cast<quint64>(take);

        if (!keepGoing) {
            // 接收方中途放弃：直接断开，不发响应（§5.5）。
            abort();
            return;
        }
    }

    if (m_bodyRemaining == 0) {
        m_bodySink = nullptr;
        m_phase = Phase::Handling;
        emit bodyComplete(); // 处理器在这里回答
    }
}

void HttpConnection::onIdleTimeout()
{
    qInfo("lanpipe: %s 空闲超时，关闭连接", qPrintable(peerDescription()));
    m_socket->abort();
    close();
}

void HttpConnection::onDisconnected()
{
    close();
}

void HttpConnection::close()
{
    if (m_closed)
        return;
    m_closed = true;
    m_idleTimer->stop();
    emit finished();
}

} // namespace lanpipe::http
