#pragma once

// 一条 TLS 连接上的一次请求（§5.15）。
//
// 状态机只有一条路径：收头 → 交给处理器 → （可选 100-continue 与读体）→ 回答 → 关连接。
// 连接不复用，所以「未读的请求体被当成下一个请求」在结构上就不可能发生——
// 这是把 keep-alive 那一整类缺陷用设计删掉，而不是逐个防住。

#include "httprequest.h"
#include "httpresponse.h"
#include "mtls.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QObject>
#include <QString>

#include <chrono>
#include <functional>
#include <optional>

class QSslSocket;
class QTimer;

namespace lanpipe::http {

class HttpConnection : public QObject
{
    Q_OBJECT

public:
    // 请求体的消费者。返回 false 表示接收方决定中途放弃（例如用户取消），
    // 连接随即断开且不发任何响应——正是 §5.5 要求的「取消时直接关连接」。
    using BodySink = std::function<bool(QByteArrayView)>;
    // 请求头解析完成后调用一次。
    using Handler = std::function<void(HttpConnection &)>;

    // 接管 socket 的所有权（它成为本对象的子对象）。peer 由连接层在握手后判定，
    // 构造即要求它是有效的——无效的连接根本不该被建出来。
    HttpConnection(QSslSocket *socket, net::PeerIdentity peer, Handler handler,
                   std::chrono::milliseconds idleTimeout, QObject *parent = nullptr);

    [[nodiscard]] const RequestHead &head() const { return m_head; }

    // 本次连接的对端身份。处理器只读它，不再自己解析证书——身份判定只有一处。
    // 是否放行这个身份是另一件事：由各处理器查信任库决定（§4 接收策略）。
    [[nodiscard]] const net::PeerIdentity &peer() const { return m_peer; }

    [[nodiscard]] QString peerDescription() const;
    [[nodiscard]] bool hasResponded() const { return m_responded; }

    // 答应 Expect: 100-continue。只应在准备读体时调用：先答应再读，
    // 否则客户端会白等一秒（§5.15）。
    void sendContinue();

    // 开始流式读体，最多 cap 字节。声明的长度超过 cap 时立刻 409 并关连接，
    // 一个字节都不读（§5.3）。收满全部字节后发出 bodyComplete()。
    void readBody(quint64 cap, BodySink sink);

    // 读体中途失败（磁盘满、写盘出错）时由 sink 调用：记住要回的状态码，
    // 停止读体并关连接。调用之后必须从 sink 返回 false。
    //
    // 不在这里直接 respond()：那会销毁正在执行的那个 sink 函数对象。
    void failBody(const Response &response);

    // 回答并关闭：写完最后一个字节后进入关闭流程。
    void respond(const Response &response);

    // 立刻断开，不发任何响应。
    void abort();

    // 暂停/恢复空闲计时。处理器要把这条连接挂起等一个人（例如等用户输入配对码），
    // 而那期间没有任何字节流动——不暂停就会被当成死连接掐掉（§5.8）。
    void pauseIdleTimeout();
    void resumeIdleTimeout();

signals:
    void bodyComplete();
    void finished(); // 连接已断开，可以销毁

private:
    enum class Phase {
        ReadingHead,
        Handling,    // 已交给处理器，等它读体或回答
        ReadingBody,
        Responded,
    };

    void onReadyRead();
    void onDisconnected();
    void onIdleTimeout();
    void parseHead();
    void pumpBody();
    void close();

    QSslSocket *m_socket = nullptr;
    net::PeerIdentity m_peer;
    Handler m_handler;
    QTimer *m_idleTimer = nullptr;

    Phase m_phase = Phase::ReadingHead;
    QByteArray m_buffer;
    RequestHead m_head;
    bool m_responded = false;
    bool m_closed = false;
    bool m_idlePaused = false;

    BodySink m_bodySink;
    quint64 m_bodyRemaining = 0;
    std::optional<Response> m_pendingFailure;
};

} // namespace lanpipe::http
