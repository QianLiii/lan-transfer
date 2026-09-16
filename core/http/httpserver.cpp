#include "httpserver.h"

#include "identity.h"
#include "mtls.h"
#include "protocol.h"

#include <QSslSocket>
#include <QTcpSocket>

namespace lanpipe::http {

HttpServer::HttpServer(QObject *parent)
    : QSslServer(parent), m_idleTimeout(proto::kStallTimeout)
{
    // 握手期的证书裁定。QSslServer 把每条 socket 的 sslErrors 转发到这里，
    // 而 Qt 只有在错误被 ignoreSslErrors() 放行之后才继续握手——所以结论必须
    // 在这里当场给出，不能挪到别处。
    connect(this, &QSslServer::sslErrors, this,
            [](QSslSocket *socket, const QList<QSslError> &errors) {
                const QList<QSslError> tolerated = net::toleratedHandshakeErrors(errors);
                if (tolerated.size() != errors.size()) {
                    // 存在不可放行的错误，整条连接作废。不做部分放行：
                    // 只放行信任类的错误，其余一律拒绝，且原因要留在日志里。
                    qWarning("lanpipe: TLS 握手被拒绝（%s）：%s",
                             qPrintable(socket->peerAddress().toString()),
                             qPrintable(net::describeErrors(errors)));
                    return;
                }
                socket->ignoreSslErrors(tolerated);
            });

    // 必须接 pendingConnectionAvailable，不能接 newConnection。
    //
    // QTcpServer 的 accept 循环在 incomingConnection() 返回后立刻发 newConnection()，
    // 对 TLS 服务器来说那时握手还没开始，socket 既没加密也还没进待取队列，
    // nextPendingConnection() 在那个时点返回空。QSslServer 要等握手完成才把 socket
    // 交给 addPendingConnection()，而它发的信号是 pendingConnectionAvailable。
    // 接错信号的症状是：每条连接都取不到，请求全部静默丢失。
    connect(this, &QTcpServer::pendingConnectionAvailable, this, &HttpServer::acceptPending);

    // 连接上限（§5.13）。QSslServer 内部把「正在握手的 socket」也算进
    // totalPendingConnections()，所以这个值同时封住了握手中的连接数。
    setMaxPendingConnections(static_cast<int>(proto::kMaxConnections));
    setHandshakeTimeout(proto::kHandshakeTimeoutMs);
}

std::expected<quint16, QString> HttpServer::listen(const Identity &identity, quint16 port,
                                                   const QHostAddress &address)
{
    // 必须在 listen() 之前设置：QSslServer 的文档明确要求，否则首批连接的
    // 握手会用默认配置完成。
    setSslConfiguration(net::mtlsConfiguration(identity));

    if (!QSslServer::listen(address, port))
        return std::unexpected(QStringLiteral("无法监听 %1:%2：%3")
                                   .arg(address.toString())
                                   .arg(port)
                                   .arg(errorString()));

    return serverPort();
}

void HttpServer::incomingConnection(qintptr descriptor)
{
    if (m_connections.size() >= static_cast<qsizetype>(proto::kMaxConnections)) {
        // 超出的连接连 TLS 握手都不做。握手是这条路径上最贵的一步，
        // 拒在它之前，多一个连接的开销就只剩 accept。
        QTcpSocket rejected;
        rejected.setSocketDescriptor(descriptor);
        rejected.abort();
        qInfo("lanpipe: %s", qPrintable(QStringLiteral("并发连接已达上限 %1，拒绝新连接")
                                            .arg(proto::kMaxConnections)));
        return;
    }

    QSslServer::incomingConnection(descriptor);
}

void HttpServer::acceptPending()
{
    while (QTcpSocket *pending = nextPendingConnection()) {
        auto *socket = qobject_cast<QSslSocket *>(pending);
        if (!socket) {
            pending->abort();
            pending->deleteLater();
            continue;
        }

        auto *connection = new HttpConnection(socket, m_handler, m_idleTimeout, this);
        m_connections.append(connection);
        connect(connection, &HttpConnection::finished, this, [this, connection] {
            m_connections.removeOne(connection);
            connection->deleteLater();
        });
    }
}

} // namespace lanpipe::http
