#pragma once

// 接收方的 HTTPS 监听（§5.13）。QSslServer 的子类，只做三件事：
//
//   1. 用固定的 mTLS 配置握手，并在握手期裁定证书错误（mtls.h）；
//   2. 把并发连接数卡死在上限内，超出的连接连握手都不做；
//   3. 管理每条连接的生命周期，把解析好的请求交给处理器。
//
// 监听地址与端口：端口 0 表示由系统分配临时端口，实际端口经服务发现通告（§3.1）。

#include "httpconnection.h"

#include <QHostAddress>
#include <QList>
#include <QSslServer>
#include <QString>

#include <chrono>
#include <expected>

namespace lanpipe {

class Identity;

} // namespace lanpipe

namespace lanpipe::http {

class HttpServer : public QSslServer
{
    Q_OBJECT

public:
    explicit HttpServer(QObject *parent = nullptr);

    // 用 identity 配置 mTLS 并开始监听，成功返回实际端口。
    [[nodiscard]] std::expected<quint16, QString> listen(const Identity &identity, quint16 port,
                                                         const QHostAddress &address =
                                                             QHostAddress::Any);

    // 每条连接解析出请求头后调用一次。
    void setHandler(HttpConnection::Handler handler) { m_handler = std::move(handler); }

    // 空闲多久算死连接。只有测试需要改它。
    void setIdleTimeout(std::chrono::milliseconds timeout) { m_idleTimeout = timeout; }

    [[nodiscard]] qsizetype connectionCount() const { return m_connections.size(); }

protected:
    void incomingConnection(qintptr descriptor) override;

private:
    void acceptPending();

    QList<HttpConnection *> m_connections;
    HttpConnection::Handler m_handler;
    std::chrono::milliseconds m_idleTimeout;
};

} // namespace lanpipe::http
