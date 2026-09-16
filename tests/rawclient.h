#pragma once

// 测试用的裸 TLS 客户端（§9 M1 的验收要靠它）。
//
// 它直接往连接里写字节，包括合法客户端永远不会发的那种——解析器的负向用例
// 只能这样测。它总是放行对端证书的信任类错误：这些用例要观察的是**服务端**的
// 裁定，客户端这边不能提前把连接掐掉。
//
// 刻意不声明 Q_OBJECT：它没有自己的信号，全靠 lambda 连接，因此作为纯头文件的
// 测试助手不牵扯 moc。

#include "mtls.h"

#include <QByteArray>
#include <QObject>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslSocket>
#include <QString>

#include <functional>

class RawClient : public QObject
{
public:
    explicit RawClient(QSslConfiguration configuration, QObject *parent = nullptr)
        : QObject(parent), m_socket(new QSslSocket(this)), m_configuration(std::move(configuration))
    {
        m_socket->setSslConfiguration(m_configuration);

        connect(m_socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError> &errors) {
            const QList<QSslError> tolerated = lanpipe::net::toleratedHandshakeErrors(errors);
            if (tolerated.size() != errors.size())
                m_error = lanpipe::net::describeErrors(errors);
            else
                m_socket->ignoreSslErrors(tolerated);
        });

        connect(m_socket, &QSslSocket::encrypted, this, [this] {
            m_encrypted = true;
            m_socket->write(m_pending);
            m_socket->flush();
            m_pending.clear();
        });

        connect(m_socket, &QSslSocket::readyRead, this, [this] { m_response += m_socket->readAll(); });

        const auto closed = [this] {
            m_response += m_socket->readAll();
            m_finished = true;
        };
        connect(m_socket, &QSslSocket::disconnected, this, closed);
        connect(m_socket, &QSslSocket::errorOccurred, this, [this, closed](QAbstractSocket::SocketError) {
            if (m_error.isEmpty())
                m_error = m_socket->errorString();
            closed();
        });
    }

    void connectTo(quint16 port)
    {
        m_socket->connectToHostEncrypted(QStringLiteral("127.0.0.1"), port);
    }

    // 握手完成前调用会先缓冲，握手一完成立即发出。
    void send(const QByteArray &bytes)
    {
        if (m_encrypted) {
            m_socket->write(bytes);
            m_socket->flush();
            return;
        }
        m_pending += bytes;
    }

    void abort() { m_socket->abort(); }
    // 等待写缓冲排空后再关，测试希望对方收到完整请求时用它。
    void closeGracefully() { m_socket->disconnectFromHost(); }

    [[nodiscard]] bool encrypted() const { return m_encrypted; }
    [[nodiscard]] bool finished() const { return m_finished; }
    [[nodiscard]] QByteArray response() const { return m_response; }
    [[nodiscard]] QString error() const { return m_error; }

    // 响应里第一行状态码；没有响应时返回 0。
    [[nodiscard]] int statusCode() const
    {
        const QByteArray line = m_response.left(m_response.indexOf("\r\n"));
        const QList<QByteArray> parts = line.split(' ');
        return parts.size() >= 2 ? parts.at(1).toInt() : 0;
    }

private:
    QSslSocket *m_socket = nullptr;
    QSslConfiguration m_configuration;
    QByteArray m_pending;
    QByteArray m_response;
    QString m_error;
    bool m_encrypted = false;
    bool m_finished = false;
};

namespace rawclient {

// 带客户端证书的配置：正常用例用它。
[[nodiscard]] inline QSslConfiguration withCertificate(const lanpipe::Identity &identity)
{
    return lanpipe::net::mtlsConfiguration(identity);
}

// 不出示任何证书的配置：用来验证「没有证书的连接一律拒绝」。
[[nodiscard]] inline QSslConfiguration withoutCertificate()
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
    configuration.setProtocol(QSsl::TlsV1_2OrLater);
    configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    return configuration;
}

} // namespace rawclient
