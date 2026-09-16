#include "pingclient.h"

#include "mtls.h"
#include "protocol.h"
#include "random.h"
#include "sas.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslCertificate>

namespace lanpipe::transfer {

PingClient::PingClient(QObject *parent) : QObject(parent), m_manager(new QNetworkAccessManager(this))
{
    qRegisterMetaType<PingClient::Result>();

    // 不跟随重定向：跳到另一个源就等于把请求交给没有做指纹比对的一方，
    // 而接收方本来也不会重定向。3xx 一律按失败处理。
    m_manager->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
}

void PingClient::start(const QUrl &url, const Identity &identity,
                       std::optional<Fingerprint> expected)
{
    m_identity = identity;
    m_expected = std::move(expected);
    m_peerFingerprint = {};
    m_handshakeError.clear();
    m_reported = false;
    m_cnonce = randomHex(proto::kNonceBytes);

    QUrl target = url;
    target.setPath(QString::fromLatin1(proto::kPathPing.data(), proto::kPathPing.size()));
    target.setQuery(QStringLiteral("cnonce=%1").arg(m_cnonce));

    QNetworkRequest request(target);
    // 两端用同一份 mTLS 配置：出示自己的证书，也要求看到对方的证书（§4）。
    request.setSslConfiguration(net::mtlsConfiguration(identity));
    request.setTransferTimeout(proto::kSenderHttpTimeout);

    QNetworkReply *reply = m_manager->get(request);
    connect(reply, &QNetworkReply::sslErrors, this,
            [this, reply](const QList<QSslError> &errors) { onSslErrors(reply, errors); });
    connect(reply, &QNetworkReply::finished, this, [this, reply] { onFinished(reply); });
}

bool PingClient::adoptPeer(const QSslCertificate &certificate)
{
    const auto fingerprint = net::peerFingerprint(certificate);
    if (!fingerprint.has_value()) {
        m_handshakeError = fingerprint.error();
        return false;
    }

    if (m_expected.has_value() && *fingerprint != *m_expected) {
        m_handshakeError = QStringLiteral("对端指纹与预期不符：观察到 %1，预期 %2")
                               .arg(fingerprint->shortForm(), m_expected->shortForm());
        return false;
    }

    m_peerFingerprint = *fingerprint;
    return true;
}

void PingClient::onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors)
{
    const QList<QSslError> tolerated = net::toleratedHandshakeErrors(errors);
    if (tolerated.size() != errors.size()) {
        m_handshakeError = QStringLiteral("TLS 握手被拒绝：%1").arg(net::describeErrors(errors));
        reply->abort();
        return;
    }

    // 证书取自错误本身：此刻 reply->sslConfiguration() 还停留在请求里带的那一份，
    // 不含对端证书。判定失败就 abort——绝不放行一个没通过指纹比对的对端。
    if (!adoptPeer(net::certificateFromErrors(errors))) {
        reply->abort();
        return;
    }

    reply->ignoreSslErrors(tolerated);
}

void PingClient::onFinished(QNetworkReply *reply)
{
    reply->deleteLater();

    Result result;

    if (!m_handshakeError.isEmpty()) {
        result.error = m_handshakeError;
        report(result);
        return;
    }

    if (reply->error() != QNetworkReply::NoError) {
        result.error = QStringLiteral("请求失败：%1").arg(reply->errorString());
        report(result);
        return;
    }

    // 握手没触发 sslErrors 的路径在这里补上身份判定。
    if (!m_peerFingerprint.isValid()
        && !adoptPeer(reply->sslConfiguration().peerCertificate())) {
        result.error = m_handshakeError;
        report(result);
        return;
    }

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray body = reply->readAll();
    if (status != 200) {
        result.error =
            QStringLiteral("对端返回 %1：%2").arg(status).arg(QString::fromUtf8(body).trimmed());
        report(result);
        return;
    }

    const auto info = pingInfoFromJson(body);
    if (!info.has_value()) {
        result.error = info.error();
        report(result);
        return;
    }

    // 响应里的 fp 只用来核对：对端在 JSON 里写的和它握手出示的必须是同一把公钥。
    // 不一致说明对端有 bug 或有人在改包，两种都不该继续。
    if (info->fingerprint != m_peerFingerprint) {
        result.error = QStringLiteral("响应里的指纹与握手所见不符：%1 vs %2")
                           .arg(info->fingerprint.shortForm(), m_peerFingerprint.shortForm());
        report(result);
        return;
    }

    result.ok = true;
    result.info = *info;
    result.peerFingerprint = m_peerFingerprint;
    // 发送方指纹在前、接收方指纹在后（§4）。两个都取自本次握手。
    result.code = sasCode(computeSas(m_identity.fingerprint(), m_peerFingerprint, m_cnonce,
                                     info->snonce));
    report(result);
}

void PingClient::report(Result result)
{
    if (m_reported)
        return;
    m_reported = true;
    emit finished(result);
}

} // namespace lanpipe::transfer
