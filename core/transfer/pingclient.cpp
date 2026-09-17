#include "pingclient.h"

#include "mtls.h"
#include "protocol.h"
#include "random.h"
#include "sas.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslCertificate>

namespace lanpipe::transfer {

PingClient::PingClient(trust::TrustStore &trust, QObject *parent)
    : QObject(parent), m_manager(new QNetworkAccessManager(this)), m_trust(trust)
{
    qRegisterMetaType<PingClient::Result>();

    // 不跟随重定向：跳到另一个源就等于把请求交给没有做指纹比对的一方，
    // 而接收方本来也不会重定向。3xx 一律按失败处理。
    m_manager->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
}

void PingClient::start(const QUrl &url, const Identity &identity, const QString &name,
                       std::optional<Fingerprint> expected)
{
    m_identity = identity;
    m_expected = std::move(expected);
    m_peerFingerprint = {};
    m_code = {};
    m_handshakeError.clear();
    m_reported = false;
    m_cnonce = randomHex(proto::kNonceBytes);

    QUrl target = url;
    target.setPath(QString::fromLatin1(proto::kPathPing.data(), proto::kPathPing.size()));

    QNetworkRequest request(target);
    // 两端用同一份 mTLS 配置：出示自己的证书，也要求看到对方的证书（§4）。
    request.setSslConfiguration(net::mtlsConfiguration(identity));
    request.setTransferTimeout(proto::kSenderHttpTimeout);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply *reply =
        m_manager->post(request, QJsonDocument(toJson(PingRequest{m_cnonce, name}))
                                     .toJson(QJsonDocument::Compact));
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

    // 信任库里记的指纹与这次看到的不符。注意 deviceId 本身就是指纹的截断，
    // 所以这条只在截断前缀相同、后面不同时才可能触发——它是一道廉价的兜底，
    // 不是「设备换了密钥」的检测（那种情况会表现为一个全新的、未配对的 deviceId）。
    const QString deviceId = deviceIdFrom(*fingerprint);
    if (m_trust.identityChanged(deviceId, fingerprint->toHex())) {
        m_handshakeError =
            QStringLiteral("已配对设备的指纹与记录不符（%1）：请删除配对后重新配对")
                .arg(deviceId.left(8));
        return false;
    }

    m_peerFingerprint = *fingerprint;
    // 输入只有两个指纹与 cnonce，所以这一刻就能算出全部 12 位并显示本端那半，
    // 不必等响应（§4 配对：接收方在响应之前就要看到它）。
    m_code = sasCode(SasRole::Sender,
                     computeSas(m_identity.fingerprint(), m_peerFingerprint, m_cnonce));
    emit peerAdopted(m_code);
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

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray body = reply->readAll();

    // 先看 HTTP 状态，再看 QNAM 的网络错误：4xx/5xx 同时会把 reply->error() 置成
    // 对应的分类错误，若先看后者，对端给的那句可读原因就被 "Conflict" 这类词盖掉了。
    if (status != 200 || reply->error() != QNetworkReply::NoError) {
        result.error = status > 0
            ? QStringLiteral("对端返回 %1：%2")
                  .arg(status)
                  .arg(QString::fromUtf8(body).trimmed())
            : QStringLiteral("请求失败：%1").arg(reply->errorString());
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
    // 发送方取前半显示、要求输入后半——这一半在 peerAdopted 时就已经显示出去了。
    result.code = m_code;
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
