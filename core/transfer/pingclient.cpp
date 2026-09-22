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
    : QObject(parent), m_manager(new QNetworkAccessManager(this)), m_trust(trust), m_pin(trust)
{
    qRegisterMetaType<PingClient::Result>();

    // 不跟随重定向：跳到另一个源就等于把请求交给没有做指纹比对的一方，
    // 而接收方本来也不会重定向。3xx 一律按失败处理。
    m_manager->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
}

void PingClient::start(const QUrl &url, const Identity &identity, const QString &name,
                       std::optional<Fingerprint> expected)
{
    // 上一轮可能还有 reply 在途（换地址时会直接再 start）：中止并作废它的代际，
    // 否则它的 finished 会带着旧结果覆盖这一轮的判定。
    ++m_generation;
    if (m_reply) {
        QNetworkReply *stale = m_reply;
        m_reply = nullptr;
        stale->abort();
    }

    m_identity = identity;
    m_pin.reset();
    m_pin.setExpected(std::move(expected));
    m_code = {};
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
    m_reply = reply;
    connect(reply, &QNetworkReply::sslErrors, this,
            [this, reply, generation = m_generation](const QList<QSslError> &errors) {
                onSslErrors(reply, errors, generation);
            });
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation = m_generation] {
        onFinished(reply, generation);
    });
}

void PingClient::announceOurHalf()
{
    if (!m_code.shown.isEmpty())
        return; // 已经报过

    // 参与量只有两个指纹与 cnonce，所以这一刻就能算出全部 12 位并显示本端那半，
    // 不必等响应（§4 配对：接收方在响应之前就要看到它）。
    m_code = sasCode(SasRole::Sender,
                     computeSas(m_identity.fingerprint(), m_pin.observed(), m_cnonce));
    emit peerAdopted(m_code);
}

void PingClient::onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors,
                             quint64 generation)
{
    if (generation != m_generation)
        return;
    m_pin.handleSslErrors(reply, errors);
    if (m_pin.accepted())
        announceOurHalf();
}

void PingClient::onFinished(QNetworkReply *reply, quint64 generation)
{
    reply->deleteLater();
    if (m_reply == reply)
        m_reply = nullptr;
    if (generation != m_generation)
        return; // start() 已经开了新一轮，这条是上一轮的残响

    Result result;

    // 握手期被拒（错误已记在 pin 里）或握手没触发 sslErrors 时的兜底判定。
    if (!m_pin.adoptFromReply(reply)) {
        result.error = m_pin.error();
        report(result);
        return;
    }
    announceOurHalf();

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

    const auto info = pingInfoFromJson(body);
    if (!info.has_value()) {
        result.error = info.error();
        report(result);
        return;
    }

    // 响应里的 fp 只用来核对：对端在 JSON 里写的和它握手出示的必须是同一把公钥。
    // 不一致说明对端有 bug 或有人在改包，两种都不该继续。
    if (info->fingerprint != m_pin.observed()) {
        result.error = QStringLiteral("响应里的指纹与握手所见不符：%1 vs %2")
                           .arg(info->fingerprint.shortForm(), m_pin.observed().shortForm());
        report(result);
        return;
    }

    result.ok = true;
    result.info = *info;
    result.peerFingerprint = m_pin.observed();
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
