#include "peerpinning.h"

#include "mtls.h"

#include <QNetworkReply>
#include <QSslCertificate>
#include <QSslConfiguration>

#include <utility>

namespace lanpipe::transfer {

PeerPin::PeerPin(trust::TrustStore &trust) : m_trust(trust)
{
}

void PeerPin::reset()
{
    m_observed = {};
    m_error.clear();
}

bool PeerPin::adopt(const QSslCertificate &certificate)
{
    const auto fingerprint = net::peerFingerprint(certificate);
    if (!fingerprint.has_value()) {
        m_error = fingerprint.error();
        return false;
    }

    if (m_expected.has_value() && *fingerprint != *m_expected) {
        m_error = QStringLiteral("对端指纹与预期不符：观察到 %1，预期 %2")
                      .arg(fingerprint->shortForm(), m_expected->shortForm());
        return false;
    }

    // 一次传输要建好几条连接。中途换了证书，就是有人在替换信道。
    if (m_observed.isValid() && m_observed != *fingerprint) {
        m_error = QStringLiteral("同一次传输里对端指纹变了：%1 → %2")
                      .arg(m_observed.shortForm(), fingerprint->shortForm());
        return false;
    }

    const QString deviceId = deviceIdFrom(*fingerprint);

    // 发送方额外要求：对端必须已经被认下来。传输没有比对码兜底，凭据只有两样——
    // 信任库里的记录，或调用方用 --pin 直接给的指纹（后者更强，也更明确）。
    if (m_requirePaired && !m_expected.has_value() && !m_trust.contains(deviceId)) {
        m_error = QStringLiteral("这台设备（%1）尚未配对，不能接收文件：先 lanpipe pair 一次")
                      .arg(deviceId.left(8));
        return false;
    }

    // 已配对但指纹与记录不符：拒绝。注意 deviceId 本身就是指纹的截断，所以这条只在
    // 截断前缀相同、后面不同时才可能触发——它是廉价兜底，不是密钥轮换检测。
    if (m_trust.identityChanged(deviceId, fingerprint->toHex())) {
        m_error = QStringLiteral("已配对设备的指纹与记录不符（%1）：请删除配对后重新配对")
                      .arg(deviceId.left(8));
        return false;
    }

    m_observed = *fingerprint;
    return true;
}

void PeerPin::handleSslErrors(QNetworkReply *reply, const QList<QSslError> &errors)
{
    const QList<QSslError> tolerated = net::toleratedHandshakeErrors(errors);
    if (tolerated.size() != errors.size()) {
        m_error = QStringLiteral("TLS 握手被拒绝：%1").arg(net::describeErrors(errors));
        reply->abort();
        return;
    }

    // 证书取自错误本身：此刻 reply->sslConfiguration() 还停留在请求里带的那一份，
    // 不含对端证书。判定失败即 abort——绝不放行一个没通过指纹比对的对端。
    if (!adopt(net::certificateFromErrors(errors))) {
        reply->abort();
        return;
    }

    reply->ignoreSslErrors(tolerated);
}

bool PeerPin::adoptFromReply(QNetworkReply *reply)
{
    if (!m_error.isEmpty())
        return false;
    if (m_observed.isValid())
        return true; // 握手期已经判定过了
    return adopt(reply->sslConfiguration().peerCertificate());
}

} // namespace lanpipe::transfer
