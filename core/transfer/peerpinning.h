#pragma once

// 发送方判定「这条连接的对端是谁」的唯一一处（§4 Transport）。
//
// 配对与发送共用它：两边都要在握手期放行自签证书、把对端证书从错误里取出来、
// 与预期指纹比对、查信任库有没有换过密钥，然后才放行。抄成两份的那一天，其中
// 一份迟早会漏掉一步——而漏掉时不会报错。
//
// 发送方比配对多一条：一次传输要建好几条连接，而**每一条**都要重新判定。

#include "identity.h"
#include "trust/truststore.h"

#include <QString>

#include <optional>

class QNetworkReply;
class QSslCertificate;
class QSslError;

namespace lanpipe::transfer {

class PeerPin
{
public:
    explicit PeerPin(trust::TrustStore &trust);

    // expected 非空时要求对端指纹完全相等——配对完成后的常规路径，也是 --pin 走的
    // 非交互路径。为空时接受并在 observed() 里回报观察到的指纹，由用户比对码兜底。
    void setExpected(std::optional<Fingerprint> expected) { m_expected = std::move(expected); }

    // 要求对端已经在信任库里。发送走这条：传文件不是配对，没有比对码兜底，
    // 只有「已经配过对」这一个前提（配对流程本身当然不设它）。
    void setRequirePaired(bool required) { m_requirePaired = required; }

    // 握手期的裁定。返回后 reply 要么已被放行，要么已被 abort。
    void handleSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);

    // 完成期的兜底判定：握手没触发 sslErrors 时，对端证书只能在这里拿到。
    // 返回 false 表示这条连接不能继续，原因在 error()。
    [[nodiscard]] bool adoptFromReply(QNetworkReply *reply);

    [[nodiscard]] bool accepted() const { return m_observed.isValid(); }
    [[nodiscard]] const Fingerprint &observed() const { return m_observed; }
    [[nodiscard]] const QString &error() const { return m_error; }

    // 换一次配对/传输时清空观察结果。
    void reset();

private:
    [[nodiscard]] bool adopt(const QSslCertificate &certificate);

    trust::TrustStore &m_trust;
    std::optional<Fingerprint> m_expected;
    bool m_requirePaired = false;
    Fingerprint m_observed;
    QString m_error;
};

} // namespace lanpipe::transfer
