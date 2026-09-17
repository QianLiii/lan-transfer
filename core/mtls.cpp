#include "mtls.h"

#include <QSslSocket>
#include <QStringList>

namespace lanpipe::net {

QSslConfiguration mtlsConfiguration(const QSslCertificate &certificate, const QSslKey &privateKey)
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();

    configuration.setLocalCertificate(certificate);
    configuration.setPrivateKey(privateKey);

    // §4：TLS 1.2 起。
    configuration.setProtocol(QSsl::TlsV1_2OrLater);

    // 要求对端出示证书。这两行必须成对出现，理由见头文件。
    configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    configuration.setMissingCertificateIsFatal(true);

    return configuration;
}

QSslConfiguration mtlsConfiguration(const Identity &identity)
{
    return mtlsConfiguration(identity.certificate(), identity.privateKey());
}

bool isPinnedTrustError(const QSslError &error)
{
    // 判据：**本协议的信任模型不使用这个概念**的错误放行；**证书内容本身不可信
    // 或不可解析**的错误拒绝。前者是我们主动放弃的 PKI 判断，后者是在说这把公钥
    // 有问题——而公钥正是我们唯一使用的东西。
    switch (error.error()) {
    case QSslError::SelfSignedCertificate:
    case QSslError::SelfSignedCertificateInChain:
    case QSslError::CertificateUntrusted:
        // 链不受系统 CA 信任。本协议不看 CA：两端都是自签的，信任来自指纹。
        return true;
    case QSslError::HostNameMismatch:
        // 名字不承载身份（§4），身份只由指纹承载。
        return true;
    case QSslError::CertificateExpired:
    case QSslError::CertificateNotYetValid:
    case QSslError::InvalidNotBeforeField:
    case QSslError::InvalidNotAfterField:
        // 有效期同样不承载身份。放行它换来的是：对端时钟偏差或久未运行时仍然
        // 连得上，而固定检查这道真正的门不受影响——它比对的还是那把公钥。
        // 反过来，拒绝有效期并不能防住私钥泄露（窃贼用同一把公钥重签一张新日期
        // 的证书即可，指纹不变），所以这份严格性本来就是空的。
        return true;
    default:
        // 其余一律不放行：签名验证失败、公钥不可解析、缺证书、黑名单……它们说的
        // 都是「这把公钥不可信」，正是我们必须拒绝的那一类。未知错误落到这里也是
        // 拒绝——新增的错误码默认 fail closed。
        return false;
    }
}

QList<QSslError> toleratedHandshakeErrors(const QList<QSslError> &errors)
{
    QList<QSslError> tolerated;
    tolerated.reserve(errors.size());
    for (const QSslError &error : errors) {
        if (isPinnedTrustError(error))
            tolerated.append(error);
    }
    return tolerated;
}

QSslCertificate certificateFromErrors(const QList<QSslError> &errors)
{
    for (const QSslError &error : errors) {
        const QSslCertificate certificate = error.certificate();
        if (!certificate.isNull())
            return certificate;
    }
    // QSslCertificate 的构造函数是 explicit，不能写 return {}。
    return QSslCertificate();
}

std::expected<Fingerprint, QString> peerFingerprint(const QSslCertificate &certificate)
{
    if (certificate.isNull())
        return std::unexpected(QStringLiteral("对端没有出示证书"));

    const Fingerprint fingerprint = Fingerprint::fromCertificate(certificate);
    if (!fingerprint.isValid())
        return std::unexpected(QStringLiteral("无法从对端证书解析出公钥"));

    return fingerprint;
}

std::expected<PeerIdentity, QString> peerIdentity(const QSslCertificate &certificate)
{
    const auto fingerprint = peerFingerprint(certificate);
    if (!fingerprint.has_value())
        return std::unexpected(fingerprint.error());
    return PeerIdentity{*fingerprint, deviceIdFrom(*fingerprint)};
}

QString describeErrors(const QList<QSslError> &errors)
{
    QStringList parts;
    parts.reserve(errors.size());
    for (const QSslError &error : errors)
        parts.append(error.errorString());
    return parts.join(QStringLiteral("；"));
}

} // namespace lanpipe::net
