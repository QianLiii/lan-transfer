#include "mtls.h"

#include <QSslSocket>
#include <QStringList>

namespace lanpipe::net {

QSslConfiguration mtlsConfiguration(const Identity &identity)
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();

    configuration.setLocalCertificate(identity.certificate());
    configuration.setPrivateKey(identity.privateKey());

    // §4：TLS 1.2 起。
    configuration.setProtocol(QSsl::TlsV1_2OrLater);

    // 要求对端出示证书。这两行必须成对出现，理由见头文件。
    configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    configuration.setMissingCertificateIsFatal(true);

    return configuration;
}

bool isPinnedTrustError(const QSslError &error)
{
    switch (error.error()) {
    case QSslError::SelfSignedCertificate:
    case QSslError::SelfSignedCertificateInChain:
    case QSslError::CertificateUntrusted:
        // 链不受系统 CA 信任。本协议不看 CA：两端都是自签的，信任来自指纹。
        return true;
    case QSslError::HostNameMismatch:
        // 名字不承载身份（§4），身份只由指纹承载。
        return true;
    default:
        // 过期、用途不符、签名错误、缺证书……一律不放行。
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

std::expected<QString, QString> peerDeviceId(const QSslCertificate &certificate)
{
    const auto fingerprint = peerFingerprint(certificate);
    if (!fingerprint.has_value())
        return std::unexpected(fingerprint.error());
    return deviceIdFrom(*fingerprint);
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
