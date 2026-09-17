#pragma once

// 设备身份（§4）。
//
// 身份由一对密钥决定，与证书分离：指纹是 SubjectPublicKeyInfo 的 SHA-256，
// 不是证书的哈希。因此证书到期重签不改变设备身份，已有配对也不会断。

#include "protocol.h"

#include <QByteArray>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>

#include <expected>
#include <optional>

namespace lanpipe {

// SPKI 的 SHA-256，32 字节。
class Fingerprint
{
public:
    Fingerprint() = default;

    // 从证书的 SubjectPublicKeyInfo 计算。对端证书走同一条路——
    // SAS 与指纹固定都依赖它（§4），所以本端和对端必须是同一个算法。
    [[nodiscard]] static Fingerprint fromCertificate(const QSslCertificate &certificate);
    [[nodiscard]] static std::optional<Fingerprint> fromHex(const QString &hex);

    [[nodiscard]] bool isValid() const { return m_bytes.size() == 32; }
    [[nodiscard]] const QByteArray &bytes() const { return m_bytes; }
    [[nodiscard]] QString toHex() const;
    // 展示用的短形式（前 8 字节）。
    [[nodiscard]] QString shortForm() const;

    friend bool operator==(const Fingerprint &, const Fingerprint &) = default;

private:
    QByteArray m_bytes;
};

// deviceId：指纹的截断形式，用于 TXT 与请求体（§3.2）。
// 长度常量在 protocol.h，那里是它被引用的地方（TXT 的 id 字段、/ping 的响应）。
[[nodiscard]] QString deviceIdFrom(const Fingerprint &fingerprint);

class Identity
{
public:
    // 从 dir 加载；缺失的部件就地生成。成功返回身份，失败返回可读的错误文本。
    Identity() = default;

    [[nodiscard]] static std::expected<Identity, QString> loadOrCreate(const QString &dir);

    // 默认目录：QStandardPaths::AppDataLocation 下的 identity/（§1.2 第 5 条）。
    [[nodiscard]] static QString defaultDir();

    [[nodiscard]] const QSslCertificate &certificate() const { return m_certificate; }
    [[nodiscard]] const QSslKey &privateKey() const { return m_privateKey; }
    [[nodiscard]] const Fingerprint &fingerprint() const { return m_fingerprint; }
    [[nodiscard]] QString deviceId() const { return deviceIdFrom(m_fingerprint); }

private:
    QSslCertificate m_certificate;
    QSslKey m_privateKey;
    Fingerprint m_fingerprint;
};

} // namespace lanpipe
