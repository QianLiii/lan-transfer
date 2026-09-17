#pragma once

// SAS (Short Authentication String) ：两端各自算出、由用户比对的 6 位数字（§4 配对）。
//
// 它不需要保密，只需要**不相等**。因此输入被刻意限制在两个来源：
//
//   - 两个指纹都取自各自在 TLS 握手里亲眼看到的证书，不取 TXT 的提示值，
//     也不取 /ping 响应里的 JSON 字段；
//   - cnonce 由发送方出，snonce 由接收方出，两个都走这条已握手的连接。
//
// 中间人必须分别与两端各建一条 TLS 连接、各出示一次自己的证书，于是两端算出的
// 输入必然不同，码也必然不同——用户一比就能看出来。
//
// 参数顺序固定为「发送方指纹在前、接收方指纹在后」，两端必须一致。

#include "identity.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QString>

#include <optional>

namespace lanpipe {

[[nodiscard]] QByteArray computeSas(const Fingerprint &senderFingerprint,
                                    const Fingerprint &receiverFingerprint,
                                    const QString &cnonce, const QString &snonce);

// 6 位数字，前导零保留。输入不是 SAS 的长度时返回空串。
[[nodiscard]] QString sasCode(const QByteArray &sas);

// 每个对端一份的 SAS 缓存（§4 规则 3）。
//
// 为什么必须缓存：每条连接只处理一个请求（§5.15），prepare 到达的是另一条连接，
// 那时发送方拿不到接收方的新 snonce。所以码在 /ping 那一刻就定下并缓存，
// prepare 只读它。若改成在 prepare 时才算，接收方就得先产出 snonce 才能显示码，
// 而用户必须在回答 prepare 之前看到码——闭环，死锁。
class SasCache
{
public:
    struct Entry
    {
        QString code;
        Fingerprint peerFingerprint;
        QDateTime settledAt;
    };

    void store(const QString &peerDeviceId, Entry entry);

    // 超过 kSasLifetime 的条目视为不存在。
    [[nodiscard]] std::optional<Entry> lookup(
        const QString &peerDeviceId,
        const QDateTime &now = QDateTime::currentDateTimeUtc()) const;

    void clear() { m_entries.clear(); }
    [[nodiscard]] qsizetype size() const { return m_entries.size(); }

private:
    QHash<QString, Entry> m_entries;
};

} // namespace lanpipe
