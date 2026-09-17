#pragma once

// SAS：两端各自算出、由用户比对的 12 位数字（§4 配对），拆成两半使用。
//
// 它不需要保密，只需要**不相等**。因此输入被刻意限制在两个来源：
//
//   - 两个指纹都取自各自在 TLS 握手里亲眼看到的证书，不取 TXT 的提示值，
//     也不取 /ping 响应里的 JSON 字段；
//   - cnonce 由发送方出，snonce 由接收方出，两个都走这条已握手的连接。
//
// 中间人必须分别与两端各建一条 TLS 连接、各出示一次自己的证书，于是两端算出的
// 输入必然不同，12 位数字也必然不同。
//
// —————————————— 为什么要拆成两半 ——————————————
//
// 中间人全程接管信道，四个输入它全知道，因此**它算得出两端各自的码**。它还能
// 自由替换两个 nonce（cnonce 是明文 URL 参数，snonce 是 JSON 字段，两者都没有
// 任何东西绑定到原始取值），于是在本机穷举 snonce 直到两端的 6 位码相同——
// 约 10^6 次哈希，毫秒级。用户再认真地比对也挡不住：两个屏幕显示的确实相同。
//
// 拆成两半之后（发送方显示前半、接收方显示后半，各自要求输入对方那一半）：
//
//   发送方的检查： 输入的 6 位 == 本端算出的后半
//   接收方的检查： 输入的 6 位 == 本端算出的前半
//
// 两端都通过 ⇔ 两端的 12 位完全相同，穷举成本从 10^6 抬到 10^12。
// 顺带带来两件事：两端各自机器比对，谁也不必相信对方「我比对过了」的自称；
// 以及「顺手输入自己屏幕上那串」这条捷径必然失败——两半只有在 10^-6 的概率下
// 偶然相同，量级与码本身的强度相同，不再另作处理。
//
// 单信道内能做到的极限就是这个：一端必须持有参照值、另一端必须提供它。要让
// 6 位码真正等于 6 位强度，只有把 SAS 绑到 TLS 会话密钥材料上（中间人每试一次
// 都得真做一次握手），而 Qt 不暴露那些材料（§4）。

#include "identity.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QMetaType>
#include <QString>

#include <optional>

namespace lanpipe {

// 谁在什么位置看这个码。同一个 SAS，两端的取用方式相反。
enum class SasRole {
    Sender,   // 显示前半，要求输入后半
    Receiver, // 显示后半，要求输入前半
};

struct SasCode
{
    QString shown; // 本端屏幕显示这 6 位，让对方念给它那一端
    QString asked; // 本端要求用户输入的 6 位——对方屏幕上显示的那串

    // 用户输入是否与对方屏幕上应当显示的一致。空白被忽略，允许「123 456」这种输入。
    [[nodiscard]] bool matches(const QString &input) const;
};

[[nodiscard]] QByteArray computeSas(const Fingerprint &senderFingerprint,
                                    const Fingerprint &receiverFingerprint,
                                    const QString &cnonce, const QString &snonce);

// 从 SAS 取出本端的两半。输入不是 SAS 的长度时返回两个空串。
[[nodiscard]] SasCode sasCode(SasRole role, const QByteArray &sas);

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
        SasCode code; // 接收方那一侧的两半：先显示 shown，稍后要求输入 asked
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

Q_DECLARE_METATYPE(lanpipe::SasCode)
