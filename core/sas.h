#pragma once

// SAS：两端各自算出、由用户比对的 12 位数字（§4 配对），拆成两半使用。
//
// 它不需要保密，只需要**不相等**。输入只有三项，两个指纹 + 一个 nonce：
//
//   - 两个指纹都取自各自在 TLS 握手里亲眼看到的证书，不取 TXT 的提示值，
//     也不取 /ping 响应里的 JSON 字段；
//   - cnonce 由发送方出，随 ping 请求交给接收方。
//
// 中间人必须分别与两端各建一条 TLS 连接、各出示一次自己的证书，于是两端算出的
// 输入必然不同（差在两个真实指纹上），12 位数字也必然不同。
//
// 为什么只有一个 nonce。曾经是两端各出一个，但那样**发送方在收到响应之前算不出
// 任何一半**，而接收方要输入的是发送方显示的那半——「接收方等发送方显示、发送方等
// 接收方响应、接收方又等自己的用户输入」形成死锁。去掉它之后，两端在请求发出前后
// 就能各自算出全部 12 位，一个往返内完成比对，接收方的结论还能随响应回去。
//
// 安全性不变：让两端不同的那个量是 `fp_A` 与 `fp_B`，nonce 不含其中；中间人本来
// 就控制转发路径上的 nonce（它可自由替换 cnonce），穷举成本仍是 10^12。
//
// —————————————— 为什么要拆成两半 ——————————————
//
// 中间人全程接管信道，全部输入它都知道，因此**它算得出两端各自的码**。它还能
// 自由替换转发路径上的 cnonce（那是明文 JSON 字段，没有任何东西绑定它的原始取值），
// 于是在本机穷举 cnonce 直到两端的 6 位码相同——约 10^6 次哈希，毫秒级。
// 用户再认真地比对也挡不住：两个屏幕显示的确实相同。
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
#include <QMetaType>
#include <QString>


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
                                    const QString &cnonce);

// 从 SAS 取出本端的两半。输入不是 SAS 的长度时返回两个空串。
[[nodiscard]] SasCode sasCode(SasRole role, const QByteArray &sas);

} // namespace lanpipe

Q_DECLARE_METATYPE(lanpipe::SasCode)
