#pragma once

// 双向 TLS 的配置与对端身份判定（§4 Transport）。
//
// 这套模型里证书不自证任何东西，指纹才自证。两端的证书都是自签的，谁签的不重要，
// 重要的是「握手里看到的那把公钥」是不是我们记住的那一把。由此推出三条规则，
// 本文件是它们的唯一落点：
//
//   1. Qt 的链校验必然失败（自签证书不在系统 CA 里），我们放行这一类的错误；
//      但只放行这一类——过期、用途不符、签名错误仍然拒绝。
//   2. 是否信任由指纹比对决定，比对失败即断连，绝不跳过检查。
//   3. 放行链校验错误**不等于**放行身份：证书裁定与身份判定是两步，顺序不能换。

#include "identity.h"

#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QString>

#include <expected>

namespace lanpipe::net {

// 两端的 TLS 配置。本项目不区分「服务器配置」与「客户端配置」：两端互为对端，
// 都必须出示自己的证书，也必须看到对方的证书。
//
// 注意 VerifyPeer 单独一项并不足以要求对端出示证书：Qt 6 里
// missingCertificateIsFatal() 默认为 false，缺证书只会产生一个可被忽略的
// NoPeerCertificate 错误。两者必须一起设置，缺证书才会成为握手期的硬失败。
[[nodiscard]] QSslConfiguration mtlsConfiguration(const Identity &identity);

// 不依赖链校验的那一类握手错误：自签证书、链不受信任、主机名不匹配。
// 名字在这套模型里不承载身份（§4）——证书里的 CN 固定是 "device"，
// 与 IP 形式的连接目标必然不匹配，这一类错误在这里没有意义。
[[nodiscard]] bool isPinnedTrustError(const QSslError &error);

// 从收到的错误里挑出可以放行的那些。
//
// 返回值短于入参就表示存在不能放行的错误，调用方必须放弃这次连接：
// ignoreSslErrors() 的语义是「收到的错误全部在这个列表里才继续」，
// 与其依赖这个语义，不如在调用处就把两种情况分开。
[[nodiscard]] QList<QSslError> toleratedHandshakeErrors(const QList<QSslError> &errors);

// 从握手错误里取出对端证书。Qt 在证书类错误上附带证书本身，这是 QNAM 客户端
// 在 sslErrors 阶段唯一可靠的证书来源——那时 QNetworkReply::sslConfiguration()
// 还停留在请求里带的那一份，不含对端证书。
//
// 取不到时返回空证书，调用方必须当作拒绝。
[[nodiscard]] QSslCertificate certificateFromErrors(const QList<QSslError> &errors);

// 对端证书 → 指纹。空证书或无法解析一律失败：这是 fail closed 的落点，
// 调用方没有任何「拿不到就跳过」的余地。
[[nodiscard]] std::expected<Fingerprint, QString> peerFingerprint(const QSslCertificate &certificate);

// 对端证书 → deviceId，用于与请求里声称的 deviceId 比对（§4）。
[[nodiscard]] std::expected<QString, QString> peerDeviceId(const QSslCertificate &certificate);

// 把错误列表拼成一行可读文本，写进日志。
[[nodiscard]] QString describeErrors(const QList<QSslError> &errors);

} // namespace lanpipe::net
