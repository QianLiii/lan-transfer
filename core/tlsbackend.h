#pragma once

// 把 TLS 后端固定为 OpenSSL（§2.5）。
//
// 为什么必须固定，而不是用 Qt 的默认选择：
//
//   Qt 在运行时 dlopen OpenSSL，取不到就落到平台原生后端——Windows 落 Schannel，
//   Apple 落 SecureTransport，再不行只剩 cert-only（无法握手）。这两个原生后端在
//   证书校验能力上与 OpenSSL 有实质差异：
//
//     - Schannel 无法实现 QueryPeer（可选客户端证书），源码注释明确说明；
//     - SecureTransport 的 supportedFeatures() 只上报客户端侧 ALPN，不含证书校验，
//       并且它会把手上的自签证书与私钥导入系统 keychain 并可能弹授权框。
//
//   本项目用双向 TLS 承载设备身份（§4），后端随平台漂移会让「同样的代码在不同机器上
//   校验行为不同」——这是最难定位的一类问题。因此统一到一个后端。
//
// 另一个独立理由：Qt 没有任何生成密钥对或自签证书的公共 API（整个 qtbase 里
// EVP_PKEY_keygen / X509_new / X509_sign 命中数为零），证书必须由 OpenSSL 生成，
// 所以 OpenSSL 本就是各平台的显式依赖，不是可选项。

#include <QString>

namespace lanpipe {

// 强制启用 OpenSSL 后端。
//
// 必须在任何 SSL 类（QSslSocket、QSslCertificate、QSslKey、QSslConfiguration）
// 被使用之前调用一次；Qt 不支持在同一进程内混用多个 TLS 后端。
//
// 成功返回空字符串。失败返回可直接展示给用户的错误文本——典型原因是缺少 OpenSSL
// 运行库（Android 上必须随 APK 打包，见 §7），或该 Qt 构建没有 openssl 后端插件。
[[nodiscard]] QString forceOpenSslBackend();

// 当前生效的后端名（如 "openssl"）。未初始化或没有可用后端时返回空字符串。
// 供日志与诊断导出使用；诊断包是出问题时唯一的支持通道（§3.6）。
//
// 只应在 forceOpenSslBackend() 成功之后调用：Qt 没有只读查询接口，
// activeBackend() 在名字为空时会写入平台默认值，提前调用会让诊断输出
// 短暂显示错误的后端名。
[[nodiscard]] QString activeBackendName();

} // namespace lanpipe
