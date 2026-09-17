#pragma once

// /ping —— 配对握手的第一个往返（§4、§5）。
//
//   发送方  GET /api/v1/ping?cnonce=<hex>
//   接收方  200 { deviceId, name, ver, fp, snonce, reachable }
//
// 两个 nonce 在这一来一回里凑齐，SAS 随即定下并缓存到接收方的 deviceId 上。
// 响应里的 fp 只是让发送方核对一下握手所见，**不是**信任锚：两端算 SAS 都用
// 握手时亲眼看到的证书（§4），谁也不读这个字段。

#include "http/httpconnection.h"
#include "identity.h"
#include "sas.h"
#include "settings.h"

#include <QByteArray>
#include <QJsonObject>
#include <QObject>
#include <QString>

#include <expected>

namespace lanpipe::transfer {

struct PingInfo
{
    QString deviceId;
    QString name;
    int version = 0;
    Fingerprint fingerprint;
    QString snonce;
    bool reachable = true;
};

[[nodiscard]] QJsonObject toJson(const PingInfo &info);

// 字段缺失或格式不对一律失败。对端是我们自己的实现，但它仍是一个不可信输入。
[[nodiscard]] std::expected<PingInfo, QString> pingInfoFromJson(const QByteArray &body);

// 从请求目标里取出 cnonce。只接受我们自己会发出的那一种形态——等长的十六进制，
// 不做百分号解码，也不接受额外参数（§5.15）。
[[nodiscard]] std::expected<QString, QString> cnonceFromTarget(QByteArrayView target);

// 接收方的 /ping 处理。
//
// identity / settings / sasCache 的生命周期由调用方保证，本类只持有引用。
class PingService : public QObject
{
    Q_OBJECT

public:
    PingService(const Identity &identity, const Settings &settings, SasCache &sasCache,
                QObject *parent = nullptr);

    // 请求目标是否归本服务处理。路径的写法只在这里出现一次，调用方按它分发。
    [[nodiscard]] static bool handles(QByteArrayView target);

    void handle(http::HttpConnection &connection);

signals:
    // 码已在接收方这一侧定下。界面据此显示 shown，稍后（prepare 的审批框里）要求
    // 用户输入 asked——那是发送方屏幕上显示的那一半（§4 规则 3）。
    void codeSettled(const QString &peerDeviceId, const lanpipe::SasCode &code);

private:
    const Identity &m_identity;
    const Settings &m_settings;
    SasCache &m_sasCache;
};

} // namespace lanpipe::transfer
