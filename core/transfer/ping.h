#pragma once

// /ping —— 配对握手（§4、§5）。
//
//   发送方  POST /api/v1/ping   { cnonce, name }
//   接收方  200 { deviceId, name, ver, fp, reachable }   —— 本端比对也通过
//           403                                       —— 本端比对未通过（或超时 504）
//
// 请求用 POST 而不是 GET：接收方的用户在被要求输入配对码之前，必须先在屏幕上看到
// 「这是谁」。查询串与请求头都承载不了 UTF-8 的设备名（§5.15 只接受可见 ASCII），
// 所以名字只能走 JSON 体。
//
// 两端各自算出 12 位码、各显示一半、各要求输入另一半，**一个往返内完成比对**：
//
//   1. 发送方先算好（它的输入在发请求之前就齐了），显示自己那半，发出请求；
//   2. 接收方算出自己那半并显示，等自己的用户输入发送方那半，比对；
//   3. 接收方把结论放进响应——200 表示它这边也通过了，403 表示没有。
//   4. 发送方收到 200 后，等自己的用户输入接收方那半，比对，写信任库。
//
// 两端都要有人在（kSasInputWindow），而且**接收方是在响应之前等输入**——这正是
// §4 里那个「只留一个 nonce」的原因：否则发送方在收到响应前算不出任何一半，双方
// 互等，成死锁。
//
// 这次比对只回答「这台设备是谁」。是否接受它这次要传的东西，仍由接收策略在 prepare
// 时另行决定（§4 接收策略）——两道门管的是两件事。
//
// 响应里的 fp 只是让发送方核对一下握手所见，**不是**信任锚：两端算 SAS 都用握手时
// 亲眼看到的证书（§4），谁也不读这个字段。

#include "http/httpconnection.h"
#include "identity.h"
#include "sas.h"
#include "settings.h"
#include "trust/truststore.h"

#include <QByteArray>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QTimer>

#include <expected>

namespace lanpipe::transfer {

// 发送方的 ping 请求体。
struct PingRequest
{
    QString cnonce;
    QString name; // 发送方的设备名，任意 UTF-8
};

[[nodiscard]] QJsonObject toJson(const PingRequest &request);

// 字段缺失或格式不对一律失败。对端是我们自己的实现，但它仍是一个不可信输入。
[[nodiscard]] std::expected<PingRequest, QString> pingRequestFromJson(const QByteArray &body);

struct PingInfo
{
    QString deviceId;
    QString name;
    int version = 0;
    Fingerprint fingerprint;
    bool reachable = true;
};

[[nodiscard]] QJsonObject toJson(const PingInfo &info);
[[nodiscard]] std::expected<PingInfo, QString> pingInfoFromJson(const QByteArray &body);

// 接收方的 /ping 处理。分两段：先请界面要用户输入，等答案，再回答请求。
//
// identity / settings / trust 的生命周期由调用方保证，本类只持有引用。
class PingService : public QObject
{
    Q_OBJECT

public:
    // 比对结果。界面据此给出不同的提示——「输错了」与「有人在中间」值得分开说。
    enum class Outcome {
        Accepted, // 两端算出的码一致，对端已写入信任库
        Mismatch, // 用户输入与本端算出的不符
        TimedOut, // 等用户输入超过了 kSasInputWindow
        Rejected, // 还没到输入那一步就被拒（身份与信任库不符、请求不合法等）
    };

    PingService(const Identity &identity, const Settings &settings, trust::TrustStore &trust,
                QObject *parent = nullptr);

    // 请求目标是否归本服务处理。目标必须与路径完全相等：cnonce 现在走请求体，
    // 路径上不该再有任何东西。
    [[nodiscard]] static bool handles(QByteArrayView target);

    void handle(http::HttpConnection &connection);

    // 界面把用户输入的那 6 位交回来。必须在 inputRequired 之后调用一次。
    void submitInput(const QString &typed);

    // 等用户输入的上限。只有测试会改它。
    void setInputWindow(std::chrono::milliseconds window);

signals:
    // 收到一条合法的 ping：界面显示 shown（本端那半）与对方的名字，
    // 并要求用户输入对方屏幕上显示的 asked。
    void inputRequired(const QString &peerDeviceId, const QString &peerName,
                       const lanpipe::SasCode &code);

    void pairingFinished(const QString &peerDeviceId,
                         lanpipe::transfer::PingService::Outcome outcome);

private:
    void onRequestComplete(http::HttpConnection &connection, const QByteArray &body);
    void finish(Outcome outcome, const QString &reason);

    const Identity &m_identity;
    const Settings &m_settings;
    trust::TrustStore &m_trust;

    // 一次只处理一条 ping：单请求连接模型下没有并发配对的需求，而「在等哪一条
    // 连接的用户输入」必须唯一，否则答案会落错地方。
    http::HttpConnection *m_pending = nullptr;
    SasCode m_code;
    PingInfo m_info;
    QString m_peerDeviceId;
    QString m_peerName;
    QTimer *m_inputTimer = nullptr;
};

} // namespace lanpipe::transfer

Q_DECLARE_METATYPE(lanpipe::transfer::PingService::Outcome)
