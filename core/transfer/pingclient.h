#pragma once

// 发送方的 /ping 调用（§4 配对第 1 步）。
//
// 它同时是发送方唯一的对端身份判定点：指纹取自这次握手，比对失败即放弃。
// 这与接收方从客户端证书重算 deviceId 是同一条规则的两面。
//
// 超时必须由本类显式设置（§5.9）：QNetworkRequest 的传输超时默认 30 秒，
// 与接收方的审批窗口精确相等，两边会同时到期。

#include "identity.h"
#include "ping.h"
#include "trust/truststore.h"

#include <QObject>
#include <QString>
#include <QUrl>

#include <optional>

class QNetworkAccessManager;
class QNetworkReply;
class QSslCertificate;

namespace lanpipe::transfer {

class PingClient : public QObject
{
    Q_OBJECT

public:
    struct Result
    {
        bool ok = false;
        QString error;               // ok 为假时的可读原因
        PingInfo info;               // ok 为真时对端的应答
        Fingerprint peerFingerprint; // 握手时亲眼看到的对端指纹
        // 本端的两半：显示 shown，要求用户输入对方屏幕上的 asked（§4 配对）。
        SasCode code;
    };

    // trust 的生命周期由调用方保证。配对成功后由本类的调用方写入信任库——
    // 「用户确认过」这个前提只有上层知道。
    explicit PingClient(trust::TrustStore &trust, QObject *parent = nullptr);

    // name 是本机设备名，随请求一起送过去：接收方的用户在被要求输入配对码之前，
    // 得先在屏幕上看到这是谁。
    //
    // expected 非空时要求对端指纹完全相等——配对完成后的常规路径（§4 规则 5），
    // 也是 --pin 走的非交互路径。为空时接受并在结果里回报观察到的指纹：
    // 首次配对的 TOFU，由用户比对码来兜底。
    void start(const QUrl &url, const Identity &identity, const QString &name,
               std::optional<Fingerprint> expected = std::nullopt);

signals:
    // 握手完成、对端指纹已核对。此刻本端那半就能显示出来了——响应还没到，
    // 而接收方那边正在等它的用户输入，所以这一半必须先出现在屏幕上。
    void peerAdopted(const lanpipe::SasCode &code);

    void finished(const lanpipe::transfer::PingClient::Result &result);

private:
    bool adoptPeer(const QSslCertificate &certificate);
    void onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);
    void onFinished(QNetworkReply *reply);
    void report(Result result);

    QNetworkAccessManager *m_manager = nullptr;
    trust::TrustStore &m_trust;
    Identity m_identity;
    std::optional<Fingerprint> m_expected;
    QString m_cnonce;
    Fingerprint m_peerFingerprint;
    QString m_handshakeError;
    SasCode m_code;
    bool m_reported = false;
};

} // namespace lanpipe::transfer

Q_DECLARE_METATYPE(lanpipe::transfer::PingClient::Result)
