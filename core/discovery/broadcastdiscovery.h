#pragma once

// UDP 广播兜底（§3.4）。
//
// 它的存在理由是「组播被过滤的网络里 mDNS 什么都收不到，而广播往往还能过」。
// 这句话是**待验证的假设**，不是设计前提——M2 要在两台真机上验。
//
// 载荷字段与 TXT 一致并额外带端口；地址不进载荷——收包时的来源地址才是被证明
// 可用的那一个，多网卡机器也因此自然地被拆成一组地址（§3.3）。
//
// 自己发的广播会回环到本机，因此按 deviceId 过滤掉自己的通告。
//
// IPv6 政策：广播只有 IPv4。IPv6 的对应物是组播，留给 DNS-SD 后端（§3.7）。

#include "discovery.h"
#include "protocol.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QHostAddress>
#include <QUdpSocket>

#include <chrono>
#include <expected>

class QTimer;

namespace lanpipe::discovery {

// 通告载荷的上限。实际载荷约 150 字节，留足余量同时挡住灌包。
inline constexpr int kMaxAnnouncementSize = 1024;

// 载荷编解码。脱离 socket 单独暴露，便于直接测。
[[nodiscard]] QByteArray encodeAdvertisement(const Advertisement &advertisement);
[[nodiscard]] std::expected<Advertisement, QString> decodeAdvertisement(QByteArrayView datagram);

class BroadcastDiscovery : public Discovery
{
    Q_OBJECT

public:
    struct Config
    {
        // 本机对外通告的内容。deviceId 同时用于过滤自己发出的广播。
        Advertisement self;

        // 是否对外通告。发送方只找人不被找——它没有在监听，通告出去也没有意义，
        // 反而会让别人连到一个不存在的端口。关掉之后只收不发。
        bool announce = true;

        QHostAddress bindAddress = QHostAddress::AnyIPv4;
        quint16 bindPort = proto::kBroadcastPort; // 0 表示由系统分配，与 bind() 的语义一致

        // 发送端口。0 表示与 bindPort 相同——生产上两者总是相同（§3.4），
        // 分开是为了让发送路径能在测试里被单独观察（同端口上按 SO_REUSEADDR
        // 绑两个 socket 时，单播报文只会投递给其中一个）。
        quint16 sendPort = 0;

        // 目标地址。空表示由各接口的子网广播地址推导。
        QList<QHostAddress> targets;

        std::chrono::milliseconds interval = proto::kBroadcastInterval;
        std::chrono::milliseconds jitter = proto::kBroadcastJitter;
    };

    explicit BroadcastDiscovery(Config config, QObject *parent = nullptr);

    void start() override;
    void stop() override;
    [[nodiscard]] QString backendName() const override;

    // 实际绑定到的端口。配置里写 0 时这里是系统分配的那个。
    [[nodiscard]] quint16 boundPort() const;

    // 最近一次发送或绑定的失败原因，供诊断导出（§3.6）。成功时为空。
    [[nodiscard]] QString lastError() const { return m_lastError; }

    // 本次通告实际会发往的地址。诊断用，也是「广播到底出去了没有」的唯一直接证据。
    [[nodiscard]] QList<QHostAddress> currentTargets() const { return targets(); }

private:
    void onReadyRead();
    void sendAdvertisement();
    [[nodiscard]] QList<QHostAddress> targets() const;

    Config m_config;
    QUdpSocket *m_socket = nullptr;
    QTimer *m_timer = nullptr;
    QString m_lastError;
};

} // namespace lanpipe::discovery
