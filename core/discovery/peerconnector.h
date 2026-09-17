#pragma once

// 依次尝试一个对端的多个地址（§3.3）。
//
// 一台机器同时有 Wi-Fi、有线、VPN 和 docker 网桥时，同一个 deviceId 下会有多个地址，
// 而连错一个要等 30–75 秒的 SYN 重试。所以：按最近见到过的顺序逐个试，每个地址给一个
// 短时限，失败就换下一个；全部试完才回到重新查询服务发现，最后才是手工输入地址（§3.6）。
//
// 它只管「下一个该试哪个、什么时候放弃」，不碰网络——调用方拿到地址后自己发起请求，
// 再回告结果。这样它既包得住 ping，也包得住 M3 的其它请求，而且可以单独测。
//
// 时限只覆盖**建立连接**那一段：ping 的响应要等接收方的用户输码（可达两分钟），
// 用同一个时限会把合法连接当成死地址。所以握手一完成就调用 connected()。

#include "peerdirectory.h"

#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <chrono>
#include <optional>

namespace lanpipe::discovery {

class PeerConnector : public QObject
{
    Q_OBJECT

public:
    struct Target
    {
        QHostAddress address;
        quint16 port = 0;
    };

    PeerConnector(const QList<PeerDirectory::Address> &addresses,
                  std::chrono::milliseconds perAddressTimeout, QObject *parent = nullptr);

    // 取下一个地址并开始计时。地址已用完时返回 nullopt，此后不再有信号。
    [[nodiscard]] std::optional<Target> startNext();

    // 连接已建立（握手完成）：撤掉时限，本次尝试不再受它约束。
    void connected();

    // 这个地址可用，收工。
    void succeeded();

    // 这个地址不可用（reason 进诊断），调用方接着 startNext()。
    void failed(const QString &reason);

    [[nodiscard]] int triedCount() const { return m_tried; }
    [[nodiscard]] bool exhausted() const { return m_index >= m_addresses.size(); }

    // 「试过哪些地址、各自为什么不行」，拼成一行给用户看（§3.6 的三种失败要能分开）。
    [[nodiscard]] QString failureSummary() const;

signals:
    // 当前地址用满了时限。调用方应当放弃在途的尝试，然后 startNext()。
    void attemptTimedOut();

private:
    void recordFailure(const QString &reason);

    QList<PeerDirectory::Address> m_addresses;
    std::chrono::milliseconds m_perAddressTimeout;
    QTimer *m_timer = nullptr;
    std::optional<PeerDirectory::Address> m_current;
    qsizetype m_index = 0;
    int m_tried = 0;
    QStringList m_failures;
};

} // namespace lanpipe::discovery
