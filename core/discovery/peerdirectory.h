#pragma once

// 对端目录（§3.3）：所有发现后端的结果在这里合流。
//
// 只有这里做三件事：
//
//   1. 按 deviceId 去重，并把来自不同后端、不同接口的通告合并成**一组地址**。
//      一台机器同时有 Wi-Fi、有线、VPN 和 docker 网桥时会出现在多个地址上，
//      连错一个要等 30–75 秒的 SYN 重试才能回退（§3.3）。
//      deviceId 由通告里的指纹现算（`Advertisement::deviceId()`），不是传输字段——
//      目录里因此没有「记录的两个字段互相矛盾」这种状态。
//   2. 每个地址记 lastSeen，最近还活着的排在最前，连接时依次尝试。
//   3. 超时未再听到即视为掉线，界面据此表达「当前不可达」（§1.2 第 58 行那条）。
//
// 目录不做信任判断：TXT 里的 fp 只是提示，是否配对、是否放行由信任库与策略决定（§4）。

#include "discovery.h"

#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>
#include <QTimer>

#include <chrono>
#include <optional>

namespace lanpipe::discovery {

class PeerDirectory : public QObject
{
    Q_OBJECT

public:
    // 一个可尝试的连接目标。
    struct Address
    {
        QHostAddress address;
        quint16 port = 0;
        QDateTime lastSeen;

        friend bool operator==(const Address &a, const Address &b)
        {
            return a.address == b.address && a.port == b.port;
        }
    };

    struct Peer
    {
        QString deviceId;
        QString name;
        QString fingerprint; // 提示值，永不作为信任锚（§3.2）
        int version = 0;
        QDateTime lastSeen;
        QList<Address> addresses; // 按 lastSeen 降序
    };

    explicit PeerDirectory(QObject *parent = nullptr);

    // 订阅一个后端。可以接多个，同一个对端会被合并（§3.3）。
    void addSource(Discovery *source);

    // lastSeen 降序；同一时刻的按 deviceId 排，保证顺序稳定。
    [[nodiscard]] QList<Peer> peers() const;
    [[nodiscard]] std::optional<Peer> peer(const QString &deviceId) const;

    // 多久没再听到就算掉线。
    void setExpiry(std::chrono::milliseconds expiry);
    [[nodiscard]] std::chrono::milliseconds expiry() const { return m_expiry; }

    // 清掉超期条目。生产由内部计时器驱动，测试直接调用以指定时刻。
    void prune(const QDateTime &now = QDateTime::currentDateTimeUtc());

signals:
    void peerAdded(const QString &deviceId);
    void peerUpdated(const QString &deviceId);
    void peerRemoved(const QString &deviceId);

private:
    void apply(const Announcement &announcement);

    QHash<QString, Peer> m_peers;
    std::chrono::milliseconds m_expiry;
    QTimer *m_sweep = nullptr;
};

} // namespace lanpipe::discovery
