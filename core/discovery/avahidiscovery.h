#pragma once

// Linux 的系统 DNS-SD 后端：Avahi，走它自己的 D-Bus 接口（§3.6）。
//
// 为什么不链 libavahi-client：那样要多一个构建依赖和一份打包负担，而失败模式完全
// 一样——两者都要求 avahi-daemon 在跑。走 D-Bus 只用到 QtDBus 与它稳定的公开接口。
//
// 系统守护进程替我们做的事（§3.6）：探测名字冲突、接口变化、休眠唤醒、TTL 刷新、
// 道别包、按接口分别处理。这些正是 mjansson/mdns 那条路要自己重写的部分。
//
// 只在 Linux 上编译。Windows 走 Windows.Networking.ServiceDiscovery.Dnssd，
// macOS 走 Network.framework。

#ifndef LANPIPE_HAVE_AVAHI
#  error "avahidiscovery.h 只在启用了 Avahi 后端（Linux + QtDBus）时编译；其它平台用 windnssddiscovery 或 broadcastdiscovery"
#endif

#include "discovery.h"
#include "protocol.h"

#include <QDBusConnection>
#include <QHash>
#include <QString>
#include <QTimer>

#include <chrono>

namespace lanpipe::discovery {

class AvahiDiscovery : public Discovery
{
    Q_OBJECT

public:
    struct Config
    {
        Advertisement self;
        // 是否对外注册。发送方只找人不被找，没有在监听，注册出去只会让别人
        // 连到一个不存在的端口。
        bool announce = true;
        // mDNS 实例名。留空时由设备名与 deviceId 前缀拼出。
        QString instanceName;
        std::chrono::milliseconds refresh = proto::kPeerRefreshInterval;
    };

    explicit AvahiDiscovery(Config config, QObject *parent = nullptr);
    ~AvahiDiscovery() override;

    void start() override;
    void stop() override;
    [[nodiscard]] QString backendName() const override { return QStringLiteral("avahi"); }

    // 最近一次失败的原因，供诊断导出（§3.6）。成功时为空。
    [[nodiscard]] QString lastError() const override { return m_lastError; }

    // 系统总线上有没有 Avahi。没有就退回 UDP 广播（§3.6）。
    [[nodiscard]] static bool isAvailable();

private Q_SLOTS:
    void onItemNew(int interface, int protocol, const QString &name, const QString &type,
                   const QString &domain, uint flags);
    void onItemRemove(int interface, int protocol, const QString &name, const QString &type,
                      const QString &domain, uint flags);

private:
    // 一条已解析出来的服务。key 是「实例名 + 接口 + 协议」——同一个服务在每个接口、
    // 每种地址族上各算一条，这正好是 PeerDirectory 要的地址集合（§3.3）。
    struct Resolved
    {
        Announcement announcement;
    };

    void refresh();
    void registerService();
    void browse();
    void fail(const QString &reason);

    [[nodiscard]] QDBusConnection bus() { return QDBusConnection::systemBus(); }
    [[nodiscard]] static QString subscribeKey(const QString &name, int interface, int protocol);

    Config m_config;
    QString m_entryGroupPath; // 注册用；空表示没注册
    QString m_browserPath;    // 浏览用；空表示没浏览
    QHash<QString, Resolved> m_resolved;
    QTimer *m_refreshTimer = nullptr;
    QString m_lastError;
    bool m_started = false;
};

} // namespace lanpipe::discovery
