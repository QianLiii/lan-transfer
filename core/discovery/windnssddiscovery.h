#pragma once

// Windows 的系统 DNS-SD 后端（§3.6）。
//
// 走 Win32 的 DNS-SD API（`windns.h`：DnsServiceRegister / DnsServiceBrowse /
// DnsServiceResolve），**不是** WinRT 的 `Windows.Networking.ServiceDiscovery.Dnssd`：
// 后者的浏览半边在微软文档里被标为「不受支持、可能变化或不可用」
// （`DnssdServiceWatcher`、`DnsdServiceInstanceCollection`），只剩注册能用。
// Win32 那一组是受支持的桌面 API，没有包标识（package identity）要求，也不需要
// C++/WinRT 或 RoInitialize。
//
// 线程形状：三个回调都由系统线程池调用，不是 Qt 线程。回调里只做两件事——把数据
// 拷成 Qt 类型、投递到对象所在的线程；回调的上下文对象故意不释放，理由见 .cpp。
//
// 只在 Windows 上编译。Linux 对应的是 avahidiscovery。

#include "discovery.h"
#include "protocol.h"

#include <QHash>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <chrono>
#include <functional>
#include <mutex>
#include <vector>

#ifndef _WIN32
#  error "windnssddiscovery.h 只在 Windows 上编译；其它平台用 avahidiscovery 或 broadcastdiscovery"
#endif

// windns.h 里的 DNS-SD 声明受 NTDDI_VERSION 保护（Windows 10 1809 / RS5 起）。
// 必须在包含任何 Windows 头之前把它抬上去，否则那几个函数根本不会声明。
#include <sdkddkver.h>
#if defined(NTDDI_WIN10_RS5) && defined(NTDDI_VERSION) && NTDDI_VERSION < NTDDI_WIN10_RS5
#  undef NTDDI_VERSION
#  define NTDDI_VERSION NTDDI_WIN10_RS5
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windns.h>

namespace lanpipe::discovery {

class WinDnsSdDiscovery : public Discovery
{
    Q_OBJECT

public:
    struct Config
    {
        Advertisement self;
        // 是否对外注册。发送方只找人不被找，没有在监听。
        bool announce = true;
        // mDNS 实例名。留空时由 deviceId 前缀拼出。
        QString instanceName;
        std::chrono::milliseconds refresh = proto::kPeerRefreshInterval;
    };

    explicit WinDnsSdDiscovery(Config config, QObject *parent = nullptr);
    ~WinDnsSdDiscovery() override;

    void start() override;
    void stop() override;
    [[nodiscard]] QString backendName() const override { return QStringLiteral("windnssd"); }
    [[nodiscard]] QString lastError() const override { return m_lastError; }

    // 编译期就要求 Windows 10 1809+，但运行时仍可能失败：没有可用网络时
    // DnsServiceBrowse 返回 ERROR_NO_NETWORK。所以这里返回 true，真正的失败由
    // start() 之后的 lastError() 报告，调用方据此退回 UDP 广播。
    [[nodiscard]] static bool isAvailable() { return true; }

private:
    // 回调的上下文。它在最后一次回调回来之前必须一直有效，而 Win32 的 DNS-SD
    // 没有「回调已停止」的回执——取消是异步的。于是它**故意不释放**：每个 start()
    // 一次，几十字节，换的是绝不会在最后一条回调里用到已析构的对象。
    // 在真实 Windows 上确认过取消语义之后，这份泄漏可以去掉。
    struct CallbackContext
    {
        explicit CallbackContext(WinDnsSdDiscovery *owner) : owner(owner) { }

        WinDnsSdDiscovery *owner;
        std::mutex mutex; // 保护 owner；析构取同一把锁后置空
    };

    // 系统线程池调用的三个回调。静态成员函数的地址就是普通函数指针，
    // 调用约定写在声明里，不依赖 lambda 的编译器扩展。
    static VOID WINAPI onRegisterComplete(DWORD status, PVOID queryContext,
                                          PDNS_SERVICE_INSTANCE instance);
    static VOID WINAPI onBrowseComplete(DWORD status, PVOID queryContext, PDNS_RECORD records);
    static VOID WINAPI onResolveComplete(DWORD status, PVOID queryContext,
                                         PDNS_SERVICE_INSTANCE instance);

    // 向对象所在线程投递一件事。**持锁期间投递**：析构会先取同一把锁再把 owner
    // 置空，于是「回调正在使用 owner」与「对象正在析构」不可能同时发生。
    // 传送的函子只做队列投递，不在锁里调用对象。
    static void postToOwner(PVOID queryContext,
                            const std::function<void(WinDnsSdDiscovery *)> &emit);

    void registerService();
    void browse();
    void refresh();
    void fail(const QString &reason);

    // 浏览报来的一批实例名，在 Qt 线程上逐个解析。
    void resolveInstances(const QStringList &instanceNames);
    // 解析结果，在 Qt 线程上组装成 Announcement。
    void adoptResolved(const QString &instanceName, const QStringList &addresses, quint16 port,
                       const QHash<QString, QByteArray> &txt);

    Config m_config;

    DNS_SERVICE_REGISTER_REQUEST m_registerRequest{};
    PDNS_SERVICE_INSTANCE m_registeredInstance = nullptr;
    bool m_registered = false;

    DNS_SERVICE_CANCEL m_browseCancel{};
    DNS_SERVICE_CANCEL m_resolveCancel{};

    // 注册时用到的字符串必须活到 API 拷走它们为止。
    std::vector<std::wstring> m_wideKeys;
    std::vector<std::wstring> m_wideValues;
    std::vector<std::wstring> m_wideName;
    std::vector<std::wstring> m_wideHost;

    // 所有分配出去的上下文。故意不释放（见上），但析构时要把它们指向本对象的
    // 指针置空，回调才不会用到已析构的对象。
    std::vector<PVOID> m_contexts;

    QHash<QString, Announcement> m_resolved;
    QTimer *m_refreshTimer = nullptr;
    QString m_lastError;
    bool m_started = false;
};

} // namespace lanpipe::discovery
