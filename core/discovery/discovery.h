#pragma once

// 设备发现的公共形状（§3）。
//
// 后端的职责只有一件：报告「我刚在某个地址上听到了一份什么通告」。
// 合并不在这里——同一台设备会经多个后端、多个接口、多块网卡反复出现，
// 去重与地址集合是 PeerDirectory 的事（§3.3）。
//
// 三个来源的地位不同（§3.6）：系统 DNS-SD 是主路径，UDP 广播是兜底，
// 手动 IP:port 是最后一招。它们都产出同一个 Announcement。

#include <QDateTime>
#include <QHostAddress>
#include <QMetaType>
#include <QObject>
#include <QString>

#include <cstdint>

namespace lanpipe::discovery {

// 一台设备对外通告的内容。§3.2 的 TXT 字段集，加一个监听端口——
// 广播载荷与 TXT 用的是同一组字段，所以只有这一个结构体。
struct Advertisement
{
    QString deviceId;    // TXT id：指纹的前 16 字节，32 位十六进制（§3.2）
    QString name;        // TXT name：用户可见名。不比 mDNS 实例名，系统会改名（§3.8）
    QString fingerprint; // TXT fp：SPKI 指纹。**仅作连接提示，永不是信任锚**（§3.2、§4）
    int version = 0;     // TXT ver：协议版本
    quint16 port = 0;    // 实际监听端口。端口 0 表示由系统分配，通告里必须是确定的那个（§3.1）
};

// 一次观测。
struct Announcement
{
    Advertisement advertisement;
    // 通告来自哪个地址。不放进载荷：收包时的来源地址才是被证明可用的那一个，
    // 多网卡机器也因此能自然地被拆成一组地址（§3.3）。
    QHostAddress address;
    QDateTime seenAt;
};

class Discovery : public QObject
{
    Q_OBJECT

public:
    ~Discovery() override = default;

    Discovery(const Discovery &) = delete;
    Discovery &operator=(const Discovery &) = delete;

    // 开始/停止通告与浏览。反复调用无副作用。
    virtual void start() = 0;
    virtual void stop() = 0;

    // 后端名，进日志与诊断导出（§3.6）。
    [[nodiscard]] virtual QString backendName() const = 0;

signals:
    // 每听到一次就发一次，同一个对端会重复出现——去重在 PeerDirectory。
    void announced(const lanpipe::discovery::Announcement &announcement);

protected:
    explicit Discovery(QObject *parent = nullptr) : QObject(parent) {}
};

} // namespace lanpipe::discovery

Q_DECLARE_METATYPE(lanpipe::discovery::Announcement)
