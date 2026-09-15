#pragma once

// 用户设置的持久化封装（§6 Settings）。
//
// 这里只存用户可见的偏好。「密钥与证书的路径」不在此列——它们由 identity 模块
// 通过 QStandardPaths 推导（§1.2 第 5 条）。两者混在一起正是 iOS 上重装或更新后
// 配置失效的成因：容器 UUID 会变，存下来的绝对路径随即指向不存在的位置。

#include <QSettings>
#include <QString>

namespace lanpipe {

// 接收策略（§4）。默认 PromptAlways——自动接受必须被显式选择。
enum class ReceivePolicy {
    AutoAcceptPaired, // 已配对设备自动接受，仅通知
    PromptAlways,     // 一律弹出审批（默认）
};

class Settings
{
public:
    // iniPath 为空时使用 QSettings 的平台原生存储位置。
    // 测试传入临时文件路径，以免污染真实配置。
    explicit Settings(const QString& iniPath = {});
    ~Settings();

    Settings(const Settings &) = delete;
    Settings &operator=(const Settings &) = delete;

    // 设备名。广播到 TXT 的 name 字段，也是其它设备上显示的名字（§3.2）。
    // 注意：mDNS 实例名可能被系统自动改名，用户可见名一律以此值为准（§3.8）。
    [[nodiscard]] QString deviceName() const;
    void setDeviceName(const QString &name);

    // 接收目录。桌面端是自由路径；移动端语义不同（应用私有目录 / SAF 树），
    // 具体解析由平台层负责（§1.2 第 3 条）。
    [[nodiscard]] QString receiveDir() const;
    void setReceiveDir(const QString &dir);

    [[nodiscard]] ReceivePolicy receivePolicy() const;
    void setReceivePolicy(ReceivePolicy policy);

    // 开放模式：接受任何设备且不弹审批。默认关闭（§4）。
    // 开启后审批这道唯一的实时防线就没了，UI 上需要明确警示。
    [[nodiscard]] bool openMode() const;
    void setOpenMode(bool enabled);

    // 固定监听端口。0 表示使用临时端口，这是默认值（§3.1）。
    // 仅在需要手工放行防火墙的场景下才应设置。
    [[nodiscard]] quint16 fixedPort() const;
    void setFixedPort(quint16 port);

private:
    QSettings m_settings;
};

} // namespace lanpipe
