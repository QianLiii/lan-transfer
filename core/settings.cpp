#include "settings.h"

#include <QString>

namespace lanpipe {

namespace {

// 配置键集中在此处，避免各处手拼字符串写错到别的位置。
constexpr auto kKeyDeviceName    = "device/name";
constexpr auto kKeyReceiveDir    = "receive/dir";
constexpr auto kKeyReceivePolicy = "receive/policy";
constexpr auto kKeyOpenMode      = "receive/openMode";
constexpr auto kKeyFixedPort     = "network/fixedPort";

// 组织名与程序名显式写死，不走 QCoreApplication 的设置。
// 这样 CLI 与图形界面共享同一份配置，且不依赖谁先调用 setOrganizationName()。
constexpr auto kOrgName = "lanpipe";
constexpr auto kAppName = "lanpipe";

// 策略以字符串而非整数落盘。原因是失败方向：枚举一旦重排或插入新值，旧的整数会
// 静默指向另一个策略，而这里的语义是安全相关的（§4）——「一律弹出审批」被误读成
// 「已配对自动接受」是最坏的一种失败。字符串在 ini 里也可读、可手工修正。
QString policyToKey(ReceivePolicy policy)
{
    switch (policy) {
    case ReceivePolicy::AutoAcceptPaired:
        return QStringLiteral("auto-accept-paired");
    case ReceivePolicy::PromptAlways:
        return QStringLiteral("prompt-always");
    }
    return QStringLiteral("prompt-always");
}

ReceivePolicy policyFromKey(const QString &key)
{
    if (key == QLatin1String("auto-accept-paired"))
        return ReceivePolicy::AutoAcceptPaired;
    // 缺省、空值、无法识别的取值一律回落到 PromptAlways。
    // 唯一能给自动接受的理由是用户显式选了它——回落到宽松侧会让
    // 「用户明确要求的一律审批」被静默取消。
    return ReceivePolicy::PromptAlways;
}

} // namespace

Settings::Settings(const QString& iniPath)
    : m_settings(iniPath.isEmpty()
                     ? QSettings(QSettings::NativeFormat, QSettings::UserScope,
                                 QLatin1String(kOrgName), QLatin1String(kAppName))
                     : QSettings(iniPath, QSettings::IniFormat))
{
}

Settings::~Settings() = default;

QString Settings::deviceName() const
{
    // 空值表示尚未设置。由调用方决定回退值（通常取主机名），
    // 本类不替它猜——设备名会广播到局域网（§3.2），值得在 UI 上显式确认一次。
    return m_settings.value(QLatin1String(kKeyDeviceName)).toString();
}

void Settings::setDeviceName(const QString &name)
{
    m_settings.setValue(QLatin1String(kKeyDeviceName), name);
}

QString Settings::receiveDir() const
{
    // 空值表示尚未设置。默认位置的解析属于平台层（桌面是下载目录，移动端是
    // 应用私有目录或 SAF 树），见 §1.2 第 3 条——这里不做平台判断。
    return m_settings.value(QLatin1String(kKeyReceiveDir)).toString();
}

void Settings::setReceiveDir(const QString &dir)
{
    m_settings.setValue(QLatin1String(kKeyReceiveDir), dir);
}

ReceivePolicy Settings::receivePolicy() const
{
    return policyFromKey(m_settings.value(QLatin1String(kKeyReceivePolicy)).toString());
}

void Settings::setReceivePolicy(ReceivePolicy policy)
{
    m_settings.setValue(QLatin1String(kKeyReceivePolicy), policyToKey(policy));
}

bool Settings::openMode() const
{
    // 不能用 QVariant::toBool()：它对任何非空且非 "false"/"0" 的字符串都返回 true，
    // 于是在 ini 里手写 "yes" 就会打开开放模式（§4：接受任何人且不弹审批），
    // 而这是全应用最宽松的一个开关。「含义不明即取较严的一侧」在这里尤其重要。
    //
    // 只认我们自己写下去的形态（QVariant 布尔序列化后是 "true"，注册表下可能是 "1"），
    // 其余取值一律为假。
    const QString raw = m_settings.value(QLatin1String(kKeyOpenMode)).toString().trimmed();
    return raw.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0
        || raw == QLatin1String("1");
}

void Settings::setOpenMode(bool enabled)
{
    m_settings.setValue(QLatin1String(kKeyOpenMode), enabled);
}

quint16 Settings::fixedPort() const
{
    // 0 表示临时端口（§3.1）。越界值也一律回落到 0：宁可让系统分配，
    // 也不要因为一个手改坏的端口号导致监听失败却看不出原因。
    const uint value = m_settings.value(QLatin1String(kKeyFixedPort), 0u).toUInt();
    if (value > 65535u)
        return 0;
    return static_cast<quint16>(value);
}

void Settings::setFixedPort(quint16 port)
{
    m_settings.setValue(QLatin1String(kKeyFixedPort), port);
}

} // namespace lanpipe
