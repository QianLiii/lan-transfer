#include "tlsbackend.h"

#include <QSslSocket>
#include <QStringList>

namespace lanpipe {

namespace {

// 后端名是小写常量，取值集合由 Qt 固定：schannel / securetransport /
// openssl / cert-only（qtlsbackend.cpp 的 builtinBackendNames）。
[[nodiscard]] QString openSslBackendName()
{
    return QStringLiteral("openssl");
}

// 把可用后端列表拼进错误信息——缺少哪个后端、有哪些可选，是排查的第一手信息。
[[nodiscard]] QString describeAvailable(const QList<QString> &backends)
{
    if (backends.isEmpty())
        return QStringLiteral("(none)");
    return backends.join(QStringLiteral(", "));
}

} // namespace

QString forceOpenSslBackend()
{
    // 必须在任何 SSL 类被使用之前调用。Qt 记录的是「已经实例化的后端」，
    // 一旦有任何 QSslSocket / QSslCertificate / QSslKey / QSslConfiguration
    // 参与过工作，后续 setActiveBackend 就会失败（源码会打印
    // "another backend is already in use"）。
    //
    // 这一句读取当前后端名；Qt 在未设置时会顺手写入平台默认值，所以它同时
    // 起到「把隐式默认显式化」的作用——这样下面失败时我们能把真实名字报出来。
    const QString current = QSslSocket::activeBackend();
    if (current == openSslBackendName())
        return {}; // 已经是目标后端，幂等返回

    const QList<QString> available = QSslSocket::availableBackends();

    // 失败信息统一附带这段上下文。一次失败的 CI 日志就能分辨出是
    // 「插件没注册」（列表里没有 openssl）还是「注册了但加载不到 OpenSSL 库」
    // （列表里有，而 supportsSsl 为假）——两者修法完全不同，不该靠再改一次码去问。
    const QString context =
        QStringLiteral("可用后端：%1；当前后端：%2")
            .arg(describeAvailable(available),
                 current.isEmpty() ? QStringLiteral("(未知)") : current);

    if (!available.contains(openSslBackendName())) {
        return QStringLiteral(
                   "TLS 后端 openssl 在此 Qt 构建中不可用。可用后端：%1。\n"
                   "该后端插件在构建 Qt 时就已决定，无法在运行时补上——需要重新构建 Qt"
                   "并在 configure 时能找到 OpenSSL 头文件。")
            .arg(describeAvailable(available));
    }

    if (!QSslSocket::setActiveBackend(openSslBackendName())) {
        // 可用性上面已经确认过，走到这里只剩一种原因：已经有别的后端在用。
        return QStringLiteral(
                   "TLS 后端切换失败：当前已在使用 %1，无法改为 openssl。\n"
                   "forceOpenSslBackend() 必须早于任何 SSL 对象被创建，"
                   "请把它放在启动流程的最前面。\n（%2）")
            .arg(current.isEmpty() ? QStringLiteral("(未知)") : current, context);
    }

    // 选定了后端不等于它可用。后端插件存在、但它运行时 dlopen 不到 OpenSSL 库时，
    // setActiveBackend 会成功，而 supportsSsl() 为 false——这是各平台最常见的一类
    // 启动失败，且症状（握手全部失败）与配置错误难以区分，所以在这里就拦下。
    //
    // 连同可用后端列表一起报出来，是为了让一次失败的 CI 就能定位：
    // 列表里有 openssl 说明插件已注册、只是加载不到库；列表里没有则是
    // 这个 Qt 构建根本没带 openssl 后端插件，那样就只能换 Qt 或改设计。
    if (!QSslSocket::supportsSsl()) {
        return QStringLiteral(
                   "TLS 后端已选定为 openssl，但它无法工作：Qt 的 openssl 插件没能加载"
                   "OpenSSL 动态库。\n"
                   "Linux：安装 libssl3/libcrypto3；Windows：随程序分发 "
                   "libssl-3-x64.dll 与 libcrypto-3-x64.dll；"
                   "Android：把 OpenSSL 库打进 APK（§7）；"
                   "macOS：系统不自带 OpenSSL，需要一并打包或让 dyld 能找到它。\n（%1）")
            .arg(context);
    }

    return {};
}

QString activeBackendName()
{
    // 注意：Qt 没有「只读地查询已选后端名」的接口——activeBackend() 在名字为空时
    // 会写入平台默认值。因此本函数只应在 forceOpenSslBackend() 成功之后调用；
    // 在那之前调用会把平台默认后端记下来（只要还没创建 SSL 对象，随后的
    // setActiveBackend 仍能覆盖它，但诊断输出会短暂地显示错误的答案）。
    return QSslSocket::activeBackend();
}

} // namespace lanpipe
