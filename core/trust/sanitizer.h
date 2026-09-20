#pragma once

// 文件名的净化与改名（§5.11）。
//
// 净化发生在**任何路径被拼出来之前**。文件名不参与临时路径的构造（那里只有
// sessionId/fileId），它只在改名进接收目录的那一刻成为路径的一部分——所以路径
// 穿越在写入那一刻就不可能发生，而最后这一步必须拿到已经净化过的名字。
//
// 规则按最严的平台写（Windows 的保留名与尾点尾空格、双向控制字符、大小写与
// NFD 归一化的冲突判定），宽松的实现到那几个平台上要重写（§1.2 第 6 条）。
// 比 §5.11 的清单多拒了一类：Windows 不允许的 `<>:"|?*`——收到一个在别的平台上
// 根本写不下去的名字，不如现在就说清楚。

#include <QString>

#include <expected>

namespace lanpipe::trust {

// 净化对端给的文件名，返回可直接用作最终文件名的名字（不含路径）。
//
// 无法安全化时返回错误，调用方必须拒收这个文件——不「静默改成别的名字」：
// 用户批准的是他在审批界面上看到的那个名字。
[[nodiscard]] std::expected<QString, QString> sanitizeFilename(const QString &raw);

// dir/name 这条最终路径是否可用（长度按平台限）。净化管名字，这一条管全路径。
[[nodiscard]] std::expected<void, QString> checkFinalPath(const QString &dir, const QString &name);

// 在 dir 里给 name 找一个不冲突的名字：photo.jpg → photo (1).jpg。
// 试满 kMaxFinalNameAttempts 次仍冲突则返回空串。
[[nodiscard]] QString uniqueName(const QString &dir, const QString &name);

// 两个名字是否指向同一个文件——按目标平台的大小写与归一化规则比。
[[nodiscard]] bool namesCollide(const QString &a, const QString &b);

// 剥掉控制字符后用于终端显示的文本。设备名与文件名都是不可信输入，
// 不剥的话一个 ANSI 转义序列就能在终端里伪造出整行输出。
[[nodiscard]] QString displaySafe(const QString &text);

} // namespace lanpipe::trust
