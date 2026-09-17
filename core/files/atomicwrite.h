#pragma once

// 原子写入文件（§1.2）。先写临时文件再改名：中途崩溃不会留下半截文件，
// 否则下次启动只会看到「无法解析」这类只能靠删文件恢复的状态。

#include <QByteArray>
#include <QString>

namespace lanpipe {

// 失败时把可读原因写进 *error。
[[nodiscard]] bool writeFileAtomically(const QString &path, const QByteArray &data, QString *error);

} // namespace lanpipe
