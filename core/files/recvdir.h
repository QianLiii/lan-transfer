#pragma once

// 接收目录的解析（§1.2 第 3 条，filesink.h 结尾留的那个形状）。
//
// 「默认落在哪」是平台的事：桌面是下载目录，Android 是应用私有目录或 SAF 树。
// Settings 只存用户显式设过的值（默认是空串），所以这一步不能省——不解析的话，
// `.lanpipe-tmp` 会落在进程的工作目录里。

#include <QString>

#include <expected>

namespace lanpipe::files {

// 解析出接收目录的绝对路径并确保它存在、可写。configured 为空时回落到下载目录。
[[nodiscard]] std::expected<QString, QString> resolveReceiveDir(const QString &configured);

} // namespace lanpipe::files
