#include "recvdir.h"

#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

namespace lanpipe::files {

std::expected<QString, QString> resolveReceiveDir(const QString &configured)
{
    QString dir = configured;
    if (dir.isEmpty()) {
        dir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        if (dir.isEmpty())
            return std::unexpected(QStringLiteral("找不到默认的下载目录，请在设置里指定接收目录"));
    }

    if (!QDir(dir).mkpath(QStringLiteral(".")))
        return std::unexpected(QStringLiteral("无法创建或访问接收目录：%1").arg(dir));

    // 可写性检查：只读目录要到第一个文件 commit 时才失败，那时整轮传输已经跑完了。
    if (!QFileInfo(dir).isWritable())
        return std::unexpected(QStringLiteral("接收目录不可写：%1").arg(dir));

    return QDir(dir).absolutePath();
}

} // namespace lanpipe::files
