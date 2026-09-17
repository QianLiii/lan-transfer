#include "atomicwrite.h"

#include <QIODevice>
#include <QSaveFile>

namespace lanpipe {

bool writeFileAtomically(const QString &path, const QByteArray &data, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        *error = QStringLiteral("无法写入 %1：%2").arg(path, file.errorString());
        return false;
    }
    if (file.write(data) != data.size()) {
        *error = QStringLiteral("写入 %1 不完整").arg(path);
        return false;
    }
    if (!file.commit()) {
        *error = QStringLiteral("提交 %1 失败：%2").arg(path, file.errorString());
        return false;
    }
    return true;
}

} // namespace lanpipe
