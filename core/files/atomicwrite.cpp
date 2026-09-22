#include "atomicwrite.h"

#include <QIODevice>
#include <QSaveFile>

namespace lanpipe {

namespace {

// 出参可以不传——调用方只关心成败时，不该因为少给一个指针就崩。
void setError(QString *error, const QString &text)
{
    if (error)
        *error = text;
}

} // namespace

bool writeFileAtomically(const QString &path, const QByteArray &data, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        setError(error, QStringLiteral("无法写入 %1：%2").arg(path, file.errorString()));
        return false;
    }
    if (file.write(data) != data.size()) {
        setError(error, QStringLiteral("写入 %1 不完整").arg(path));
        return false;
    }
    if (!file.commit()) {
        setError(error, QStringLiteral("提交 %1 失败：%2").arg(path, file.errorString()));
        return false;
    }
    return true;
}

} // namespace lanpipe
