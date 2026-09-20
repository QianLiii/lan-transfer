#include "localsource.h"

#include <QFile>
#include <QFileInfo>

#include <utility>

namespace lanpipe::files {

LocalFileSource::LocalFileSource(QString path) : m_path(std::move(path))
{
}

std::unique_ptr<QIODevice> LocalFileSource::open()
{
    auto file = std::make_unique<QFile>(m_path);
    if (!file->open(QIODevice::ReadOnly))
        return nullptr;
    return file;
}

std::optional<quint64> LocalFileSource::size() const
{
    // 不是普通文件（不存在、是目录、是管道）时返回空值：那是「定不下来」，
    // 不是「零字节」，调用方据此拒绝或改走不确定态（§5.14）。
    const QFileInfo info(m_path);
    if (!info.isFile())
        return std::nullopt;
    return static_cast<quint64>(info.size());
}

QString LocalFileSource::displayName() const
{
    return QFileInfo(m_path).fileName();
}

} // namespace lanpipe::files
