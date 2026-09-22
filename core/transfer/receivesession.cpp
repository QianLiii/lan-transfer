#include "receivesession.h"

#include "protocol.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <utility>

namespace lanpipe::transfer {

ReceiveSession::ReceiveSession(QString sessionId, net::PeerIdentity sender, QString senderName,
                               QList<Entry> entries, quint64 totalSize, QString receiveDir)
    : m_sessionId(std::move(sessionId))
    , m_sender(std::move(sender))
    , m_senderName(std::move(senderName))
    , m_entries(std::move(entries))
    , m_totalSize(totalSize)
    , m_receiveDir(std::move(receiveDir))
{
}

ReceiveSession::Entry *ReceiveSession::find(const QString &fileId)
{
    for (Entry &entry : m_entries) {
        if (entry.declared.id == fileId)
            return &entry;
    }
    return nullptr;
}

bool ReceiveSession::hasInFlight() const
{
    for (const Entry &entry : m_entries) {
        if (entry.inFlight)
            return true;
    }
    return false;
}

QString ReceiveSession::tempDir() const
{
    return QDir(QDir(m_receiveDir).filePath(QString::fromLatin1(proto::kTempDirName)))
        .filePath(m_sessionId);
}

std::unique_ptr<files::LocalFileSink> ReceiveSession::openSink(const Entry &entry) const
{
    auto sink = std::make_unique<files::LocalFileSink>(m_receiveDir, m_sessionId, entry.declared.id,
                                                       entry.sanitized,
                                                       m_sender.fingerprint.toHex(),
                                                       entry.declared.size);
    if (sink->open() == nullptr)
        return nullptr;
    return sink;
}

bool ReceiveSession::commitFile(Entry &entry, files::LocalFileSink &sink)
{
    if (!sink.commit())
        return false;

    entry.committedBytes = sink.bytesWritten();
    entry.finalPath = sink.finalPath();
    entry.committed = true;
    entry.inFlight = false;
    return true;
}

CompleteReport ReceiveSession::report() const
{
    CompleteReport report;
    report.files.reserve(m_entries.size());
    for (const Entry &entry : m_entries) {
        // 没落位的一律报 0：发送方据此判定「没收到」，而在途与失败在它看来是同一件事。
        report.files.append({entry.declared.id, entry.committed ? entry.committedBytes : 0});
    }
    return report;
}

void ReceiveSession::destroyTempData() const
{
    removeTreeSafely(tempDir());
}

void removeTreeSafely(const QString &path)
{
    const QFileInfo info(path);
    if (info.isSymLink() || !info.isDir()) {
        // 链接本身或普通文件：删掉它，绝不顺着链接往里走。QDir::exists() 会跟随
        // 链接，所以判断用 QFileInfo。
        if (info.isSymLink() || info.exists())
            QFile::remove(path);
        return;
    }

    const QFileInfoList entries =
        QDir(path).entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::System
                                 | QDir::NoDotAndDotDot);
    for (const QFileInfo &entry : entries)
        removeTreeSafely(entry.absoluteFilePath());

    QDir().rmdir(path);
}

int sweepTempRoot(const QString &receiveDir, std::chrono::hours retention, const QDateTime &now,
                  const QString &keepSessionId)
{
    const QString root =
        QDir(receiveDir).filePath(QString::fromLatin1(proto::kTempDirName));
    const QDir dir(root);
    if (!dir.exists())
        return 0;

    int removed = 0;
    const QFileInfoList entries =
        dir.entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);
    for (const QFileInfo &info : entries) {
        // 活动会话永远是活的：它的目录 mtime 不会随分片增长而更新，只看时间会误判。
        if (!keepSessionId.isEmpty() && info.fileName() == keepSessionId)
            continue;
        // 其余这条保留期只服务崩溃留下的孤儿：活着的会话自己清理自己（TTL）。
        const auto age = std::chrono::milliseconds(info.lastModified().msecsTo(now));
        if (age < retention)
            continue;
        removeTreeSafely(info.absoluteFilePath());
        ++removed;
    }

    // 全删光之后连根目录也收掉，免得接收目录里永远留一个空壳。
    QDir().rmdir(root);
    return removed;
}

} // namespace lanpipe::transfer
