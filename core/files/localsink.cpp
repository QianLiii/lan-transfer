#include "localsink.h"

#include "atomicwrite.h"
#include "protocol.h"
#include "trust/sanitizer.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

#include <utility>

namespace lanpipe::files {

namespace {

constexpr auto kKeySourceName = "sourceName";
constexpr auto kKeySessionId = "sessionId";
constexpr auto kKeySenderFingerprint = "senderFingerprint";
constexpr auto kKeyDeclaredLength = "declaredLength";

} // namespace

LocalFileSink::LocalFileSink(QString receiveDir, QString sessionId, QString fileId,
                             QString desiredName, QString senderFingerprint, quint64 declaredSize)
    : m_receiveDir(std::move(receiveDir))
    , m_sessionId(std::move(sessionId))
    , m_fileId(std::move(fileId))
    , m_desiredName(std::move(desiredName))
    , m_senderFingerprint(std::move(senderFingerprint))
    , m_declaredSize(declaredSize)
{
}

QString LocalFileSink::tempDir() const
{
    return QDir(QDir(m_receiveDir).filePath(QString::fromLatin1(proto::kTempDirName)))
        .filePath(m_sessionId);
}

QString LocalFileSink::metaPath() const
{
    return QDir(tempDir()).filePath(m_fileId + QStringLiteral(".part.meta"));
}

bool LocalFileSink::writeMeta() const
{
    // 元数据在第一个数据字节之前落盘：它是 v2 续传的全部依据，也是「这个分片是
    // 谁的、本来该多大」的唯一记录（§5.7）。
    QJsonObject object;
    object.insert(QLatin1String(kKeySourceName), m_desiredName);
    object.insert(QLatin1String(kKeySessionId), m_sessionId);
    object.insert(QLatin1String(kKeySenderFingerprint), m_senderFingerprint);
    object.insert(QLatin1String(kKeyDeclaredLength), static_cast<double>(m_declaredSize));

    QString error;
    return writeFileAtomically(metaPath(),
                               QJsonDocument(object).toJson(QJsonDocument::Indented), &error);
}

std::unique_ptr<QIODevice> LocalFileSink::open()
{
    if (m_committed || m_discarded || m_file)
        return nullptr; // 一个 sink 只开一次

    if (!QDir(m_receiveDir).mkpath(QString::fromLatin1(proto::kTempDirName) + QLatin1Char('/')
                                   + m_sessionId)) {
        return nullptr;
    }
    if (!writeMeta())
        return nullptr;

    auto file = std::make_unique<QSaveFile>(QDir(tempDir()).filePath(m_fileId));
    if (!file->open(QIODevice::WriteOnly))
        return nullptr;

    m_tempPath = file->fileName();
    m_file = file.get();
    return file;
}

quint64 LocalFileSink::bytesWritten() const
{
    // commit 之后数据已经被改名走，设备上再也问不出长度（QSaveFile::size() 会去
    // stat 那个已经不在的临时路径，返回 0）——所以用 commit 时记下的快照。
    if (m_committed)
        return m_written;
    // 设备还活着就以它为准；调用方提前销毁了设备时退回快照。
    return m_file ? static_cast<quint64>(m_file->size()) : m_written;
}

bool LocalFileSink::commit()
{
    if (m_committed)
        return true; // 契约：重复 commit 是无操作
    if (m_discarded || !m_file)
        return false;

    m_written = static_cast<quint64>(m_file->size());

    // 先落到临时路径（QSaveFile 在这里 fsync）。这一步失败通常意味着写盘过程中
    // 出过错，例如磁盘满。
    if (!m_file->commit())
        return false;

    // 直到这一刻才解析最终名：构造这个 sink 与 commit 之间可能隔着几分钟，
    // 期间完全可能有别的文件落到同一个名字上。
    const QString finalName = trust::uniqueName(m_receiveDir, m_desiredName);
    if (finalName.isEmpty()) {
        qWarning("lanpipe: 接收目录里同名文件太多，放弃改名");
        return false;
    }
    if (const auto pathOk = trust::checkFinalPath(m_receiveDir, finalName); !pathOk.has_value()) {
        qWarning("lanpipe: %s", qPrintable(pathOk.error()));
        return false;
    }

    // 探测与改名之间仍有极小的窗口（Qt 没有 RENAME_NOREPLACE 的跨平台封装）。
    // 窗口内被覆盖的是本机另一个进程刚写下的文件，不是对端可控的事。
    m_finalPath = QDir(m_receiveDir).filePath(finalName);
    if (!QFile::rename(m_tempPath, m_finalPath)) {
        m_finalPath.clear();
        return false;
    }

    m_committed = true;
    QFile::remove(metaPath()); // 数据已经改名走，元数据没有用了
    return true;
}

void LocalFileSink::discard()
{
    if (m_discarded || m_committed)
        return;
    m_discarded = true;

    if (m_file && m_file->isOpen()) {
        // cancelWriting() 会把临时文件一并删掉，且此后 commit() 也不会再保存。
        m_file->cancelWriting();
    } else if (!m_tempPath.isEmpty()) {
        // 已经 commit 到临时路径、改名却没成功的那一步。
        QFile::remove(m_tempPath);
    }
    QFile::remove(metaPath());
}

} // namespace lanpipe::files
