#pragma once

// 桌面端的 FileSink：写到 <receive-dir>/.lanpipe-tmp/<sessionId>/<fileId>，
// commit() 时改名进接收目录（§5.7）。
//
// 文件名不参与临时路径的构造，路径穿越因此在写入那一刻就不可能发生；净化过的
// 名字只在 commit 那一刻成为路径的一部分。
//
// QSaveFile 承担两件事：commit 时先落盘再改名（断电后不会留下长度正确而内容未
// 落盘的文件），以及未 commit 就析构时自动丢弃临时文件——重传因此天然是干净的。
//
// open() 返回的设备所有权归调用方：**必须先 commit() 或 discard()，再销毁它**。

#include "filesink.h"

#include <QPointer>
#include <QSaveFile>
#include <QString>

#include <memory>

namespace lanpipe::files {

class LocalFileSink : public FileSink
{
public:
    // desiredName 必须是已净化的名字（trust::sanitizeFilename）。冲突改名在
    // commit() 那一刻才做——构造到 commit 之间可能隔着几分钟。
    LocalFileSink(QString receiveDir, QString sessionId, QString fileId, QString desiredName,
                  QString senderFingerprint, quint64 declaredSize);

    [[nodiscard]] std::unique_ptr<QIODevice> open() override;
    [[nodiscard]] quint64 bytesWritten() const override;
    [[nodiscard]] bool commit() override;
    void discard() override;

    // 最终落地位置。commit() 成功之后才有值。
    [[nodiscard]] QString finalPath() const { return m_finalPath; }
    [[nodiscard]] QString tempDir() const;

private:
    [[nodiscard]] QString metaPath() const;
    [[nodiscard]] bool writeMeta() const;

    QString m_receiveDir;
    QString m_sessionId;
    QString m_fileId;
    QString m_desiredName;
    QString m_senderFingerprint;
    quint64 m_declaredSize = 0;

    QPointer<QSaveFile> m_file; // 设备归调用方，这里只借用；对方销毁即自动置空
    QString m_tempPath;
    QString m_finalPath;
    quint64 m_written = 0;
    bool m_committed = false;
    bool m_discarded = false;
};

} // namespace lanpipe::files
