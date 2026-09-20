#pragma once

// 一次接收会话（§5）：发送方是谁、它声明了什么、每个文件走到哪一步。
//
// 会话不做策略判断（那是 trust/policy），也不碰连接（那是 ReceiveService）。
// 它的临时数据全在 <receive-dir>/.lanpipe-tmp/<sessionId>/ 下——删这一棵子树
// 绝不会碰到已经改名进接收目录的文件。

#include "files/localsink.h"
#include "identity.h"
#include "mtls.h"
#include "transfer/transfer.h"

#include <QDateTime>
#include <QList>
#include <QString>

#include <chrono>
#include <memory>

namespace lanpipe::transfer {

class ReceiveSession
{
public:
    struct Entry
    {
        TransferFile declared;
        QString sanitized; // 净化后的名字；审批界面显示的就是它
        QString finalPath; // 已落位时才有值
        quint64 committedBytes = 0;
        bool inFlight = false;
        bool committed = false;
    };

    ReceiveSession(QString sessionId, net::PeerIdentity sender, QString senderName,
                   QList<Entry> entries, quint64 totalSize, QString receiveDir);

    [[nodiscard]] const QString &sessionId() const { return m_sessionId; }
    [[nodiscard]] const net::PeerIdentity &sender() const { return m_sender; }
    [[nodiscard]] const QString &senderName() const { return m_senderName; }
    [[nodiscard]] quint64 totalSize() const { return m_totalSize; }
    [[nodiscard]] const QList<Entry> &entries() const { return m_entries; }
    [[nodiscard]] QList<Entry> &entries() { return m_entries; }

    [[nodiscard]] Entry *find(const QString &fileId);
    [[nodiscard]] bool hasInFlight() const;

    [[nodiscard]] QString tempDir() const;

    // 给一个文件建 sink。打开失败时返回空（磁盘满、权限、名字冲突用尽…）。
    [[nodiscard]] std::unique_ptr<files::LocalFileSink> openSink(const Entry &entry) const;

    // 改名进接收目录并记账。sink 必须还是打开着的那一个。
    [[nodiscard]] bool commitFile(Entry &entry, files::LocalFileSink &sink);

    // complete 的应答内容：每个声明过的文件都出现，只统计已落位的字节。
    [[nodiscard]] CompleteReport report() const;

    // 删掉本会话的临时数据（取消、超时、异常收尾都走它）。
    void destroyTempData() const;

private:
    QString m_sessionId;
    net::PeerIdentity m_sender;
    QString m_senderName;
    QList<Entry> m_entries;
    quint64 m_totalSize = 0;
    QString m_receiveDir;
};

// 删掉 .lanpipe-tmp 下超过 retention 的条目，返回删了几个（§5.7）。
int sweepTempRoot(const QString &receiveDir, std::chrono::hours retention,
                  const QDateTime &now = QDateTime::currentDateTimeUtc());

// 删一棵目录树。符号链接只删链接本身——这是全仓唯一一处按目录名删东西的代码，
// 跟随链接就等于给出了一条从接收目录往外删的路径。
void removeTreeSafely(const QString &path);

} // namespace lanpipe::transfer
