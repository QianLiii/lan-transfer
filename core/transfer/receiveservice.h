#pragma once

// 接收方的四个传输端点（§5）：prepare / upload / complete / abort。
//
// 审批的形状与 PingService 一致：发 approvalRequired 信号，调用方用
// submitApproval(bool) 把答案交回来。CLI 同步读一行、界面异步弹框，核心不为
// 谁去问而改变形状——这正是配对流程已经证明过的那一套。
//
// 同时只有一个会话（§5.13），等审批的那一次也算占位：否则能同时弹出两个框。

#include "http/httpconnection.h"
#include "settings.h"
#include "transfer/receivesession.h"
#include "trust/truststore.h"

#include <QDateTime>
#include <QObject>
#include <QString>
#include <QTimer>

#include <chrono>
#include <functional>
#include <memory>

namespace lanpipe::transfer {

class ReceiveService : public QObject
{
    Q_OBJECT

public:
    // 空闲空间探针：返回该目录所在卷的可用字节数。问不出来时返回 0——未知不等于
    // 不足（见 .cpp）。测试注入定值来构造 507。
    using FreeSpaceProbe = std::function<quint64(const QString &dir)>;

    ReceiveService(const Settings &settings, trust::TrustStore &trust, QString receiveDir,
                   QObject *parent = nullptr);

    // 请求目标是否归本服务处理。四个端点的前缀之外一律不认。
    [[nodiscard]] static bool handles(QByteArrayView target);

    void handle(http::HttpConnection &connection);

    // 界面把审批结果交回来。必须在 approvalRequired 之后调用一次。
    void submitApproval(bool accepted);

    // 接收方取消当前会话（界面取消、CLI 的 SIGINT）。没有会话时是无操作。
    void cancelActive();

    [[nodiscard]] bool hasActiveSession() const { return m_session != nullptr; }
    [[nodiscard]] QString activeSessionId() const;

    // 只有测试会改这些。
    void setApprovalWindow(std::chrono::milliseconds window);
    void setSessionTtl(std::chrono::milliseconds ttl);
    void setFreeSpaceProbe(FreeSpaceProbe probe);

    // .lanpipe-tmp 的清理：构造时扫一次，之后按 kTempSweepInterval 周期扫（§5.7）。
    // 返回删掉几个条目。
    int sweepStaleTempData(const QDateTime &now = QDateTime::currentDateTimeUtc());

signals:
    // 需要用户决定是否接收。request 里的文件名已经净化过——用户看到的就是要
    // 落地的那个名字。
    void approvalRequired(const lanpipe::transfer::TransferRequest &request);

    void fileProgress(const QString &fileId, quint64 received, quint64 total);
    void fileCommitted(const QString &fileId, const QString &finalPath, quint64 bytes);
    void sessionFinished(const QString &sessionId, bool completed);

private:
    void handlePrepare(http::HttpConnection &connection);
    void handleUpload(http::HttpConnection &connection);
    void handleComplete(http::HttpConnection &connection);
    void handleAbort(http::HttpConnection &connection);

    void onPrepareBody(http::HttpConnection &connection, const QByteArray &body);
    // timedOut 与「用户拒绝」分开：前者是 504，后者是 403（§5 的应答表）。
    void finishPrepare(http::HttpConnection &connection, bool accepted, bool timedOut = false);
    void acceptRequest(http::HttpConnection &connection);

    // 丢掉等审批那一次的临时目录（没接受、超时、对端走了都走它）。
    void dropPendingSessionTempData();

    // 会话存在、且属于这条连接的对端时返回它，否则回答并返回空。
    ReceiveSession *requireSession(http::HttpConnection &connection, const QString &sessionId);

    void commitUpload(http::HttpConnection &connection, const QString &fileId);
    void discardUpload();

    // 拆除会话：停表、断在途的 PUT、删临时数据。幂等。
    void teardown(const QString &sessionId, bool completed);

    void armSessionTtl();
    void onSessionExpired();

    [[nodiscard]] int ttlRemainingSeconds() const;

    const Settings &m_settings;
    trust::TrustStore &m_trust;
    QString m_receiveDir;
    FreeSpaceProbe m_freeSpace;

    std::unique_ptr<ReceiveSession> m_session;
    QTimer *m_sessionTtl = nullptr;

    // 等审批的那一次。sessionId 在 prepare 时就定下来：临时目录要按它建，
    // 不能等审批通过再换一个（那样这个目录就成了没人认领的孤儿）。
    http::HttpConnection *m_pendingApproval = nullptr;
    TransferRequest m_pendingRequest;
    QList<ReceiveSession::Entry> m_pendingEntries;
    net::PeerIdentity m_pendingPeer;
    QString m_pendingSessionId;
    QTimer *m_approvalTimer = nullptr;

    // 在途的那次 PUT。
    http::HttpConnection *m_upload = nullptr;
    QString m_uploadFileId;
    std::unique_ptr<files::LocalFileSink> m_uploadSink; // 先析构 sink 再析构 device
    std::unique_ptr<QIODevice> m_uploadDevice;
    quint64 m_uploadWritten = 0;

    QTimer *m_sweepTimer = nullptr;
};

} // namespace lanpipe::transfer
