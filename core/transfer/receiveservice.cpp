#include "receiveservice.h"

#include "http/httpresponse.h"
#include "protocol.h"
#include "random.h"
#include "trust/policy.h"
#include "trust/sanitizer.h"

#include <QDir>
#include <QStorageInfo>

#include <utility>

using namespace lanpipe::http;

namespace lanpipe::transfer {

namespace {

const QByteArrayView preparePath(proto::kPathPrepare.data(), proto::kPathPrepare.size());
const QByteArrayView uploadPrefix(proto::kPathUploadPrefix.data(), proto::kPathUploadPrefix.size());
const QByteArrayView completePrefix(proto::kPathCompletePrefix.data(),
                                    proto::kPathCompletePrefix.size());
const QByteArrayView abortPrefix(proto::kPathAbortPrefix.data(), proto::kPathAbortPrefix.size());

// 路径里的 id 只认 randomHex() 产出的形态：小写十六进制、长度正好。
bool isId(QByteArrayView text, int bytes)
{
    if (text.size() != bytes * 2)
        return false;
    for (const char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

// /api/v1/upload/<sessionId>/<fileId>：正好两段，多一段少一段都不认。
std::optional<QPair<QString, QString>> parseUploadTarget(QByteArrayView target)
{
    const QByteArrayView rest = target.sliced(uploadPrefix.size());
    const qsizetype slash = rest.indexOf('/');
    if (slash < 0)
        return std::nullopt;

    const QByteArrayView sessionId = rest.first(slash);
    const QByteArrayView fileId = rest.sliced(slash + 1);
    if (!isId(sessionId, proto::kSessionIdBytes) || !isId(fileId, proto::kFileIdBytes))
        return std::nullopt;

    return QPair<QString, QString>{QString::fromLatin1(sessionId.toByteArray()),
                                   QString::fromLatin1(fileId.toByteArray())};
}

// /api/v1/complete/<sessionId> 与 /api/v1/abort/<sessionId>：正好一段。
std::optional<QString> parseSessionTarget(QByteArrayView target, QByteArrayView prefix)
{
    const QByteArrayView rest = target.sliced(prefix.size());
    if (!isId(rest, proto::kSessionIdBytes))
        return std::nullopt;
    return QString::fromLatin1(rest.toByteArray());
}

// 问不出可用空间时返回 0。未知不等于不足——这是给用户的提示，不是安全门，
// 不该因为文件系统不配合就拒收（§5.4）。
quint64 defaultFreeSpace(const QString &dir)
{
    const QStorageInfo info(dir);
    if (!info.isValid() || !info.isReady())
        return 0;
    const qint64 available = info.bytesAvailable();
    return available > 0 ? static_cast<quint64>(available) : 0;
}

// <receive-dir>/.lanpipe-tmp/<sessionId>。会话临时目录只有这一个拼法。
QString sessionTempDir(const QString &receiveDir, const QString &sessionId)
{
    return QDir(QDir(receiveDir).filePath(QString::fromLatin1(proto::kTempDirName)))
        .filePath(sessionId);
}

void respondJson(http::HttpConnection &connection, Status status, const QJsonObject &body)
{
    connection.respond(Response::json(status, body));
}

void respondError(http::HttpConnection &connection, Status status, const QString &reason,
                  int retryAfterSeconds = 0)
{
    respondJson(connection, status, errorBody(reason, retryAfterSeconds));
}

} // namespace

ReceiveService::ReceiveService(const Settings &settings, trust::TrustStore &trust,
                               QString receiveDir, QObject *parent)
    : QObject(parent)
    , m_settings(settings)
    , m_trust(trust)
    , m_receiveDir(std::move(receiveDir))
    , m_freeSpace(&defaultFreeSpace)
{
    m_approvalTimer = new QTimer(this);
    m_approvalTimer->setSingleShot(true);
    m_approvalTimer->setInterval(proto::kApprovalWindow);
    connect(m_approvalTimer, &QTimer::timeout, this, [this] {
        if (m_pendingApproval)
            finishPrepare(*m_pendingApproval, false, /*timedOut=*/true);
    });

    m_sessionTtl = new QTimer(this);
    m_sessionTtl->setSingleShot(true);
    m_sessionTtl->setInterval(proto::kSessionTtl);
    connect(m_sessionTtl, &QTimer::timeout, this, &ReceiveService::onSessionExpired);

    m_sweepTimer = new QTimer(this);
    m_sweepTimer->setInterval(proto::kTempSweepInterval);
    connect(m_sweepTimer, &QTimer::timeout, this, [this] { sweepStaleTempData(); });
    m_sweepTimer->start();

    sweepStaleTempData(); // 上一次崩溃留下的分片在这里清掉（§5.7）
}

bool ReceiveService::handles(QByteArrayView target)
{
    return target == preparePath || target.startsWith(uploadPrefix)
        || target.startsWith(completePrefix) || target.startsWith(abortPrefix);
}

QString ReceiveService::activeSessionId() const
{
    return m_session ? m_session->sessionId() : QString();
}

void ReceiveService::setApprovalWindow(std::chrono::milliseconds window)
{
    m_approvalTimer->setInterval(window);
}

void ReceiveService::setSessionTtl(std::chrono::milliseconds ttl)
{
    m_sessionTtl->setInterval(ttl);
}

void ReceiveService::setFreeSpaceProbe(FreeSpaceProbe probe)
{
    m_freeSpace = std::move(probe);
}

int ReceiveService::sweepStaleTempData(const QDateTime &now)
{
    return sweepTempRoot(m_receiveDir, proto::kTempRetention, now);
}

int ReceiveService::ttlRemainingSeconds() const
{
    const int remaining = m_sessionTtl->remainingTime();
    return remaining > 0 ? std::max(1, remaining / 1000) : 1;
}

void ReceiveService::armSessionTtl()
{
    if (m_session)
        m_sessionTtl->start();
}

void ReceiveService::onSessionExpired()
{
    if (!m_session)
        return;
    qInfo("lanpipe: 会话 %s 空闲超时，清理临时数据",
          qPrintable(m_session->sessionId().left(8)));
    teardown(m_session->sessionId(), /*completed=*/false);
}

void ReceiveService::cancelActive()
{
    if (!m_session)
        return;
    // 拆除会 abort() 在途的连接，而 abort() 是同步把 finished 送回来的——所以
    // 拆到事件循环的下一轮再走，别在别人的调用栈上析构会话。
    const QString sessionId = m_session->sessionId();
    QMetaObject::invokeMethod(this, [this, sessionId] { teardown(sessionId, false); },
                              Qt::QueuedConnection);
}

void ReceiveService::handle(http::HttpConnection &connection)
{
    const QByteArrayView target(connection.head().target);

    if (target == preparePath) {
        handlePrepare(connection);
        return;
    }
    if (target.startsWith(uploadPrefix)) {
        handleUpload(connection);
        return;
    }
    if (target.startsWith(completePrefix)) {
        handleComplete(connection);
        return;
    }
    if (target.startsWith(abortPrefix)) {
        handleAbort(connection);
        return;
    }
    respondError(connection, Status::BadRequest, QStringLiteral("未知目标"));
}

void ReceiveService::handlePrepare(http::HttpConnection &connection)
{
    if (connection.head().method != "POST") {
        respondError(connection, Status::BadRequest, QStringLiteral("prepare 只接受 POST"));
        return;
    }

    // 一次只处理一次审批：排队会让「回答的是哪一次」变得含糊（与配对同一条理由）。
    if (m_pendingApproval) {
        respondError(connection, Status::Conflict, QStringLiteral("另一次传输正在等审批"));
        return;
    }

    auto body = std::make_shared<QByteArray>();
    // readBody 可能在调用内就发出 bodyComplete，所以先接好再读。
    connect(&connection, &HttpConnection::bodyComplete, &connection,
            [this, &connection, body] { onPrepareBody(connection, *body); });
    // 对方在等审批期间放弃了：这次请求不留任何痕迹。
    connect(&connection, &HttpConnection::finished, &connection, [this, &connection] {
        if (m_pendingApproval != &connection)
            return;
        m_pendingApproval = nullptr;
        m_approvalTimer->stop();
        dropPendingSessionTempData();
        m_pendingEntries.clear();
    });

    connection.readBody(proto::kMaxPrepareBodySize, [body](QByteArrayView chunk) {
        body->append(chunk);
        return true;
    });
}

void ReceiveService::onPrepareBody(http::HttpConnection &connection, const QByteArray &body)
{
    const auto request = transferRequestFromJson(body);
    if (!request.has_value()) {
        respondError(connection, Status::BadRequest, request.error());
        return;
    }

    // 身份只取自连接层（§4）：不取请求里的任何字段，也就没有「声称的身份」要校验。
    const net::PeerIdentity peer = connection.peer();

    // 黑名单与配对关系可能被另一个进程改过（`lanpipe block` 与 `serve` 不是一个进程）。
    // 每次 prepare 之前重读一遍，用户在别处屏蔽一台设备就立刻生效。文件很小，
    // 而 prepare 是一次传输一次的操作，不在热路径上。
    QString reloadError;
    if (!m_trust.reload(&reloadError))
        qWarning("lanpipe: 重新载入信任库失败，沿用内存里的那份：%s", qPrintable(reloadError));

    // 已配对但指纹变了：拒绝，且优先于任何策略——开放模式也不该放行一台换过密钥
    // 的设备（§4 规则 5）。
    if (m_trust.identityChanged(peer.deviceId, peer.fingerprint.toHex())) {
        respondError(connection, Status::Forbidden,
                     QStringLiteral("设备身份已变（%1）：请删除旧配对后重新配对")
                         .arg(peer.deviceId.left(8)));
        return;
    }

    // 净化先于任何路径构造，也先于审批：用户在框里看到的名字必须就是落地的名字。
    TransferRequest parsed = *request; // 这份副本用来把名字换成净化后的，供显示
    QList<ReceiveSession::Entry> entries;
    entries.reserve(request->files.size());
    for (qsizetype i = 0; i < request->files.size(); ++i) {
        const TransferFile &file = request->files.at(i);
        const auto sanitized = trust::sanitizeFilename(file.name);
        if (!sanitized.has_value()) {
            respondError(connection, Status::BadRequest,
                         QStringLiteral("文件 %1 的名字不可用：%2")
                             .arg(trust::displaySafe(file.name), sanitized.error()));
            return;
        }
        if (const auto pathOk = trust::checkFinalPath(m_receiveDir, *sanitized);
            !pathOk.has_value()) {
            respondError(connection, Status::BadRequest,
                         QStringLiteral("文件 %1：%2").arg(trust::displaySafe(*sanitized),
                                                          pathOk.error()));
            return;
        }
        ReceiveSession::Entry entry;
        entry.declared = file;
        entry.sanitized = *sanitized;
        entries.append(entry);
        parsed.files[i].name = *sanitized; // 审批界面显示的是要落地的那个名字
    }

    if (m_session) {
        respondError(connection, Status::Conflict, QStringLiteral("已有一次传输在进行中"),
                     ttlRemainingSeconds());
        return;
    }

    // 空间检查在弹框之前：用户不该为一个注定失败的传输点「接受」（§5.4）。
    const quint64 available = m_freeSpace(m_receiveDir);
    if (available > 0 && available < request->totalSize + proto::kFreeSpaceSlack) {
        respondError(connection, Status::InsufficientStorage,
                     QStringLiteral("接收目录所在卷的空间不足"));
        return;
    }

    const QString sessionId = randomHex(proto::kSessionIdBytes);
    const QString tempDir = sessionTempDir(m_receiveDir, sessionId);
    if (!QDir().mkpath(tempDir)) {
        respondError(connection, Status::InternalError,
                     QStringLiteral("无法在接收目录里建立会话临时目录"));
        return;
    }

    m_pendingApproval = &connection;
    m_pendingRequest = parsed;
    m_pendingEntries = std::move(entries);
    m_pendingPeer = peer;
    m_pendingSessionId = sessionId;

    const trust::Decision decision = trust::decide(m_settings, m_trust, peer);
    if (decision == trust::Decision::Reject) {
        // 黑名单：不回「等审批」，直接说清楚，用户不会再被它打扰。
        dropPendingSessionTempData();
        m_pendingEntries.clear();
        respondError(connection, Status::Forbidden,
                     QStringLiteral("这台设备已被屏蔽（%1）").arg(peer.deviceId.left(8)));
        return;
    }
    if (decision == trust::Decision::Accept) {
        finishPrepare(connection, true);
        return;
    }

    // 限流：提示疲劳是最短的攻击路径，问得太频繁就不再问，直接拒。
    if (!m_promptLimiter.allowPrompt(peer.deviceId)) {
        dropPendingSessionTempData();
        m_pendingEntries.clear();
        respondError(connection, Status::Forbidden,
                     QStringLiteral("这台设备请求过于频繁（%1）：稍后再试")
                         .arg(peer.deviceId.left(8)));
        return;
    }

    // 等用户期间这条连接没有任何字节流动，空闲计时必须让开（§5.8）——否则连接超时
    // 与审批窗口同时到期，发送方看到的是「连接被掐断」而不是 504。
    connection.pauseIdleTimeout();
    m_approvalTimer->start();
    emit approvalRequired(m_pendingRequest);
}

void ReceiveService::submitApproval(bool accepted)
{
    if (!m_pendingApproval)
        return; // 超时或对端已经断开
    finishPrepare(*m_pendingApproval, accepted);
}

void ReceiveService::submitBlock()
{
    if (!m_pendingApproval)
        return;

    trust::TrustStore::BlockedEntry entry;
    entry.deviceId = m_pendingPeer.deviceId;
    entry.name = m_pendingRequest.senderName;
    entry.blockedAt = QDateTime::currentDateTimeUtc();

    QString error;
    if (!m_trust.block(entry, &error)) {
        // 落盘失败也照样拒——用户点的是「拒绝并屏蔽」，至少要做到拒绝。
        qWarning("lanpipe: 屏蔽 %s 失败：%s", qPrintable(entry.deviceId.left(8)),
                 qPrintable(error));
    } else {
        emit peerBlocked(entry.deviceId, entry.name);
    }

    finishPrepare(*m_pendingApproval, false);
}

void ReceiveService::finishPrepare(http::HttpConnection &connection, bool accepted, bool timedOut)
{
    if (m_pendingApproval != &connection)
        return;

    m_pendingApproval = nullptr;
    m_approvalTimer->stop();
    connection.resumeIdleTimeout();

    if (!accepted) {
        dropPendingSessionTempData();
        m_pendingEntries.clear();
        if (timedOut) {
            respondError(connection, Status::GatewayTimeout, QStringLiteral("等用户审批超时"));
            return;
        }
        respondError(connection, Status::Forbidden, QStringLiteral("接收方拒绝了这次传输"));
        return;
    }

    acceptRequest(connection);
}

void ReceiveService::dropPendingSessionTempData()
{
    if (m_pendingSessionId.isEmpty())
        return; // 判空必不可少：空 id 会指向 .lanpipe-tmp 根目录，那一下删掉的是所有会话
    removeTreeSafely(sessionTempDir(m_receiveDir, m_pendingSessionId));
    // 顺带收掉空掉的根目录，别在用户的接收目录里留一个空壳。
    QDir().rmdir(QDir(m_receiveDir).filePath(QString::fromLatin1(proto::kTempDirName)));
    m_pendingSessionId.clear();
}

void ReceiveService::acceptRequest(http::HttpConnection &connection)
{
    // 用 prepare 阶段定下的那个 id：临时目录那时就建好了，也验证过可写。
    const QString sessionId = std::exchange(m_pendingSessionId, QString());
    if (m_session) // 理论到不了这里；真到了也不能让两个会话同时存在
        teardown(m_session->sessionId(), false);

    m_session = std::make_unique<ReceiveSession>(sessionId, m_pendingPeer,
                                                 m_pendingRequest.senderName,
                                                 std::move(m_pendingEntries),
                                                 m_pendingRequest.totalSize, m_receiveDir);
    m_pendingEntries.clear();
    m_pendingRequest = {};

    respondJson(connection, Status::Ok, prepareResponse(sessionId));
    armSessionTtl();
}

ReceiveSession *ReceiveService::requireSession(http::HttpConnection &connection,
                                              const QString &sessionId)
{
    if (!m_session || m_session->sessionId() != sessionId) {
        respondError(connection, Status::Gone, QStringLiteral("会话不存在或已结束"));
        return nullptr;
    }
    // 会话归属由证书决定，不由请求里的任何字段决定。128 位的 sessionId 猜不到，
    // 但这条与「身份判定只有一处」是同一条规矩。
    if (m_session->sender().deviceId != connection.peer().deviceId) {
        respondError(connection, Status::Forbidden, QStringLiteral("这个会话不属于你"));
        return nullptr;
    }
    return m_session.get();
}

void ReceiveService::handleUpload(http::HttpConnection &connection)
{
    if (connection.head().method != "PUT") {
        respondError(connection, Status::BadRequest, QStringLiteral("upload 只接受 PUT"));
        return;
    }

    const auto ids = parseUploadTarget(QByteArrayView(connection.head().target));
    if (!ids.has_value()) {
        respondError(connection, Status::BadRequest, QStringLiteral("上传路径格式不对"));
        return;
    }
    const QString &sessionId = ids->first;
    const QString &fileId = ids->second;

    ReceiveSession *session = requireSession(connection, sessionId);
    if (!session)
        return;

    ReceiveSession::Entry *entry = session->find(fileId);
    if (!entry) {
        respondError(connection, Status::Conflict, QStringLiteral("这个文件不在本次声明的清单里"));
        return;
    }
    if (entry->committed) {
        respondError(connection, Status::Conflict, QStringLiteral("该文件已经接收完毕"));
        return;
    }
    if (entry->inFlight) {
        respondError(connection, Status::Conflict, QStringLiteral("该文件正在传输中"));
        return;
    }

    // 声明的长度必须正好等于批准的大小（§5.3）。少了这一条，批准 1 MB 可以传 100 GB。
    // 缺 Content-Length 按 0 算：零字节文件自然通过，其余自然被拒。
    const quint64 declared = connection.head().hasContentLength ? connection.head().contentLength : 0;
    if (declared != entry->declared.size) {
        respondError(connection, Status::Conflict,
                     QStringLiteral("声明的长度（%1）与批准的（%2）不符")
                         .arg(declared)
                         .arg(entry->declared.size));
        return;
    }

    m_uploadSink = session->openSink(*entry);
    if (!m_uploadSink) {
        respondError(connection, Status::InsufficientStorage,
                     QStringLiteral("无法在接收目录里创建临时文件"));
        return;
    }
    m_uploadDevice = m_uploadSink->open();
    if (!m_uploadDevice) {
        m_uploadSink.reset();
        respondError(connection, Status::InternalError, QStringLiteral("无法打开临时文件"));
        return;
    }

    entry->inFlight = true;
    m_upload = &connection;
    m_uploadFileId = fileId;
    m_uploadWritten = 0;
    m_sessionTtl->stop(); // PUT 在途时由连接自己的空闲计时兜底，别让 TTL 从中间打断

    // 连接断了（对端被杀、空闲超时、接收方取消）：会话留着，重传会从头再来。
    connect(&connection, &HttpConnection::finished, &connection,
            [this, &connection, sessionId, fileId] {
                if (m_upload != &connection)
                    return; // 已经正常收尾过
                discardUpload();
                if (m_session && m_session->sessionId() == sessionId) {
                    if (ReceiveSession::Entry *entry = m_session->find(fileId))
                        entry->inFlight = false;
                    armSessionTtl();
                }
            });

    connect(&connection, &HttpConnection::bodyComplete, &connection,
            [this, &connection, fileId] { commitUpload(connection, fileId); });

    // 先答应 Expect: 100-continue 再读体，否则 curl 这类客户端白等一秒（§5.15）。
    connection.sendContinue();

    const quint64 expected = entry->declared.size;
    connection.readBody(expected, [this, &connection, fileId, expected](QByteArrayView chunk) {
        if (!m_uploadDevice)
            return false; // 状态已经被收走了（拆除、失败）：按放弃处理，别再往下写
        const qint64 written = m_uploadDevice->write(chunk.data(), chunk.size());
        if (written != chunk.size()) {
            // 写盘失败（多半是空间不够）：给一个可读的状态码再关连接，而不是闷声断连。
            connection.failBody(Response::json(
                Status::InsufficientStorage,
                errorBody(QStringLiteral("写入接收目录失败"))));
            return false;
        }
        m_uploadWritten += static_cast<quint64>(written);
        emit fileProgress(fileId, m_uploadWritten, expected);
        return true;
    });
}

void ReceiveService::commitUpload(http::HttpConnection &connection, const QString &fileId)
{
    ReceiveSession *session = m_session.get();
    if (!session || session->sessionId().isEmpty()) {
        respondError(connection, Status::Gone, QStringLiteral("会话已结束"));
        discardUpload();
        return;
    }

    ReceiveSession::Entry *entry = session->find(fileId);

    // 失败时除了回答，还要把这个文件从「在传」状态里放出来——否则它再也传不了
    // （重传会拿到「该文件正在传输中」）。
    const auto failUpload = [&](Status status, const QString &reason) {
        if (entry)
            entry->inFlight = false;
        respondError(connection, status, reason);
        discardUpload();
    };

    if (!entry || !m_uploadSink) {
        failUpload(Status::Conflict, QStringLiteral("上传状态已失效"));
        return;
    }

    if (m_uploadWritten != entry->declared.size) {
        failUpload(Status::Conflict,
                   QStringLiteral("实际收到的字节数（%1）与批准的（%2）不符")
                       .arg(m_uploadWritten)
                       .arg(entry->declared.size));
        return;
    }

    // 到这里才改名：文件在**自己的 PUT 返回 200 的那一刻**就位（§5.2）。
    if (!session->commitFile(*entry, *m_uploadSink)) {
        failUpload(Status::InternalError, QStringLiteral("无法把文件改名到接收目录"));
        return;
    }

    const QString finalPath = entry->finalPath;
    const quint64 bytes = entry->committedBytes;

    releaseUpload();
    armSessionTtl();

    QJsonObject object;
    object.insert(QStringLiteral("id"), fileId);
    object.insert(QStringLiteral("bytes"), static_cast<double>(bytes));
    respondJson(connection, Status::Ok, object);

    emit fileCommitted(fileId, finalPath, bytes);
}

void ReceiveService::releaseUpload()
{
    m_upload = nullptr;
    m_uploadFileId.clear();
    m_uploadSink.reset();
    m_uploadDevice.reset();
    m_uploadWritten = 0;
}

void ReceiveService::discardUpload()
{
    if (m_uploadSink)
        m_uploadSink->discard();
    releaseUpload();
}

void ReceiveService::handleComplete(http::HttpConnection &connection)
{
    if (connection.head().method != "POST") {
        respondError(connection, Status::BadRequest, QStringLiteral("complete 只接受 POST"));
        return;
    }

    const auto sessionId = parseSessionTarget(QByteArrayView(connection.head().target), completePrefix);
    if (!sessionId.has_value()) {
        respondError(connection, Status::BadRequest, QStringLiteral("complete 路径格式不对"));
        return;
    }

    ReceiveSession *session = requireSession(connection, *sessionId);
    if (!session)
        return;

    // complete 是报告，不是断言：它回答「每个文件到了多少字节」，不因为缺文件而报错
    // ——发送方要能区分「对方没发完」与「协议出错」。
    respondJson(connection, Status::Ok, toJson(session->report()));
    teardown(*sessionId, /*completed=*/true);
}

void ReceiveService::handleAbort(http::HttpConnection &connection)
{
    if (connection.head().method != "POST") {
        respondError(connection, Status::BadRequest, QStringLiteral("abort 只接受 POST"));
        return;
    }

    const auto sessionId = parseSessionTarget(QByteArrayView(connection.head().target), abortPrefix);
    if (!sessionId.has_value()) {
        respondError(connection, Status::BadRequest, QStringLiteral("abort 路径格式不对"));
        return;
    }

    // 取消是幂等的：目标状态（没有这个会话）已经达成，不该因为「别人已经清过了」
    // 让发送方的取消路径看到错误。
    if (m_session && m_session->sessionId() == *sessionId) {
        if (m_session->sender().deviceId != connection.peer().deviceId) {
            respondError(connection, Status::Forbidden, QStringLiteral("这个会话不属于你"));
            return;
        }
        teardown(*sessionId, /*completed=*/false); // 先拆再答：200 到达时临时数据已经没了
    }

    respondJson(connection, Status::Ok, QJsonObject());
}

void ReceiveService::teardown(const QString &sessionId, bool completed)
{
    if (!m_session || m_session->sessionId() != sessionId)
        return;

    m_sessionTtl->stop();

    // 先把会话摘下来：abort() 是同步把 finished 送回来的，那些槽不能再碰它。
    std::unique_ptr<ReceiveSession> session = std::move(m_session);

    // 连接指针要先取出来再清状态：清完之后 abort() 触发的那次 finished 会因为
    // m_upload 已经为空而直接返回（它不该再去动已经拆掉的东西）。
    http::HttpConnection *upload = m_upload;
    discardUpload();

    if (upload)
        upload->abort(); // 取消不回 410、不发响应，直接关（§5.5）

    session->destroyTempData();
    // 顺带收掉空掉的根目录：不然用户的接收目录里永远留一个 .lanpipe-tmp 空壳。
    QDir().rmdir(QDir(m_receiveDir).filePath(QString::fromLatin1(proto::kTempDirName)));
    emit sessionFinished(sessionId, completed);
}

} // namespace lanpipe::transfer
