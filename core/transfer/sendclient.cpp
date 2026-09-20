#include "sendclient.h"

#include "mtls.h"
#include "protocol.h"
#include "random.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

#include <algorithm>
#include <utility>

namespace lanpipe::transfer {

namespace {

// 请求超时逐跳不同：prepare 要等接收方的用户点「接受」，PUT 只按进度算死活。
// 两个都必须显式设置——QNetworkRequest 不设就是「不超时」（§5.9）。
std::chrono::milliseconds timeoutFor(bool isUpload)
{
    return isUpload ? proto::kStallTimeout : proto::kSenderRequestTimeout;
}

} // namespace

SendClient::SendClient(trust::TrustStore &trust, QObject *parent)
    : QObject(parent), m_manager(new QNetworkAccessManager(this)), m_trust(trust), m_pin(trust)
{
    qRegisterMetaType<SendClient::Result>();

    // 不跟随重定向：跳到另一个源就等于把请求交给没有做指纹比对的一方（与配对同）。
    m_manager->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
}

SendClient::~SendClient() = default;

QUrl SendClient::urlWithPath(const std::string &path) const
{
    QUrl url = m_baseUrl;
    url.setPath(QString::fromStdString(path));
    return url;
}

QNetworkRequest SendClient::makeRequest(const QUrl &url) const
{
    QNetworkRequest request(url);
    request.setSslConfiguration(net::mtlsConfiguration(m_identity));
    return request;
}

void SendClient::wireReply(QNetworkReply *reply)
{
    connect(reply, &QNetworkReply::sslErrors, this,
            [this, reply](const QList<QSslError> &errors) { m_pin.handleSslErrors(reply, errors); });
}

void SendClient::start(const QUrl &url, const Identity &identity, const QString &deviceName,
                       const QList<std::shared_ptr<files::FileSource>> &sources,
                       std::optional<Fingerprint> expected)
{
    m_identity = identity;
    m_pin.reset();
    m_pin.setExpected(std::move(expected));
    // 传文件不是配对：没有比对码兜底，对端必须已经在信任库里（§4 规则 5）。
    m_pin.setRequirePaired(true);
    m_baseUrl = url;
    m_deviceName = deviceName;
    m_sessionId.clear();
    m_items.clear();
    m_index = 0;
    m_totalBytes = 0;
    m_cancelled = false;
    m_reported = false;
    m_peerContacted = false;
    m_device.reset();
    m_step = Step::Preparing;
    m_result = {};

    for (const std::shared_ptr<files::FileSource> &source : sources) {
        if (!source) {
            fail(QStringLiteral("有一个文件的来源是空的"));
            return;
        }
        // §5.14：大小定不下来就不发。让用户批准一个「不知道多大」的东西，
        // 等于让审批界面失去意义——那条路留给将来明确支持不确定态的版本。
        const auto size = source->size();
        if (!size.has_value()) {
            fail(QStringLiteral("无法确定 %1 的大小：请在接收方那边改用别的文件，或先把它存到本地")
                     .arg(source->displayName()));
            return;
        }

        Item item;
        item.id = randomHex(proto::kFileIdBytes);
        item.name = source->displayName();
        item.size = *size;
        item.source = source;
        m_totalBytes += item.size;
        m_items.append(item);
    }

    m_result.totalBytes = m_totalBytes;
    sendPrepare();
}

void SendClient::sendPrepare()
{
    TransferRequest request;
    request.senderName = m_deviceName;
    request.totalSize = m_totalBytes;
    for (const Item &item : m_items) {
        TransferFile file;
        file.id = item.id;
        file.name = item.name;
        file.size = item.size;
        request.files.append(file);
    }

    QNetworkRequest networkRequest(makeRequest(urlWithPath(std::string(proto::kPathPrepare))));
    networkRequest.setTransferTimeout(timeoutFor(/*isUpload=*/false));
    networkRequest.setHeader(QNetworkRequest::ContentTypeHeader,
                             QStringLiteral("application/json"));

    m_step = Step::Preparing;
    QNetworkReply *reply = m_manager->post(
        networkRequest,
        QJsonDocument(toJson(request)).toJson(QJsonDocument::Compact));
    m_reply = reply;
    wireReply(reply);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply] { onReplyFinished(reply, Step::Preparing); });
}

void SendClient::sendNextFile()
{
    while (m_index < m_items.size() && m_items.at(m_index).done)
        ++m_index;

    if (m_index >= m_items.size()) {
        sendComplete();
        return;
    }

    Item &item = m_items[m_index];

    // prepare 之后文件可能被改过。QNAM 在「设备比声明的短」时会把 Content-Length
    // 改小（接收方会 409，可接受），但「设备比声明的长」时它只发声明的那部分——
    // 接收方会收到一个大小完全正确的截断文件，静默出错。这里自己先拦住。
    const auto currentSize = item.source->size();
    if (!currentSize.has_value()) {
        fail(QStringLiteral("%1 在 prepare 之后读不到大小了").arg(item.name));
        return;
    }
    if (*currentSize != item.size) {
        fail(QStringLiteral("%1 在 prepare 之后变了（声明 %2 字节，现在是 %3 字节）")
                 .arg(item.name)
                 .arg(item.size)
                 .arg(*currentSize));
        return;
    }

    m_device.reset(); // 上一个设备到这里才换掉（见 onReplyFinished 里的说明）
    m_device = item.source->open();
    if (!m_device) {
        fail(QStringLiteral("无法打开 %1").arg(item.name));
        return;
    }

    QNetworkRequest request(
        makeRequest(urlWithPath(proto::uploadPath(m_sessionId.toStdString(), item.id.toStdString()))));
    request.setTransferTimeout(timeoutFor(/*isUpload=*/true));

    m_step = Step::Uploading;
    QNetworkReply *reply = m_manager->put(request, m_device.get());
    m_reply = reply;
    wireReply(reply);

    // 按下标找条目，不捕获引用：m_items 只在 start() 里重建，但引用会让这条
    // 连接的存活期与那个下标绑在一起，读起来不能确定。
    const qsizetype index = m_index;
    connect(reply, &QNetworkReply::uploadProgress, this,
            [this, index](qint64 sent, qint64 total) {
                // §5.10：这是「交给 socket 的字节数」，比写入磁盘的计数靠前一个
                // socket 缓冲加一块。收到 200 之前不能显示完成。
                //
                // 只看单调增长：Qt 在连接收尾时还会补发一次 (0, 0)，照单全收会把
                // 计数打回 0，让最后那次端到端核对误判成「没收到」。
                if (index >= m_items.size() || sent <= 0 || total <= 0)
                    return;
                Item &item = m_items[index];
                item.sent = std::max(item.sent, static_cast<quint64>(sent));
                emit fileProgress(item.id, item.sent, static_cast<quint64>(total));
            });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply] { onReplyFinished(reply, Step::Uploading); });
}

void SendClient::sendComplete()
{
    QNetworkRequest request(makeRequest(urlWithPath(proto::completePath(m_sessionId.toStdString()))));
    request.setTransferTimeout(timeoutFor(/*isUpload=*/false));

    m_step = Step::Completing;
    QNetworkReply *reply = m_manager->post(request, QByteArray());
    m_reply = reply;
    wireReply(reply);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply] { onReplyFinished(reply, Step::Completing); });
}

void SendClient::sendAbort()
{
    if (m_sessionId.isEmpty()) {
        Result result;
        result.cancelled = m_cancelled;
        result.error = m_cancelled ? QStringLiteral("已取消") : m_result.error;
        reportResult(result);
        return;
    }

    QNetworkRequest request(makeRequest(urlWithPath(proto::abortPath(m_sessionId.toStdString()))));
    request.setTransferTimeout(timeoutFor(/*isUpload=*/false));

    QNetworkReply *reply = m_manager->post(request, QByteArray());
    m_reply = reply;
    wireReply(reply);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply] { onReplyFinished(reply, Step::Aborting); });
}

void SendClient::onReplyFinished(QNetworkReply *reply, Step step)
{
    reply->deleteLater();
    if (m_reply == reply)
        m_reply = nullptr;
    m_peerContacted = true;

    // 设备**不在这里**销毁：取消路径上 abort() 之后 QNAM 仍可能再读一次，删早了
    // 就是踩空（实测崩在 QNonContiguousByteDeviceIoDeviceImpl::advanceReadPointerEx）。
    // 它由下一次上传替换、或随本对象一起销毁——多留一个文件句柄而已。

    if (step == Step::Aborting) {
        // 收尾请求的结果不重要：它的作用是让接收方早点清掉临时数据。
        Result result;
        result.cancelled = m_cancelled;
        result.error = m_cancelled ? QStringLiteral("已取消") : m_result.error;
        reportResult(result);
        return;
    }

    if (m_cancelled)
        return; // 被取消时中断的那条 reply，收尾交给 cancel()

    if (!m_pin.adoptFromReply(reply)) {
        fail(m_pin.error());
        return;
    }

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray body = reply->readAll();
    if (status != 200) {
        fail(status > 0 ? QStringLiteral("对端返回 %1：%2").arg(status).arg(reasonFrom(body))
                        : QStringLiteral("请求失败：%1").arg(reply->errorString()));
        return;
    }

    if (step == Step::Preparing) {
        const auto sessionId = sessionIdFromJson(body);
        if (!sessionId.has_value()) {
            fail(sessionId.error());
            return;
        }
        m_sessionId = *sessionId;
        emit prepared(m_sessionId);
        sendNextFile();
        return;
    }

    if (step == Step::Uploading) {
        m_items[m_index].done = true;
        ++m_index;
        sendNextFile();
        return;
    }

    // Completing：端到端核对。complete 是这次传输唯一的整体校验点（§5.2）。
    const auto report = completeReportFromJson(body);
    if (!report.has_value()) {
        fail(report.error());
        return;
    }

    Result result;
    result.totalBytes = m_totalBytes;
    for (const Item &item : m_items) {
        if (report->bytesFor(item.id) != item.sent)
            result.unverifiedFiles.append(item.name);
    }

    if (result.unverifiedFiles.isEmpty()) {
        result.ok = true;
    } else {
        result.error = QStringLiteral("%1 个文件没有被完整接收（%2）")
                           .arg(result.unverifiedFiles.size())
                           .arg(result.unverifiedFiles.join(QStringLiteral("、")));
    }

    m_step = Step::Done;
    reportResult(result);
}

void SendClient::fail(const QString &error)
{
    if (m_reported || m_step == Step::Done) {
        m_step = Step::Done;
        return;
    }

    m_result.ok = false;
    m_result.error = error;

    // 已经开始传输了就先告诉接收方，别让它抱着临时数据等到 TTL。
    if (!m_sessionId.isEmpty() && m_step != Step::Aborting) {
        m_step = Step::Aborting;
        sendAbort();
        return;
    }

    m_step = Step::Done;
    reportResult(m_result);
}

void SendClient::cancel()
{
    if (m_reported)
        return;

    m_cancelled = true;
    if (m_reply)
        m_reply->abort(); // 在途的请求直接掐掉

    if (m_sessionId.isEmpty()) {
        m_step = Step::Done;
        Result result;
        result.cancelled = true;
        result.error = QStringLiteral("已取消");
        reportResult(result);
        return;
    }

    m_step = Step::Aborting;
    sendAbort();
}

void SendClient::reportResult(Result result)
{
    if (m_reported)
        return;
    m_reported = true;
    m_step = Step::Done;
    emit finished(result);
}

} // namespace lanpipe::transfer
