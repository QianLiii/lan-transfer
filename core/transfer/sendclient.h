#pragma once

// 发送方：prepare → 逐个 PUT → complete（§5）。
//
// 显式状态机，不是回调链：串行多步套 lambda 会变成一层套一层，而每一步的失败处理
// 与取消都要重写一遍。这里每一跳只做一件事，由 reply 的 finished 驱动。
//
// 每个请求都新建连接（§5.15 的一条连接一个请求），也就都要重新做一次指纹判定。

#include "files/filesource.h"
#include "identity.h"
#include "transfer/peerpinning.h"
#include "transfer/transfer.h"

#include <QObject>
#include <QStringList>
#include <QUrl>

#include <memory>
#include <optional>

class QNetworkAccessManager;
class QNetworkReply;
class QNetworkRequest;
class QIODevice;

namespace lanpipe::transfer {

class SendClient : public QObject
{
    Q_OBJECT

public:
    struct Result
    {
        bool ok = false;
        bool cancelled = false;
        QString error;
        quint64 totalBytes = 0;
        // 端到端核对没过的文件：complete 报回来的字节数与实际发出的不符。
        QStringList unverifiedFiles;
    };

    explicit SendClient(trust::TrustStore &trust, QObject *parent = nullptr);
    ~SendClient() override;

    // 每个 source 的 size() 都必须有值：大小定不下来的文件在 prepare 之前就被拒，
    // 一个请求都不发（§5.14）。
    void start(const QUrl &url, const Identity &identity, const QString &deviceName,
               const QList<std::shared_ptr<files::FileSource>> &sources,
               std::optional<Fingerprint> expected = std::nullopt);

    // 发送方取消：尽力通知接收方（abort），然后本地收尾。
    void cancel();

    // 有过一次回话（哪怕内容是拒绝）。逐地址回退只该在「完全没连上」时触发：
    // 收到任何应答都说明这个地址是通的，问题在别处。
    [[nodiscard]] bool peerContacted() const { return m_peerContacted; }

signals:
    // 握手完成、对端指纹已核对。**每次传输只发一次，且在 prepare 之前**。
    //
    // 调用方据此撤销「逐个地址的时限」：那个时限只管建立连接，而 prepare 的 200
    // 要等对方的用户点审批（最长 kApprovalWindow）。挂在 prepared 上会让一次正常
    // 的、需要人工审批的传输在 3 秒后被当成地址不可用。
    void connected();

    void prepared(const QString &sessionId);
    void fileProgress(const QString &fileId, quint64 sent, quint64 total);
    void finished(const lanpipe::transfer::SendClient::Result &result);

private:
    enum class Step { Idle, Preparing, Uploading, Completing, Aborting, Done };

    struct Item
    {
        QString id;
        QString name;
        quint64 size = 0;
        std::shared_ptr<files::FileSource> source;
        quint64 sent = 0;
        bool done = false;
    };

    void sendPrepare();
    void sendNextFile();
    void sendComplete();
    void sendAbort();

    // generation 用来丢弃上一轮的 finished：start() 会中止在途的 reply，而中止之后
    // 那条 reply 仍会把 finished 送到这里——带着旧 step 改新一轮的状态。
    void onReplyFinished(QNetworkReply *reply, Step step, quint64 generation);
    void wireReply(QNetworkReply *reply); // 指纹判定 + 进度
    [[nodiscard]] QNetworkRequest makeRequest(const QUrl &url) const;
    [[nodiscard]] QUrl urlWithPath(const std::string &path) const;

    void fail(const QString &error);
    void reportResult(Result result);
    // 对端已经通过指纹判定：报一次 connected()（幂等）。
    void notePeerReached();

    QNetworkAccessManager *m_manager = nullptr;
    trust::TrustStore &m_trust;
    PeerPin m_pin;
    Identity m_identity;

    Step m_step = Step::Idle;
    QUrl m_baseUrl;
    QString m_deviceName; // 随 prepare 交给接收方：它的用户要先看到「这是谁」
    QString m_sessionId;
    QList<Item> m_items;
    quint64 m_totalBytes = 0;
    qsizetype m_index = 0;

    QNetworkReply *m_reply = nullptr;
    quint64 m_generation = 0; // 每次 start() 自增；旧轮的信号一律丢弃
    // QNAM 不接管设备：它必须活到 reply 的 finished（头文件已经写明）。
    std::unique_ptr<QIODevice> m_device;
    Result m_result; // 失败原因在中途就记下，收尾时统一报出去
    bool m_peerContacted = false;
    bool m_peerReachable = false; // connected() 每次传输只发一次
    bool m_cancelled = false;
    bool m_reported = false;
};

} // namespace lanpipe::transfer

Q_DECLARE_METATYPE(lanpipe::transfer::SendClient::Result)
