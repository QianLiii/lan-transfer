#include "ping.h"

#include "mtls.h"
#include "protocol.h"
#include "random.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonValue>

#include <cmath>
#include <memory>
#include <utility>

namespace lanpipe::transfer {

namespace {

// 一个定长的十六进制字段。长度不符或含非十六进制字符都算失败。
std::expected<QString, QString> hexField(const QJsonObject &object, const char *key, int characters)
{
    const QJsonValue value = object.value(QLatin1String(key));
    if (!value.isString())
        return std::unexpected(QStringLiteral("字段 %1 缺失或不是字符串").arg(QLatin1String(key)));

    const QString text = value.toString();
    if (text.size() != characters)
        return std::unexpected(
            QStringLiteral("字段 %1 长度应为 %2").arg(QLatin1String(key)).arg(characters));

    for (const QChar c : text) {
        if (!((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f') || (c >= u'A' && c <= u'F')))
            return std::unexpected(QStringLiteral("字段 %1 含非十六进制字符").arg(QLatin1String(key)));
    }
    return text;
}

} // namespace

QJsonObject toJson(const PingRequest &request)
{
    QJsonObject object;
    object.insert(QStringLiteral("cnonce"), request.cnonce);
    object.insert(QStringLiteral("name"), request.name);
    return object;
}

std::expected<PingRequest, QString> pingRequestFromJson(const QByteArray &body)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (document.isNull())
        return std::unexpected(QStringLiteral("请求体不是合法 JSON：%1").arg(parseError.errorString()));
    if (!document.isObject())
        return std::unexpected(QStringLiteral("请求体不是 JSON 对象"));

    const QJsonObject object = document.object();

    const auto cnonce = hexField(object, "cnonce", proto::kNonceBytes * 2);
    if (!cnonce.has_value())
        return std::unexpected(cnonce.error());

    const QJsonValue name = object.value(QStringLiteral("name"));
    if (!name.isString())
        return std::unexpected(QStringLiteral("字段 name 缺失或不是字符串"));
    // 设备名有长度上限：它会进信任库、进配对提示、进 devices 列表，而这里不拦的话
    // 唯一约束只是请求体那 4 KB。
    if (name.toString().toUtf8().size() > static_cast<qsizetype>(proto::kMaxDisplayNameBytes)) {
        return std::unexpected(
            QStringLiteral("字段 name 超过 %1 字节").arg(proto::kMaxDisplayNameBytes));
    }

    PingRequest request;
    request.cnonce = *cnonce;
    request.name = name.toString();
    return request;
}

QJsonObject toJson(const PingInfo &info)
{
    QJsonObject object;
    object.insert(QStringLiteral("name"), info.name);
    object.insert(QStringLiteral("ver"), info.version);
    object.insert(QStringLiteral("fp"), info.fingerprint.toHex());
    object.insert(QStringLiteral("reachable"), info.reachable);
    return object;
}

std::expected<PingInfo, QString> pingInfoFromJson(const QByteArray &body)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (document.isNull())
        return std::unexpected(QStringLiteral("响应体不是合法 JSON：%1").arg(parseError.errorString()));
    if (!document.isObject())
        return std::unexpected(QStringLiteral("响应体不是 JSON 对象"));

    const QJsonObject object = document.object();

    const auto fingerprintHex = hexField(object, "fp", 32 * 2);
    if (!fingerprintHex.has_value())
        return std::unexpected(fingerprintHex.error());

    const auto fingerprint = Fingerprint::fromHex(*fingerprintHex);
    if (!fingerprint.has_value())
        return std::unexpected(QStringLiteral("字段 fp 不是有效的指纹"));

    const QJsonValue name = object.value(QStringLiteral("name"));
    if (!name.isString())
        return std::unexpected(QStringLiteral("字段 name 缺失或不是字符串"));
    // 响应里的名字同样有上限：它是对端可控的字节，我们会拿它写信任库、打终端。
    if (name.toString().toUtf8().size() > static_cast<qsizetype>(proto::kMaxDisplayNameBytes))
        return std::unexpected(QStringLiteral("字段 name 超过 %1 字节").arg(proto::kMaxDisplayNameBytes));

    const QJsonValue version = object.value(QStringLiteral("ver"));
    if (!version.isDouble())
        return std::unexpected(QStringLiteral("字段 ver 缺失或不是整数"));
    // 整数性与范围：只查 isDouble 的话，1.5 会被 toInt() 截成 1、1e300 变成未定义值。
    const double versionNumber = version.toDouble();
    if (!std::isfinite(versionNumber) || std::floor(versionNumber) != versionNumber
        || versionNumber < 1 || versionNumber > 1000) {
        return std::unexpected(QStringLiteral("字段 ver 不是有效的协议版本"));
    }

    const QJsonValue reachable = object.value(QStringLiteral("reachable"));
    if (!reachable.isBool())
        return std::unexpected(QStringLiteral("字段 reachable 缺失或不是布尔值"));

    PingInfo info;
    info.name = name.toString();
    info.version = version.toInt();
    info.fingerprint = *fingerprint;
    info.reachable = reachable.toBool();
    return info;
}

PingService::PingService(const Identity &identity, const Settings &settings, trust::TrustStore &trust,
                         QObject *parent)
    : QObject(parent), m_identity(identity), m_settings(settings), m_trust(trust)
{
    m_inputTimer = new QTimer(this);
    m_inputTimer->setSingleShot(true);
    m_inputTimer->setInterval(proto::kSasInputWindow);
    connect(m_inputTimer, &QTimer::timeout, this, [this] { finish(Outcome::TimedOut, {}); });
}

bool PingService::handles(QByteArrayView target)
{
    const QByteArrayView path(proto::kPathPing.data(), proto::kPathPing.size());
    return target == path;
}

void PingService::handle(http::HttpConnection &connection)
{
    using http::Status;

    if (m_pending) {
        // 已经有一次配对在等用户输入。第二个 ping 直接拒掉，而不是排队——
        // 排队会让「回答的是哪一次」变得含糊。
        connection.respond(
            http::Response::text(Status::Conflict, QStringLiteral("已有一次配对在进行中")));
        return;
    }

    if (connection.head().method != "POST") {
        connection.respond(http::Response::text(Status::BadRequest, QStringLiteral("只接受 POST")));
        return;
    }

    // 体很小，但仍是不可信输入：先按上限收完再解析。readBody 可能在调用内就发出
    // bodyComplete（体为空或已全部到达），所以连接必须先接好。
    auto body = std::make_shared<QByteArray>();
    connect(&connection, &http::HttpConnection::bodyComplete, &connection,
            [this, &connection, body] { onRequestComplete(connection, *body); });

    // 对方可能在等我们用户输入期间就放弃了。连接一断，这次配对就不该留下任何记录：
    // 那台设备并没有得到我们的答复。
    connect(&connection, &http::HttpConnection::finished, &connection, [this, &connection] {
        if (m_pending != &connection)
            return;
        m_pending = nullptr;
        m_inputTimer->stop();
        qInfo("lanpipe: %s", qPrintable(QStringLiteral("配对中断：对端已断开（%1）")
                                            .arg(m_peerDeviceId.left(8))));
        emit pairingFinished(m_peerDeviceId, Outcome::Rejected);
    });

    connection.readBody(proto::kMaxPingBodySize, [body](QByteArrayView chunk) {
        body->append(chunk);
        return true;
    });
}

void PingService::onRequestComplete(http::HttpConnection &connection, const QByteArray &body)
{
    using http::Status;

    const auto request = pingRequestFromJson(body);
    if (!request.has_value()) {
        connection.respond(http::Response::text(Status::BadRequest, request.error()));
        return;
    }

    // 对端身份由连接层在握手后判定，取自那次握手看到的证书，不取请求里的任何声明
    // （§4）。走到这里的连接一定带着有效身份，因此这里没有失败分支。
    const net::PeerIdentity &peer = connection.peer();
    const QString observed = peer.fingerprint.toHex();

    // 黑名单可能被另一个进程改过（`lanpipe block` 与 `serve` 不是一个进程），
    // 所以动手之前重读一遍。屏蔽的意义就是不再被它打扰——配对请求也算打扰。
    QString reloadError;
    if (!m_trust.reload(&reloadError))
        qWarning("lanpipe: 重新载入信任库失败，沿用内存里的那份：%s", qPrintable(reloadError));

    if (m_trust.isBlocked(peer.deviceId)) {
        const QString reason = QStringLiteral("这台设备已被屏蔽（%1）").arg(peer.deviceId.left(8));
        connection.respond(http::Response::text(http::Status::Forbidden, reason));
        emit pairingFinished(peer.deviceId, Outcome::Rejected);
        return;
    }

    // 已配对但指纹变了：这台设备换过密钥，必须拒绝，绝不静默重新配对（§4 规则 5）。
    if (m_trust.identityChanged(peer.deviceId, observed)) {
        const QString reason = QStringLiteral("设备身份已变（%1）：请删除旧配对后重新配对")
                                   .arg(peer.deviceId.left(8));
        qWarning("lanpipe: %s", qPrintable(reason));
        connection.respond(http::Response::text(Status::Forbidden, reason));
        emit pairingFinished(peer.deviceId, Outcome::Rejected);
        return;
    }

    // 接收方取后半显示、要求输入前半（§4 配对）。输入只有两个指纹与 cnonce，
    // 所以两端在请求发出的前后就都算得出全部 12 位。
    const SasCode code = sasCode(
        SasRole::Receiver,
        computeSas(peer.fingerprint, m_identity.fingerprint(), request->cnonce));

    PingInfo info;
    info.name = m_settings.deviceName();
    info.version = proto::kVersion;
    info.fingerprint = m_identity.fingerprint();
    // 能走到这里就说明网络可达，而会话上限要到 M3 才存在（§5.13）。
    info.reachable = true;

    // 响应推迟到用户输入之后才发：结论要随它回去（200 = 本端也通过了）。
    // 等用户期间这条连接没有任何字节流动，空闲计时必须让开（§5.8）。
    connection.pauseIdleTimeout();

    m_pending = &connection;
    m_code = code;
    m_info = info;
    m_peerDeviceId = peer.deviceId;
    m_peerName = request->name;
    m_inputTimer->start();
    emit inputRequired(m_peerDeviceId, m_peerName, m_code);
}

void PingService::setInputWindow(std::chrono::milliseconds window)
{
    m_inputTimer->setInterval(window);
}

void PingService::submitInput(const QString &typed)
{
    if (!m_pending)
        return; // 超时或已经被回答过

    finish(m_code.matches(typed) ? Outcome::Accepted : Outcome::Mismatch, {});
}

void PingService::finish(Outcome outcome, const QString &reason)
{
    if (!m_pending)
        return;

    http::HttpConnection *connection = std::exchange(m_pending, nullptr);
    m_inputTimer->stop();
    if (!connection)
        return; // 对端已经断开，onConnectionGone 处理过了
    connection->resumeIdleTimeout();

    switch (outcome) {
    case Outcome::Accepted: {
        // 本端比对通过之后才写入信任库。写的是**观察到的**指纹，不是请求里的
        // 任何声明（§4 规则 4）。
        QString error;
        if (!m_trust.add({m_peerDeviceId, connection->peer().fingerprint.toHex(), m_peerName,
                          QDateTime::currentDateTimeUtc()},
                         &error)) {
            qWarning("lanpipe: 配对通过但写入信任库失败：%s", qPrintable(error));
            connection->respond(
                http::Response::text(http::Status::InternalError, QStringLiteral("无法保存配对")));
            emit pairingFinished(m_peerDeviceId, Outcome::Rejected);
            return;
        }
        connection->respond(http::Response::json(http::Status::Ok, toJson(m_info)));
        emit pairingFinished(m_peerDeviceId, Outcome::Accepted);
        return;
    }
    case Outcome::Mismatch:
        connection->respond(http::Response::text(
            http::Status::Forbidden, QStringLiteral("配对码不一致")));
        emit pairingFinished(m_peerDeviceId, Outcome::Mismatch);
        return;
    case Outcome::TimedOut:
        connection->respond(http::Response::text(
            http::Status::GatewayTimeout, QStringLiteral("等用户输入超时")));
        emit pairingFinished(m_peerDeviceId, Outcome::TimedOut);
        return;
    case Outcome::Rejected:
        break;
    }

    connection->respond(http::Response::text(http::Status::Forbidden, reason));
    emit pairingFinished(m_peerDeviceId, Outcome::Rejected);
}

} // namespace lanpipe::transfer
