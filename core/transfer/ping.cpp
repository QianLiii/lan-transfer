#include "ping.h"

#include "mtls.h"
#include "protocol.h"
#include "random.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonValue>
#include <QStringList>

namespace lanpipe::transfer {

namespace {

// 一个定长的十六进制字段。长度不符或含非十六进制字符都算失败。
std::expected<QString, QString> hexField(const QJsonObject &object, const char *key,
                                         int characters)
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

bool isHexString(const QString &text, int characters)
{
    if (text.size() != characters)
        return false;
    for (const QChar c : text) {
        if (!((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f') || (c >= u'A' && c <= u'F')))
            return false;
    }
    return true;
}

} // namespace

QJsonObject toJson(const PingInfo &info)
{
    QJsonObject object;
    object.insert(QStringLiteral("deviceId"), info.deviceId);
    object.insert(QStringLiteral("name"), info.name);
    object.insert(QStringLiteral("ver"), info.version);
    object.insert(QStringLiteral("fp"), info.fingerprint.toHex());
    object.insert(QStringLiteral("snonce"), info.snonce);
    object.insert(QStringLiteral("reachable"), info.reachable);
    return object;
}

std::expected<PingInfo, QString> pingInfoFromJson(const QByteArray &body)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (document.isNull() || !document.isObject())
        return std::unexpected(
            QStringLiteral("响应体不是 JSON 对象：%1").arg(parseError.errorString()));

    const QJsonObject object = document.object();

    const auto deviceId = hexField(object, "deviceId", kDeviceIdBytes * 2);
    if (!deviceId.has_value())
        return std::unexpected(deviceId.error());

    const auto fingerprintHex = hexField(object, "fp", 32 * 2);
    if (!fingerprintHex.has_value())
        return std::unexpected(fingerprintHex.error());

    const auto fingerprint = Fingerprint::fromHex(*fingerprintHex);
    if (!fingerprint.has_value())
        return std::unexpected(QStringLiteral("字段 fp 不是有效的指纹"));

    const auto snonce = hexField(object, "snonce", proto::kNonceBytes * 2);
    if (!snonce.has_value())
        return std::unexpected(snonce.error());

    const QJsonValue name = object.value(QStringLiteral("name"));
    if (!name.isString())
        return std::unexpected(QStringLiteral("字段 name 缺失或不是字符串"));

    const QJsonValue version = object.value(QStringLiteral("ver"));
    if (!version.isDouble())
        return std::unexpected(QStringLiteral("字段 ver 缺失或不是整数"));

    const QJsonValue reachable = object.value(QStringLiteral("reachable"));
    if (!reachable.isBool())
        return std::unexpected(QStringLiteral("字段 reachable 缺失或不是布尔值"));

    PingInfo info;
    info.deviceId = *deviceId;
    info.name = name.toString();
    info.version = version.toInt();
    info.fingerprint = *fingerprint;
    info.snonce = *snonce;
    info.reachable = reachable.toBool();
    return info;
}

std::expected<QString, QString> cnonceFromTarget(QByteArrayView targetView)
{
    const QByteArray target(targetView);
    const QByteArray path(proto::kPathPing.data(), proto::kPathPing.size());
    if (!target.startsWith(path))
        return std::unexpected(QStringLiteral("请求目标不是 %1").arg(QString::fromLatin1(path)));

    const QByteArray prefix = QByteArrayLiteral("?cnonce=");
    const QByteArray rest = target.mid(path.size());
    if (!rest.startsWith(prefix))
        return std::unexpected(QStringLiteral("请求目标必须带 ?cnonce=<hex>"));

    const QString cnonce = QString::fromLatin1(rest.mid(prefix.size()));
    if (!isHexString(cnonce, proto::kNonceBytes * 2))
        return std::unexpected(
            QStringLiteral("cnonce 必须是 %1 位十六进制").arg(proto::kNonceBytes * 2));
    return cnonce;
}

PingService::PingService(const Identity &identity, const Settings &settings, SasCache &sasCache,
                         QObject *parent)
    : QObject(parent), m_identity(identity), m_settings(settings), m_sasCache(sasCache)
{
}

bool PingService::handles(QByteArrayView target)
{
    const QByteArrayView path(proto::kPathPing.data(), proto::kPathPing.size());
    return target.startsWith(path);
}

void PingService::handle(http::HttpConnection &connection)
{
    using http::Status;

    if (connection.head().method != "GET") {
        connection.respond(http::Response::text(Status::BadRequest, QStringLiteral("只接受 GET")));
        return;
    }

    const auto cnonce = cnonceFromTarget(connection.head().target);
    if (!cnonce.has_value()) {
        connection.respond(http::Response::text(Status::BadRequest, cnonce.error()));
        return;
    }

    // 对端身份取自这次握手看到的证书，不取任何请求里的声明（§4）。
    const auto peer = net::peerFingerprint(connection.peerCertificate());
    if (!peer.has_value()) {
        connection.respond(http::Response::text(Status::Forbidden, peer.error()));
        return;
    }

    PingInfo info;
    info.deviceId = m_identity.deviceId();
    info.name = m_settings.deviceName();
    info.version = proto::kVersion;
    info.fingerprint = m_identity.fingerprint();
    info.snonce = randomHex(proto::kNonceBytes);
    // 能走到这里就说明网络可达，而会话上限要到 M3 才存在（§5.13）。
    info.reachable = true;

    // 码在这一次交换里定下，并缓存到 deviceId 上：prepare 走的是另一条连接，
    // 那时拿不到新的 snonce（§4 规则 3）。
    const QString peerDeviceId = deviceIdFrom(*peer);
    const QString code =
        sasCode(computeSas(*peer, m_identity.fingerprint(), *cnonce, info.snonce));
    m_sasCache.store(peerDeviceId, {code, *peer, QDateTime::currentDateTimeUtc()});
    emit codeSettled(peerDeviceId, code);

    connection.respond(http::Response::json(Status::Ok, toJson(info)));
}

} // namespace lanpipe::transfer
