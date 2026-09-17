#include "broadcastdiscovery.h"

#include "protocol.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkInterface>
#include <QRandomGenerator>
#include <QTimer>

namespace lanpipe::discovery {

namespace {

// §3.2：单条 TXT 串上限 255 字节。广播载荷没有这个限制，但两边用的是同一组
// 字段，用同一个上限才不会出现「TXT 截断了、广播没有」这种不一致。
constexpr int kMaxNameBytes = 255;

// 一次 readyRead 最多处理这么多报文：一个灌包的邻居不该把事件循环占住。
constexpr int kMaxDatagramsPerRead = 64;

QByteArray truncatedToBytes(const QString &text, int maxBytes)
{
    const QByteArray utf8 = text.toUtf8();
    if (utf8.size() <= maxBytes)
        return utf8;

    // 按 UTF-8 边界回退，避免截出半个字符。
    int end = maxBytes;
    while (end > 0 && (static_cast<unsigned char>(utf8.at(end)) & 0xC0) == 0x80)
        --end;
    return utf8.left(end);
}

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
            return std::unexpected(
                QStringLiteral("字段 %1 含非十六进制字符").arg(QLatin1String(key)));
    }
    return text;
}

} // namespace

QByteArray encodeAdvertisement(const Advertisement &advertisement)
{
    QJsonObject object;
    object.insert(QStringLiteral("id"), advertisement.deviceId);
    object.insert(QStringLiteral("name"),
                  QString::fromUtf8(truncatedToBytes(advertisement.name, kMaxNameBytes)));
    object.insert(QStringLiteral("fp"), advertisement.fingerprint);
    object.insert(QStringLiteral("ver"), advertisement.version);
    object.insert(QStringLiteral("port"), advertisement.port);
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

std::expected<Advertisement, QString> decodeAdvertisement(QByteArrayView datagram)
{
    QJsonParseError parseError;
    const QJsonDocument document =
        QJsonDocument::fromJson(QByteArray(datagram).left(kMaxAnnouncementSize), &parseError);
    if (document.isNull() || !document.isObject())
        return std::unexpected(
            QStringLiteral("载荷不是 JSON 对象：%1").arg(parseError.errorString()));

    const QJsonObject object = document.object();

    const auto deviceId = hexField(object, "id", proto::kDeviceIdBytes * 2);
    if (!deviceId.has_value())
        return std::unexpected(deviceId.error());

    const auto fingerprint = hexField(object, "fp", 32 * 2);
    if (!fingerprint.has_value())
        return std::unexpected(fingerprint.error());

    const QJsonValue name = object.value(QStringLiteral("name"));
    if (!name.isString())
        return std::unexpected(QStringLiteral("字段 name 缺失或不是字符串"));
    if (name.toString().toUtf8().size() > kMaxNameBytes)
        return std::unexpected(QStringLiteral("字段 name 超过 %1 字节").arg(kMaxNameBytes));

    const QJsonValue version = object.value(QStringLiteral("ver"));
    if (!version.isDouble())
        return std::unexpected(QStringLiteral("字段 ver 缺失或不是整数"));

    const QJsonValue port = object.value(QStringLiteral("port"));
    if (!port.isDouble())
        return std::unexpected(QStringLiteral("字段 port 缺失或不是整数"));
    const int portValue = port.toInt();
    if (portValue <= 0 || portValue > 65535)
        return std::unexpected(QStringLiteral("字段 port 不在 1–65535 内"));

    Advertisement advertisement;
    advertisement.deviceId = *deviceId;
    advertisement.name = name.toString();
    advertisement.fingerprint = *fingerprint;
    advertisement.version = version.toInt();
    advertisement.port = static_cast<quint16>(portValue);
    return advertisement;
}

BroadcastDiscovery::BroadcastDiscovery(Config config, QObject *parent)
    : Discovery(parent), m_config(std::move(config))
{
}

QString BroadcastDiscovery::backendName() const
{
    return QStringLiteral("broadcast");
}

quint16 BroadcastDiscovery::boundPort() const
{
    return m_socket ? m_socket->localPort() : 0;
}

void BroadcastDiscovery::start()
{
    if (m_socket)
        return; // 幂等

    if (m_config.announce && m_config.self.port == 0) {
        // 通告一个端口 0 等于通告「我不知道自己在哪个端口」，对方拿到也没用。
        m_lastError = QStringLiteral("监听端口为 0，没有可通告的内容");
        return;
    }

    m_socket = new QUdpSocket(this);
    // ShareAddress：同一台机器上跑两个实例时要能同时收到广播（§3.4）。
    // Qt 对 IPv4 UDP socket 会自动设置 SO_BROADCAST，无需另行设置。
    if (!m_socket->bind(m_config.bindAddress, m_config.bindPort,
                        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        m_lastError = QStringLiteral("无法绑定 %1:%2：%3")
                          .arg(m_config.bindAddress.toString())
                          .arg(m_config.bindPort)
                          .arg(m_socket->errorString());
        delete m_socket;
        m_socket = nullptr;
        return;
    }

    connect(m_socket, &QUdpSocket::readyRead, this, &BroadcastDiscovery::onReadyRead);

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true); // 每次重设间隔，抖动才有意义
    connect(m_timer, &QTimer::timeout, this, &BroadcastDiscovery::sendAdvertisement);
    sendAdvertisement();          // 起手先发一次，别让对方等满一个周期
}

void BroadcastDiscovery::stop()
{
    if (m_timer) {
        m_timer->stop();
        delete m_timer;
        m_timer = nullptr;
    }
    if (m_socket) {
        m_socket->close();
        delete m_socket;
        m_socket = nullptr;
    }
}

void BroadcastDiscovery::sendAdvertisement()
{
    if (!m_socket)
        return;

    if (!m_config.announce) {
        // 只收不发：不排下一次，也就不会有下一次。
        return;
    }

    const QByteArray payload = encodeAdvertisement(m_config.self);
    const QList<QHostAddress> destinations = targets();
    // sendPort 为 0 表示「发往自己绑定的端口」。必须在绑定之后解析——配置里写 0
    // 时真实端口是系统分配的，构造时还不知道。
    const quint16 port = m_config.sendPort != 0 ? m_config.sendPort : m_socket->localPort();

    m_lastError.clear();
    if (destinations.isEmpty()) {
        m_lastError = QStringLiteral("没有可用的广播地址（没有已启用的 IPv4 接口？）");
    } else {
        for (const QHostAddress &destination : destinations) {
            const qint64 sent = m_socket->writeDatagram(payload, destination, port);
            if (sent != payload.size()) {
                m_lastError = QStringLiteral("向 %1 发送失败：%2")
                                  .arg(destination.toString(), m_socket->errorString());
            }
        }
    }

    if (m_timer) {
        const auto jitter = m_config.jitter.count() > 0
            ? std::chrono::milliseconds(QRandomGenerator::system()->bounded(
                  static_cast<quint32>(m_config.jitter.count())))
            : std::chrono::milliseconds(0);
        m_timer->start(m_config.interval + jitter);
    }
}

QList<QHostAddress> BroadcastDiscovery::targets() const
{
    if (!m_config.targets.isEmpty())
        return m_config.targets;

    // 各接口的子网广播地址（192.168.31.255 这类）。只发 255.255.255.255 的话，
    // 多网卡的机器上只会从默认路由那一块出去，其余接口上的对端什么都收不到。
    QList<QHostAddress> destinations;
    for (const QNetworkInterface &interface : QNetworkInterface::allInterfaces()) {
        const auto flags = interface.flags();
        if (!(flags & QNetworkInterface::IsUp) || !(flags & QNetworkInterface::IsRunning)
            || (flags & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        for (const QNetworkAddressEntry &entry : interface.addressEntries()) {
            const QHostAddress broadcast = entry.broadcast();
            if (broadcast.isNull() || broadcast.protocol() != QAbstractSocket::IPv4Protocol)
                continue;
            if (!destinations.contains(broadcast))
                destinations.append(broadcast);
        }
    }

    // 一个接口广播地址都没拿到时的兜底（某些平台或某些网卡不上报）。全局广播
    // 只从一个接口出去，不如上面精确，但总比不发强。
    if (destinations.isEmpty())
        destinations.append(QHostAddress(QHostAddress::Broadcast));

    return destinations;
}

void BroadcastDiscovery::onReadyRead()
{
    for (int i = 0; i < kMaxDatagramsPerRead && m_socket->hasPendingDatagrams(); ++i) {
        // 固定缓冲 + 定长读取：报文多大都不会让我们分配内存，超出部分被截断，
        // 解析随即失败并被丢弃。
        char buffer[kMaxAnnouncementSize + 1];
        QHostAddress sender;
        quint16 senderPort = 0;
        const qint64 size = m_socket->readDatagram(buffer, sizeof(buffer), &sender, &senderPort);
        if (size <= 0)
            continue;

        const auto advertisement = decodeAdvertisement(QByteArrayView(buffer, size));
        if (!advertisement.has_value()) {
            // 用 qDebug：默认不显示，排查时用 QT_LOGGING_RULES 打开。
            // 这里不能用 qWarning——一个灌包的邻居会把它变成日志洪水。
            qDebug("lanpipe: 丢弃一条广播通告：%s", qPrintable(advertisement.error()));
            continue;
        }

        // 自己发的广播会回环到本机。
        if (advertisement->deviceId == m_config.self.deviceId)
            continue;

        Announcement announcement;
        announcement.advertisement = *advertisement;
        announcement.address = sender;
        announcement.seenAt = QDateTime::currentDateTimeUtc();
        emit announced(announcement);
    }
}

} // namespace lanpipe::discovery
