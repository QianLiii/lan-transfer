#include "avahidiscovery.h"

#include <QDBusArgument>
#include <QDBusMetaType>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QVariant>

namespace lanpipe::discovery {

namespace {

// Avahi 的「任意接口 / 任意协议」哨兵值（avahi-common/defs.h）。
constexpr int kIfUnspec = -1;
constexpr int kProtoUnspec = -1;

// 解析一条服务要问守护进程一次；它是本机 D-Bus 往返，正常在毫秒级。
// 给个上限是为了一个卡住的守护进程不把我们的界面拖住。
constexpr int kCallTimeoutMs = 5000;

const QString kServiceName = QStringLiteral("org.freedesktop.Avahi");
const QString kServerPath = QStringLiteral("/");
const QString kServerInterface = QStringLiteral("org.freedesktop.Avahi.Server");
const QString kEntryGroupInterface = QStringLiteral("org.freedesktop.Avahi.EntryGroup");
const QString kBrowserInterface = QStringLiteral("org.freedesktop.Avahi.ServiceBrowser");

QString serviceTypeName()
{
    return QString::fromLatin1(proto::kServiceType);
}

QByteArray txtEntry(std::string_view key, const QByteArray &value)
{
    QByteArray out(key.data(), static_cast<qsizetype>(key.size()));
    out += '=';
    out += value;
    return out;
}

// TXT 串 → 键值。没有 '=' 的条目直接忽略——TXT 里允许放裸标志位，我们不使用。
QHash<QString, QByteArray> parseTxt(const QList<QByteArray> &record)
{
    QHash<QString, QByteArray> fields;
    for (const QByteArray &entry : record) {
        const qsizetype separator = entry.indexOf('=');
        if (separator <= 0)
            continue;
        fields.insert(QString::fromLatin1(entry.left(separator)), entry.mid(separator + 1));
    }
    return fields;
}

} // namespace

QString AvahiDiscovery::subscribeKey(const QString &name, int interface, int protocol)
{
    return QStringLiteral("%1|%2|%3").arg(name).arg(interface).arg(protocol);
}

AvahiDiscovery::AvahiDiscovery(Config config, QObject *parent)
    : Discovery(parent), m_config(std::move(config))
{
    // TXT 记录的线格式是 aay，也就是 QList<QByteArray>；QtDBus 不预注册这个类型，
    // 不注册的表现是发消息时 "Marshalling failed: Unregistered type"。
    qDBusRegisterMetaType<QByteArrayList>();

    if (m_config.instanceName.isEmpty()) {
        // §3.8：用户可见的名字是 TXT 的 name；mDNS 实例名只是网上唯一的标识，
        // 系统还会在冲突时自动改名，所以拿 deviceId 前缀保证唯一即可。
        m_config.instanceName =
            QStringLiteral("lanpipe-%1").arg(m_config.self.deviceId().left(8));
    }

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(m_config.refresh);
    connect(m_refreshTimer, &QTimer::timeout, this, &AvahiDiscovery::refresh);
}

AvahiDiscovery::~AvahiDiscovery()
{
    stop();
}

bool AvahiDiscovery::isAvailable()
{
    const QDBusConnection connection = QDBusConnection::systemBus();
    if (!connection.isConnected())
        return false;
    return connection.interface()->isServiceRegistered(kServiceName);
}

void AvahiDiscovery::fail(const QString &reason)
{
    m_lastError = reason;
    stop();
}

void AvahiDiscovery::start()
{
    if (m_started)
        return; // 幂等

    m_lastError.clear();

    const QDBusConnection connection = bus();
    if (!connection.isConnected()) {
        fail(QStringLiteral("系统 D-Bus 未连接，无法使用 Avahi"));
        return;
    }
    if (!connection.interface()->isServiceRegistered(kServiceName)) {
        fail(QStringLiteral("avahi-daemon 未在系统总线上运行（装上并启动它，或改用 UDP 广播）"));
        return;
    }

    m_started = true;

    if (m_config.announce)
        registerService();
    if (!m_lastError.isEmpty())
        return; // 注册失败已经 stop() 过了

    browse();
    if (!m_lastError.isEmpty())
        return;

    m_refreshTimer->start();
}

void AvahiDiscovery::registerService()
{
    const QDBusMessage groupReply =
        bus().call(QDBusMessage::createMethodCall(kServiceName, kServerPath, kServerInterface,
                                                  QStringLiteral("EntryGroupNew")),
                   QDBus::Block, kCallTimeoutMs);
    if (groupReply.type() != QDBusMessage::ReplyMessage) {
        fail(QStringLiteral("向 Avahi 申请 EntryGroup 失败：%1").arg(groupReply.errorMessage()));
        return;
    }
    m_entryGroupPath = groupReply.arguments().constFirst().value<QDBusObjectPath>().path();

    QList<QByteArray> txt;
    txt << txtEntry(proto::kTxtKeyFp, m_config.self.fingerprint.toLatin1())
        << txtEntry(proto::kTxtKeyName, txtTruncated(m_config.self.name))
        << txtEntry(proto::kTxtKeyVer, QByteArray::number(m_config.self.version));

    QDBusMessage add = QDBusMessage::createMethodCall(kServiceName, m_entryGroupPath,
                                                     kEntryGroupInterface,
                                                     QStringLiteral("AddService"));
    // 接口与协议都用「任意」：守护进程替我们决定往哪些接口上注册。
    //
    // 端口必须显式包成 ushort：QVariant 没有 ushort 的构造函数，quint16 会被提升成
    // int，线上签名就成了 i 而不是 Avahi 要的 q，报「方法不存在」。
    const QVariant port = QVariant::fromValue<ushort>(static_cast<ushort>(m_config.self.port));
    add << kIfUnspec << kProtoUnspec << uint(0) << m_config.instanceName << serviceTypeName()
        << QString() /* domain：默认 .local */
        << QString() /* host：默认本机主机名 */
        << port << QVariant::fromValue(txt);

    const QDBusMessage addReply = bus().call(add, QDBus::Block, kCallTimeoutMs);
    if (addReply.type() != QDBusMessage::ReplyMessage) {
        fail(QStringLiteral("注册服务失败：%1").arg(addReply.errorMessage()));
        return;
    }

    const QDBusMessage commitReply =
        bus().call(QDBusMessage::createMethodCall(kServiceName, m_entryGroupPath,
                                                  kEntryGroupInterface, QStringLiteral("Commit")),
                   QDBus::Block, kCallTimeoutMs);
    if (commitReply.type() != QDBusMessage::ReplyMessage) {
        fail(QStringLiteral("提交服务注册失败：%1").arg(commitReply.errorMessage()));
        return;
    }
}

void AvahiDiscovery::browse()
{
    QDBusMessage msg = QDBusMessage::createMethodCall(kServiceName, kServerPath, kServerInterface,
                                                     QStringLiteral("ServiceBrowserNew"));
    msg << kIfUnspec << kProtoUnspec << serviceTypeName() << QString() << uint(0);

    const QDBusMessage reply = bus().call(msg, QDBus::Block, kCallTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        fail(QStringLiteral("启动服务浏览失败：%1").arg(reply.errorMessage()));
        return;
    }
    m_browserPath = reply.arguments().constFirst().value<QDBusObjectPath>().path();

    const bool connected = bus().connect(kServiceName, m_browserPath, kBrowserInterface,
                                         QStringLiteral("ItemNew"), this,
                                         SLOT(onItemNew(int, int, QString, QString, QString, uint)))
        && bus().connect(kServiceName, m_browserPath, kBrowserInterface,
                         QStringLiteral("ItemRemove"), this,
                         SLOT(onItemRemove(int, int, QString, QString, QString, uint)));
    if (!connected) {
        fail(QStringLiteral("订阅 Avahi 的浏览结果失败"));
        return;
    }
}

void AvahiDiscovery::stop()
{
    if (!m_started)
        return;
    m_started = false;
    m_refreshTimer->stop();

    QDBusConnection connection = bus();
    if (!m_browserPath.isEmpty() && connection.isConnected()) {
        connection.disconnect(kServiceName, m_browserPath, kBrowserInterface, QStringLiteral("ItemNew"),
                              this, SLOT(onItemNew(int, int, QString, QString, QString, uint)));
        connection.disconnect(kServiceName, m_browserPath, kBrowserInterface,
                              QStringLiteral("ItemRemove"), this,
                              SLOT(onItemRemove(int, int, QString, QString, QString, uint)));
        connection.call(QDBusMessage::createMethodCall(kServiceName, m_browserPath,
                                                       kBrowserInterface, QStringLiteral("Free")),
                        QDBus::NoBlock);
        m_browserPath.clear();
    }
    if (!m_entryGroupPath.isEmpty() && connection.isConnected()) {
        connection.call(QDBusMessage::createMethodCall(kServiceName, m_entryGroupPath,
                                                       kEntryGroupInterface, QStringLiteral("Free")),
                        QDBus::NoBlock);
        m_entryGroupPath.clear();
    }
    m_resolved.clear();
}

void AvahiDiscovery::onItemNew(int interface, int protocol, const QString &name,
                               const QString &type, const QString &domain, uint flags)
{
    Q_UNUSED(flags);
    if (type != serviceTypeName())
        return; // 同一条总线上的其它服务类型，不关我们的事

    // 解析要问守护进程一次：ItemNew 只给了实例名，地址与端口在 SRV/TXT 里。
    // 同一个服务在每个接口、每种地址族上各来一次，这正是「一个 deviceId 一组地址」的来源。
    QDBusMessage msg = QDBusMessage::createMethodCall(kServiceName, kServerPath, kServerInterface,
                                                     QStringLiteral("ResolveService"));
    msg << interface << protocol << name << type << domain << kProtoUnspec << uint(0);

    const QDBusMessage reply = bus().call(msg, QDBus::Block, kCallTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        // 服务在我们解析之前就消失了，是常态，不是错误。
        return;
    }

    // out: i interface, i protocol, s name, s type, s domain, s host, i aprotocol,
    //      s address, q port, aay txt, u flags
    const QList<QVariant> out = reply.arguments();
    if (out.size() < 10)
        return;

    const QString address = out.at(7).toString();
    const quint16 port = out.at(8).value<quint16>();

    QList<QByteArray> txt;
    if (out.at(9).canConvert<QDBusArgument>())
        out.at(9).value<QDBusArgument>() >> txt;

    const QHash<QString, QByteArray> fields = parseTxt(txt);
    Advertisement advertisement;
    advertisement.fingerprint =
        QString::fromLatin1(fields.value(QString::fromLatin1(proto::kTxtKeyFp)));
    advertisement.name = QString::fromUtf8(fields.value(QString::fromLatin1(proto::kTxtKeyName)));
    advertisement.version =
        fields.value(QString::fromLatin1(proto::kTxtKeyVer)).toInt();
    advertisement.port = port;

    // deviceId 由指纹现算，指纹不是 64 个十六进制字符就算字段不合法。
    if (advertisement.deviceId().isEmpty() || port == 0)
        return; // 不是我们的服务，或者字段不合法

    // 自己的注册守护进程也会报回来。
    if (advertisement.fingerprint.compare(m_config.self.fingerprint, Qt::CaseInsensitive) == 0)
        return;

    Announcement announcement;
    announcement.advertisement = advertisement;
    announcement.address = QHostAddress(address);
    announcement.seenAt = QDateTime::currentDateTimeUtc();

    m_resolved.insert(subscribeKey(name, interface, protocol), Resolved{announcement});
    emit announced(announcement);
}

void AvahiDiscovery::onItemRemove(int interface, int protocol, const QString &name,
                                  const QString &type, const QString &domain, uint flags)
{
    Q_UNUSED(type);
    Q_UNUSED(domain);
    Q_UNUSED(flags);
    // 只是不再重发；PeerDirectory 的超时判定会把它摘掉（§3.3）。
    m_resolved.remove(subscribeKey(name, interface, protocol));
}

void AvahiDiscovery::refresh()
{
    // DNS-SD 的浏览结果是一份稳定列表，不像广播那样每 2 秒自己响一次。所以这里
    // 主动把还活着的条目再报一遍，PeerDirectory 的超时判定对两种后端才是同一套。
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (auto it = m_resolved.begin(); it != m_resolved.end(); ++it) {
        it->announcement.seenAt = now;
        emit announced(it->announcement);
    }
}

} // namespace lanpipe::discovery
