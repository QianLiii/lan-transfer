#include "windnssddiscovery.h"

#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QMetaObject>
#include <QtEndian>

#include <cstring>

namespace lanpipe::discovery {

namespace {

// windns.h 里这几个声明的版本门槛是 Windows 10 1809（RS5）。
constexpr DWORD kRequestVersion = DNS_QUERY_REQUEST_VERSION1;

QString serviceTypeSuffix()
{
    // 浏览与注册都用完全限定名：<实例>._lanpipe._tcp.local
    return QStringLiteral(".%1.local").arg(QString::fromLatin1(proto::kServiceType));
}

QStringList instanceNamesFrom(PDNS_RECORD records)
{
    const QString suffix = serviceTypeSuffix();
    QStringList names;
    for (PDNS_RECORD record = records; record != nullptr; record = record->pNext) {
        if (record->wType != DNS_TYPE_PTR || record->Data.PTR.pNameHost == nullptr)
            continue;
        const QString name = QString::fromWCharArray(record->Data.PTR.pNameHost);
        if (name.endsWith(suffix) && !names.contains(name))
            names.append(name);
    }
    return names;
}

QHash<QString, QByteArray> txtFrom(const DNS_SERVICE_INSTANCE *instance)
{
    QHash<QString, QByteArray> fields;
    for (DWORD i = 0; i < instance->dwPropertyCount; ++i) {
        if (instance->keys == nullptr || instance->keys[i] == nullptr)
            continue;
        const QString key = QString::fromWCharArray(instance->keys[i]);
        const QString value = instance->values != nullptr && instance->values[i] != nullptr
            ? QString::fromWCharArray(instance->values[i])
            : QString();
        fields.insert(key, value.toUtf8());
    }
    return fields;
}

// 文档与实测都提示这两个字段可能为空，空的时候由调用方按主机名再解析一次。
QStringList addressesFrom(const DNS_SERVICE_INSTANCE *instance)
{
    QStringList addresses;
    if (instance->ip4Address != nullptr) {
        quint32 raw = 0;
        std::memcpy(&raw, instance->ip4Address, sizeof(raw));
        addresses.append(QHostAddress(qFromBigEndian(raw)).toString());
    }
    if (instance->ip6Address != nullptr) {
        Q_IPV6ADDR raw; // 注意名字：Qt 里是 Q_IPV6ADDR，不是 Q_IPv6Address
        std::memcpy(&raw, instance->ip6Address, sizeof(raw));
        addresses.append(QHostAddress(raw).toString());
    }
    return addresses;
}

} // namespace

WinDnsSdDiscovery::WinDnsSdDiscovery(Config config, QObject *parent)
    : Discovery(parent), m_config(std::move(config))
{
    if (m_config.instanceName.isEmpty())
        m_config.instanceName = QStringLiteral("lanpipe-%1").arg(m_config.self.deviceId.left(8));

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(m_config.refresh);
    connect(m_refreshTimer, &QTimer::timeout, this, &WinDnsSdDiscovery::refresh);
}

WinDnsSdDiscovery::~WinDnsSdDiscovery()
{
    stop();

    // 取消是异步的，回调还可能再来一次。把每个上下文指向本对象的指针置空——
    // 取到锁说明此刻没有回调正在投递。上下文本身仍然不释放（见头文件），
    // 因为无法知道最后一个回调何时到达。
    for (PVOID raw : m_contexts) {
        auto *context = static_cast<CallbackContext *>(raw);
        const std::lock_guard<std::mutex> lock(context->mutex);
        context->owner = nullptr;
    }
    // 已经投递、尚未派发的事件由 Qt 在对象析构时丢弃。
}

void WinDnsSdDiscovery::postToOwner(PVOID queryContext,
                                    const std::function<void(WinDnsSdDiscovery *)> &emit)
{
    auto *context = static_cast<CallbackContext *>(queryContext);
    if (context == nullptr)
        return;
    const std::lock_guard<std::mutex> lock(context->mutex);
    if (context->owner == nullptr)
        return;
    emit(context->owner); // 只做队列投递，不在锁里调用对象
}

void WinDnsSdDiscovery::fail(const QString &reason)
{
    m_lastError = reason;
    stop();
}

void WinDnsSdDiscovery::start()
{
    if (m_started)
        return;
    m_lastError.clear();

    const QString hostName = QHostInfo::localHostName();
    if (hostName.isEmpty()) {
        fail(QStringLiteral("拿不到本机主机名，无法注册 DNS-SD 服务"));
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

void WinDnsSdDiscovery::registerService()
{
    // 实例名要完全限定，主机名要带 .local 后缀。
    m_wideName.assign({(m_config.instanceName + serviceTypeSuffix()).toStdWString()});
    m_wideHost.assign({(hostName + QStringLiteral(".local")).toStdWString()});

    m_wideKeys.assign({
        QString::fromLatin1(proto::kTxtKeyId).toStdWString(),
        QString::fromLatin1(proto::kTxtKeyFp).toStdWString(),
        QString::fromLatin1(proto::kTxtKeyName).toStdWString(),
        QString::fromLatin1(proto::kTxtKeyVer).toStdWString(),
    });
    m_wideValues.assign({
        m_config.self.deviceId.toStdWString(),
        m_config.self.fingerprint.toStdWString(),
        QString::fromUtf8(txtTruncated(m_config.self.name)).toStdWString(),
        QString::number(m_config.self.version).toStdWString(),
    });

    // 四个 vector 都已定型，这里取到的指针在整个注册期间有效——push_back 之后再取
    // 会让先前取到的 c_str() 因扩容而失效。
    std::vector<PCWSTR> keyPointers;
    std::vector<PCWSTR> valuePointers;
    keyPointers.reserve(m_wideKeys.size());
    valuePointers.reserve(m_wideValues.size());
    for (const std::wstring &key : m_wideKeys)
        keyPointers.push_back(key.c_str());
    for (const std::wstring &value : m_wideValues)
        valuePointers.push_back(value.c_str());

    // 地址传 nullptr：由系统按本机实际接口决定，这正是我们要的。
    //
    // keys / values 的形参是 PCWSTR *（指向常量的指针），不是 PWSTR *：
    // T ** → const T ** 不能隐式转换，所以这里必须原样传 PCWSTR *，
    // 用 const_cast<PWSTR *> 反而编不过。
    m_registeredInstance = DnsServiceConstructInstance(
        m_wideName.front().data(), m_wideHost.front().data(), nullptr, nullptr,
        m_config.self.port, 0 /* priority */, 0 /* weight */,
        static_cast<DWORD>(keyPointers.size()), keyPointers.data(), valuePointers.data());

    if (m_registeredInstance == nullptr) {
        fail(QStringLiteral("构造 DNS-SD 服务实例失败"));
        return;
    }

    m_registerRequest = {};
    m_registerRequest.Version = kRequestVersion;
    m_registerRequest.InterfaceIndex = 0; // 所有接口
    m_registerRequest.pServiceInstance = m_registeredInstance;
    m_registerRequest.pQueryContext = new CallbackContext(this); // 故意不释放
    m_contexts.push_back(m_registerRequest.pQueryContext);
    m_registerRequest.pRegisterCompletionCallback = &WinDnsSdDiscovery::onRegisterComplete;
    m_registerRequest.unicastEnabled = FALSE;

    const DWORD result = DnsServiceRegister(&m_registerRequest, nullptr);
    if (result != DNS_REQUEST_PENDING) {
        fail(QStringLiteral("DnsServiceRegister 失败（错误码 %1）").arg(result));
        return;
    }
    m_registered = true;
}

void WinDnsSdDiscovery::browse()
{
    // 查询名同样只在调用期间需要有效。
    const std::wstring queryName =
        QStringLiteral("%1.local").arg(QString::fromLatin1(proto::kServiceType)).toStdWString();

    DNS_SERVICE_BROWSE_REQUEST request{};
    request.Version = kRequestVersion;
    request.InterfaceIndex = 0; // 所有接口
    request.QueryName = queryName.c_str();
    request.pQueryContext = new CallbackContext(this); // 故意不释放
    m_contexts.push_back(request.pQueryContext);
    request.pBrowseCallback = &WinDnsSdDiscovery::onBrowseComplete;

    const DWORD result = DnsServiceBrowse(&request, &m_browseCancel);
    if (result != DNS_REQUEST_PENDING) {
        // 没插网线时这里就是 ERROR_NO_NETWORK（1222）。
        fail(QStringLiteral("DnsServiceBrowse 失败（错误码 %1）").arg(result));
        return;
    }
}

VOID WINAPI WinDnsSdDiscovery::onRegisterComplete(DWORD status, PVOID queryContext,
                                                  PDNS_SERVICE_INSTANCE instance)
{
    Q_UNUSED(instance);
    if (status == ERROR_SUCCESS)
        return;

    // 注册失败要让界面上看得见：没有它，别人永远发现不了我们。
    postToOwner(queryContext, [status](WinDnsSdDiscovery *owner) {
        QMetaObject::invokeMethod(
            owner,
            [owner, status] {
                owner->fail(QStringLiteral("DNS-SD 注册失败（错误码 %1）").arg(status));
            },
            Qt::QueuedConnection);
    });
}

VOID WINAPI WinDnsSdDiscovery::onBrowseComplete(DWORD status, PVOID queryContext,
                                                PDNS_RECORD records)
{
    // 这个线程不是 Qt 线程：只做拷贝与释放，然后把结果投递回去。
    QStringList names;
    if (status == ERROR_SUCCESS && records != nullptr)
        names = instanceNamesFrom(records);
    if (records != nullptr)
        DnsRecordListFree(records, DnsFreeRecordList);
    if (names.isEmpty())
        return;

    postToOwner(queryContext, [names](WinDnsSdDiscovery *owner) {
        QMetaObject::invokeMethod(owner, [owner, names] { owner->resolveInstances(names); },
                                  Qt::QueuedConnection);
    });
}

VOID WINAPI WinDnsSdDiscovery::onResolveComplete(DWORD status, PVOID queryContext,
                                                 PDNS_SERVICE_INSTANCE instance)
{
    if (status != ERROR_SUCCESS || instance == nullptr) {
        if (instance != nullptr)
            DnsServiceFreeInstance(instance);
        return;
    }

    // 同样：拷出来、立刻释放，然后回 Qt 线程。
    const QString name = QString::fromWCharArray(instance->pszInstanceName);
    const quint16 port = instance->wPort;
    const QStringList addresses = addressesFrom(instance);
    const QString hostName = instance->pszHostName != nullptr
        ? QString::fromWCharArray(instance->pszHostName)
        : QString();
    const QHash<QString, QByteArray> txt = txtFrom(instance);
    DnsServiceFreeInstance(instance);

    // 解析结果里没有地址是已知情形，退回按主机名查一次。QHostInfo 收一个接收者对象：
    // 对象析构后回调不会被调用，所以这里可以直接调私有方法。
    const bool needsHostLookup = addresses.isEmpty() && !hostName.isEmpty();

    postToOwner(queryContext, [&](WinDnsSdDiscovery *owner) {
        if (needsHostLookup) {
            QHostInfo::lookupHost(hostName, owner,
                                  [owner, name, port, txt](const QHostInfo &info) {
                                      QStringList resolved;
                                      const QList<QHostAddress> found = info.addresses();
                                      for (const QHostAddress &address : found)
                                          resolved.append(address.toString());
                                      owner->adoptResolved(name, resolved, port, txt);
                                  });
            return;
        }
        QMetaObject::invokeMethod(
            owner,
            [owner, name, addresses, port, txt] {
                owner->adoptResolved(name, addresses, port, txt);
            },
            Qt::QueuedConnection);
    });
}

void WinDnsSdDiscovery::resolveInstances(const QStringList &instanceNames)
{
    for (const QString &name : instanceNames) {
        const std::wstring queryName = name.toStdWString();

        DNS_SERVICE_RESOLVE_REQUEST request{};
        request.Version = kRequestVersion;
        request.InterfaceIndex = 0;
        request.QueryName = const_cast<PWSTR>(queryName.c_str()); // 只在调用期间需要有效
        request.pQueryContext = new CallbackContext(this); // 故意不释放
        m_contexts.push_back(request.pQueryContext);
        request.pResolveCompletionCallback = &WinDnsSdDiscovery::onResolveComplete;

        DnsServiceResolve(&request, &m_resolveCancel);
    }
}

void WinDnsSdDiscovery::adoptResolved(const QString &instanceName, const QStringList &addresses,
                                      quint16 port, const QHash<QString, QByteArray> &txt)
{
    if (!m_started)
        return; // 已经停了，这是取消前发出的回调

    Advertisement advertisement;
    advertisement.deviceId = QString::fromLatin1(txt.value(QString::fromLatin1(proto::kTxtKeyId)));
    advertisement.fingerprint =
        QString::fromLatin1(txt.value(QString::fromLatin1(proto::kTxtKeyFp)));
    advertisement.name = QString::fromUtf8(txt.value(QString::fromLatin1(proto::kTxtKeyName)));
    advertisement.version = txt.value(QString::fromLatin1(proto::kTxtKeyVer)).toInt();
    advertisement.port = port;

    if (advertisement.deviceId.size() != proto::kDeviceIdBytes * 2
        || advertisement.fingerprint.size() != 64 || port == 0) {
        return; // 不是我们的服务，或者字段不合法
    }
    if (advertisement.deviceId == m_config.self.deviceId)
        return; // 自己的注册，系统也会报回来

    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const QString &address : addresses) {
        const QHostAddress host(address);
        if (host.isNull())
            continue;
        Announcement announcement;
        announcement.advertisement = advertisement;
        announcement.address = host;
        announcement.seenAt = now;
        // 一个实例在每个接口、每种地址族上各来一条，这正好是 PeerDirectory
        // 要的那组地址（§3.3）。
        m_resolved.insert(instanceName + QLatin1Char('|') + address, announcement);
        emit announced(announcement);
    }
}

void WinDnsSdDiscovery::refresh()
{
    // 与 Avahi 后端同一个理由：DNS-SD 的浏览结果是稳定列表，不像广播那样每 2 秒
    // 自己响一次，所以要主动重报，目录的超时判定对两种后端才是同一套。
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (auto it = m_resolved.begin(); it != m_resolved.end(); ++it) {
        it->seenAt = now;
        emit announced(it.value());
    }
}

void WinDnsSdDiscovery::stop()
{
    if (!m_started)
        return;
    m_started = false;
    m_refreshTimer->stop();

    if (m_registered) {
        DnsServiceDeRegister(&m_registerRequest, nullptr);
        m_registered = false;
    }
    if (m_registeredInstance != nullptr) {
        DnsServiceFreeInstance(m_registeredInstance);
        m_registeredInstance = nullptr;
    }
    DnsServiceBrowseCancel(&m_browseCancel);
    m_resolved.clear();
}

} // namespace lanpipe::discovery
