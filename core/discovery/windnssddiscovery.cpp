#include "windnssddiscovery.h"

#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QMetaObject>
#include <QSysInfo>
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

        QString name = QString::fromWCharArray(record->Data.PTR.pNameHost);
        // 完全限定名可能带结尾的点（mDNS 的写法是 "…local."），也可能大小写不同。
        // 不认这两种写法的话，名字会被整批滤掉，表现为「浏览器一条都没报」。
        if (name.endsWith(QLatin1Char('.')))
            name.chop(1);
        if (name.endsWith(suffix, Qt::CaseInsensitive) && !names.contains(name))
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
    // 必须当场打出来，不能只塞进 lastError：这个后端的失败多半发生在回调线程里
    // 或 start() 返回之后，调用方那时早已不看了。stderr 是无缓冲的，进程就算随后
    // 崩掉，这一行也留得下——而 QtTest 的 stdout 带缓冲，崩了就没。
    qWarning("lanpipe: system DNS-SD failure: %s", qPrintable(reason));
    m_lastError = reason;
    stop();
}

void WinDnsSdDiscovery::start()
{
    if (m_started)
        return;
    m_lastError.clear();

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
    // 主机名只有注册才需要，所以在本函数里取——放在 start() 里会让这里看不见它。
    //
    // 用 QSysInfo::machineHostName() 而不是 QHostInfo::localHostName()：后者可能去
    // 解析一次 DNS，在没有 mDNS 的网络上会卡住几十秒，而我们只是要一个名字。
    const QString hostName = QSysInfo::machineHostName();
    if (hostName.isEmpty()) {
        fail(QStringLiteral("no local host name; cannot register the DNS-SD service"));
        return;
    }

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
    m_session->registeredInstance = DnsServiceConstructInstance(
        m_wideName.front().data(), m_wideHost.front().data(), nullptr, nullptr,
        m_config.self.port, 0 /* priority */, 0 /* weight */,
        static_cast<DWORD>(keyPointers.size()), keyPointers.data(), valuePointers.data());

    if (m_session->registeredInstance == nullptr) {
        fail(QStringLiteral("DnsServiceConstructInstance returned null"));
        return;
    }

    m_session->registerRequest = {};
    m_session->registerRequest.Version = kRequestVersion;
    m_session->registerRequest.InterfaceIndex = 0; // 所有接口
    m_session->registerRequest.pServiceInstance = m_session->registeredInstance;
    m_session->registerRequest.pQueryContext = new CallbackContext(this); // 故意不释放
    m_contexts.push_back(m_session->registerRequest.pQueryContext);
    m_session->registerRequest.pRegisterCompletionCallback = &WinDnsSdDiscovery::onRegisterComplete;
    m_session->registerRequest.unicastEnabled = FALSE;

    const DWORD result = DnsServiceRegister(&m_session->registerRequest, nullptr);
    if (result != DNS_REQUEST_PENDING) {
        fail(QStringLiteral("DnsServiceRegister failed (error %1)").arg(result));
        return;
    }
    m_session->registered = true;
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

    const DWORD result = DnsServiceBrowse(&request, &m_session->browseCancel);
    if (result != DNS_REQUEST_PENDING) {
        // 没插网线时这里就是 ERROR_NO_NETWORK（1222）。
        fail(QStringLiteral("DnsServiceBrowse failed (error %1)").arg(result));
        return;
    }
    m_session->browsing = true;
}

VOID WINAPI WinDnsSdDiscovery::onRegisterComplete(DWORD status, PVOID queryContext,
                                                  PDNS_SERVICE_INSTANCE instance)
{
    Q_UNUSED(instance);

    // 回调回来之前，那个实例指针归 API 保管，我们不能释放它。
    postToOwner(queryContext, [](WinDnsSdDiscovery *owner) {
        QMetaObject::invokeMethod(owner, [owner] { owner->m_session->registerCompleted = true; },
                                  Qt::QueuedConnection);
    });

    if (status == ERROR_SUCCESS)
        return;

    // 注册失败要让界面上看得见：没有它，别人永远发现不了我们。
    postToOwner(queryContext, [status](WinDnsSdDiscovery *owner) {
        QMetaObject::invokeMethod(
            owner,
            [owner, status] {
                owner->fail(QStringLiteral("DNS-SD registration failed (error %1)").arg(status));
            },
            Qt::QueuedConnection);
    });
}

VOID WINAPI WinDnsSdDiscovery::onBrowseComplete(DWORD status, PVOID queryContext,
                                                PDNS_RECORD records)
{
    // 这个线程不是 Qt 线程：只做拷贝与释放，然后把结果投递回去。
    QStringList names;
    int recordCount = 0;
    if (status == ERROR_SUCCESS && records != nullptr) {
        for (PDNS_RECORD record = records; record != nullptr; record = record->pNext)
            ++recordCount;
        names = instanceNamesFrom(records);
    }
    m_browseCallbacks.fetch_add(1);
    m_recordsSeen.fetch_add(recordCount);

    // 这行必须在下面的提前返回之前：空名单恰恰是最需要看见的情形。
    qInfo("lanpipe: DNS-SD browse callback: status=%lu records=%d matching=%lld",
          static_cast<unsigned long>(status), recordCount,
          static_cast<long long>(names.size()));

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
        // 服务在我们解析之前消失是常态，不当作错误；但留一条便于排查
        // 「为什么一直收不到通告」。
        qInfo("lanpipe: DNS-SD resolve failed (error %lu)",
              static_cast<unsigned long>(status));
        // 失败时不碰那个指针：它未必是有效的 DNS_SERVICE_INSTANCE。
        return;
    }

    // 同样：拷出来、立刻释放，然后回 Qt 线程。
    //
    // 三个字段都要防空：回调拿到的结构体不一定填满，而 fromWCharArray(nullptr)
    // 是直接崩。宁可少处理一条，也不能把进程带走。
    const QString name = instance->pszInstanceName != nullptr
        ? QString::fromWCharArray(instance->pszInstanceName)
        : QString();
    const quint16 port = instance->wPort;
    const QStringList addresses = addressesFrom(instance);
    const QString hostName = instance->pszHostName != nullptr
        ? QString::fromWCharArray(instance->pszHostName)
        : QString();
    const QHash<QString, QByteArray> txt = txtFrom(instance);

    // 走到这里说明状态是成功、指针有效，这个实例归调用方释放（上面的失败分支
    // 已经返回，不碰它）。
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

        DnsServiceResolve(&request, &m_session->resolveCancel);
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

    if (m_session->registered) {
        DnsServiceDeRegister(&m_session->registerRequest, nullptr);
        m_session->registered = false;
    }
    // 完成回调还没回来就不释放：那个指针此刻归 API 保管，释放它会让 API 在回调里
    // 用到已释放的内存。宁可少释放一次（每个 start() 一次，几十字节），也不冒这个险。
    if (m_session->registeredInstance != nullptr && m_session->registerCompleted) {
        DnsServiceFreeInstance(m_session->registeredInstance);
        m_session->registeredInstance = nullptr;
    }
    if (m_session->browsing) {
        DnsServiceBrowseCancel(&m_session->browseCancel);
        m_session->browsing = false;
    }
    m_resolved.clear();
}

} // namespace lanpipe::discovery
