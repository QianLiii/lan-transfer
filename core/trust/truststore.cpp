#include "truststore.h"

#include "files/atomicwrite.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QStandardPaths>

#include <algorithm>

namespace lanpipe::trust {

namespace {

constexpr int kFormatVersion = 1;

// JSON 键名只在读写两处出现，成对出现才不会漂。
constexpr auto kKeyVersion = "version";
constexpr auto kKeyPeers = "peers";
constexpr auto kKeyDeviceId = "deviceId";
constexpr auto kKeyFingerprint = "fingerprint";
constexpr auto kKeyName = "name";
constexpr auto kKeyPairedAt = "pairedAt";

QJsonObject toJson(const TrustStore::Entry &entry)
{
    QJsonObject object;
    object.insert(QLatin1String(kKeyDeviceId), entry.deviceId);
    object.insert(QLatin1String(kKeyFingerprint), entry.fingerprint);
    object.insert(QLatin1String(kKeyName), entry.name);
    object.insert(QLatin1String(kKeyPairedAt), entry.pairedAt.toString(Qt::ISODate));
    return object;
}

std::expected<TrustStore::Entry, QString> entryFromJson(const QJsonValue &value)
{
    if (!value.isObject())
        return std::unexpected(QStringLiteral("对端记录不是 JSON 对象"));

    const QJsonObject object = value.toObject();
    TrustStore::Entry entry;
    entry.deviceId = object.value(QLatin1String(kKeyDeviceId)).toString();
    entry.fingerprint = object.value(QLatin1String(kKeyFingerprint)).toString();
    entry.name = object.value(QLatin1String(kKeyName)).toString();
    entry.pairedAt = QDateTime::fromString(object.value(QLatin1String(kKeyPairedAt)).toString(),
                                           Qt::ISODate);

    if (entry.deviceId.isEmpty() || entry.fingerprint.isEmpty())
        return std::unexpected(QStringLiteral("对端记录缺少 deviceId 或指纹"));

    return entry;
}

} // namespace

QString TrustStore::defaultPath()
{
    return QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation))
        .filePath(QStringLiteral("trust.json"));
}

std::expected<TrustStore, QString> TrustStore::load(const QString &path)
{
    TrustStore store;
    store.m_path = path.isEmpty() ? defaultPath() : path;

    QFile file(store.m_path);
    if (!file.exists())
        return store; // 还没配过对，是正常状态
    if (!file.open(QIODevice::ReadOnly))
        return std::unexpected(
            QStringLiteral("无法读取信任库 %1：%2").arg(store.m_path, file.errorString()));

    const QByteArray raw = file.readAll();
    file.close();

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(raw, &parseError);
    if (document.isNull() || !document.isObject()) {
        return std::unexpected(QStringLiteral("信任库 %1 已损坏：%2")
                                   .arg(store.m_path, parseError.errorString()));
    }

    const QJsonObject root = document.object();
    if (root.value(QLatin1String(kKeyVersion)).toInt() != kFormatVersion) {
        return std::unexpected(
            QStringLiteral("信任库 %1 的格式版本不是 %2").arg(store.m_path).arg(kFormatVersion));
    }

    const QJsonValue peers = root.value(QLatin1String(kKeyPeers));
    if (!peers.isArray())
        return std::unexpected(QStringLiteral("信任库 %1 缺少对端列表").arg(store.m_path));

    for (const QJsonValue &value : peers.toArray()) {
        auto entry = entryFromJson(value);
        if (!entry.has_value())
            return std::unexpected(
                QStringLiteral("信任库 %1 有问题：%2").arg(store.m_path, entry.error()));
        store.m_entries.insert(entry->deviceId, *entry);
    }

    return store;
}

std::optional<TrustStore::Entry> TrustStore::find(const QString &deviceId) const
{
    const auto it = m_entries.constFind(deviceId);
    if (it == m_entries.constEnd())
        return std::nullopt;
    return *it;
}

QList<TrustStore::Entry> TrustStore::entries() const
{
    QList<Entry> result;
    result.reserve(m_entries.size());
    for (const Entry &entry : m_entries)
        result.append(entry);

    // 最近配对的排前面；同时刻按 deviceId，保证顺序稳定。
    std::sort(result.begin(), result.end(), [](const Entry &a, const Entry &b) {
        if (a.pairedAt != b.pairedAt)
            return a.pairedAt > b.pairedAt;
        return a.deviceId < b.deviceId;
    });
    return result;
}

bool TrustStore::identityChanged(const QString &deviceId, const QString &observedFingerprint) const
{
    const auto it = m_entries.constFind(deviceId);
    if (it == m_entries.constEnd())
        return false; // 未配对，谈不上「变了」
    return it->fingerprint.compare(observedFingerprint, Qt::CaseInsensitive) != 0;
}

bool TrustStore::add(Entry entry, QString *error)
{
    if (entry.deviceId.isEmpty() || entry.fingerprint.isEmpty()) {
        *error = QStringLiteral("对端记录缺少 deviceId 或指纹");
        return false;
    }

    const auto previous = m_entries.constFind(entry.deviceId);
    m_entries.insert(entry.deviceId, std::move(entry));

    if (save(error))
        return true;

    // 落盘失败就回滚内存，否则内存与磁盘不一致，而调用方以为已经配对成功。
    if (previous == m_entries.constEnd())
        m_entries.remove(entry.deviceId);
    else
        m_entries.insert(previous->deviceId, *previous);
    return false;
}

bool TrustStore::remove(const QString &deviceId, QString *error)
{
    const auto previous = m_entries.constFind(deviceId);
    if (previous == m_entries.constEnd())
        return true;

    const Entry removed = *previous;
    m_entries.remove(deviceId);

    if (save(error))
        return true;

    m_entries.insert(removed.deviceId, removed);
    return false;
}

bool TrustStore::clear(QString *error)
{
    const QHash<QString, Entry> previous = m_entries;
    m_entries.clear();
    if (save(error))
        return true;
    m_entries = previous;
    return false;
}

bool TrustStore::save(QString *error) const
{
    QJsonArray peers;
    for (const Entry &entry : entries())
        peers.append(toJson(entry));

    QJsonObject root;
    root.insert(QLatin1String(kKeyVersion), kFormatVersion);
    root.insert(QLatin1String(kKeyPeers), peers);

    const QByteArray data = QJsonDocument(root).toJson(QJsonDocument::Indented);
    return writeFileAtomically(m_path, data, error);
}

} // namespace lanpipe::trust
