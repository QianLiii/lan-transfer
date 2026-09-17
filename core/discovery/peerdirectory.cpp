#include "peerdirectory.h"

#include "protocol.h"

#include <QStringList>

#include <algorithm>

namespace lanpipe::discovery {

namespace {

// 超过 expiry 没再听到。
bool isStale(const QDateTime &lastSeen, const QDateTime &now, std::chrono::milliseconds expiry)
{
    return std::chrono::milliseconds(lastSeen.msecsTo(now)) > expiry;
}

} // namespace

PeerDirectory::PeerDirectory(QObject *parent)
    : QObject(parent), m_expiry(proto::kPeerExpiry)
{
    m_sweep = new QTimer(this);
    m_sweep->setInterval(m_expiry / 2);
    connect(m_sweep, &QTimer::timeout, this, [this] { prune(); });
    m_sweep->start();
}

void PeerDirectory::addSource(Discovery *source)
{
    if (!source)
        return;
    connect(source, &Discovery::announced, this, &PeerDirectory::apply);
}

void PeerDirectory::setExpiry(std::chrono::milliseconds expiry)
{
    m_expiry = expiry;
    m_sweep->setInterval(std::max(expiry / 2, std::chrono::milliseconds(1)));
}

void PeerDirectory::apply(const Announcement &announcement)
{
    const Advertisement &advertisement = announcement.advertisement;
    if (advertisement.deviceId.isEmpty() || announcement.address.isNull())
        return;

    auto it = m_peers.find(advertisement.deviceId);
    const bool isNew = it == m_peers.end();
    if (isNew)
        it = m_peers.insert(advertisement.deviceId, Peer{});

    Peer &peer = it.value();
    peer.deviceId = advertisement.deviceId;
    // 名字、指纹、版本都可能变（用户改名、证书重签后指纹不变、协议升级），
    // 因此每次通告都覆盖，而不是只在首次写入。
    peer.name = advertisement.name;
    peer.fingerprint = advertisement.fingerprint;
    peer.version = advertisement.version;
    peer.lastSeen = announcement.seenAt;

    const Address address{announcement.address, advertisement.port, announcement.seenAt};
    const auto existing = std::find(peer.addresses.begin(), peer.addresses.end(), address);
    if (existing == peer.addresses.end())
        peer.addresses.append(address);
    else
        existing->lastSeen = announcement.seenAt;

    // 最近还活着的排最前：多网卡机器上先试哪个，顺序决定回退要花多久。
    std::sort(peer.addresses.begin(), peer.addresses.end(),
              [](const Address &a, const Address &b) { return a.lastSeen > b.lastSeen; });

    if (isNew)
        emit peerAdded(peer.deviceId);
    else
        emit peerUpdated(peer.deviceId);
}

QList<PeerDirectory::Peer> PeerDirectory::peers() const
{
    QList<Peer> result;
    result.reserve(m_peers.size());
    for (const Peer &peer : m_peers)
        result.append(peer);

    std::sort(result.begin(), result.end(), [](const Peer &a, const Peer &b) {
        if (a.lastSeen != b.lastSeen)
            return a.lastSeen > b.lastSeen;
        return a.deviceId < b.deviceId;
    });
    return result;
}

std::optional<PeerDirectory::Peer> PeerDirectory::peer(const QString &deviceId) const
{
    const auto it = m_peers.constFind(deviceId);
    if (it == m_peers.constEnd())
        return std::nullopt;
    return *it;
}

void PeerDirectory::prune(const QDateTime &now)
{
    QStringList gone;
    for (auto it = m_peers.constBegin(); it != m_peers.constEnd(); ++it) {
        if (isStale(it->lastSeen, now, m_expiry))
            gone.append(it.key());
    }

    for (const QString &deviceId : gone) {
        m_peers.remove(deviceId);
        emit peerRemoved(deviceId);
    }
}

} // namespace lanpipe::discovery
