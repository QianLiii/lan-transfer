#include "peerconnector.h"

namespace lanpipe::discovery {

PeerConnector::PeerConnector(const QList<PeerDirectory::Address> &addresses,
                             std::chrono::milliseconds perAddressTimeout, QObject *parent)
    : QObject(parent), m_addresses(addresses), m_perAddressTimeout(perAddressTimeout)
{
    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    m_timer->setInterval(m_perAddressTimeout);
    connect(m_timer, &QTimer::timeout, this, [this] {
        recordFailure(QStringLiteral("连接超时"));
        emit attemptTimedOut();
    });
}

std::optional<PeerConnector::Target> PeerConnector::startNext()
{
    if (m_index >= m_addresses.size())
        return std::nullopt;

    m_current = m_addresses.at(m_index++);
    ++m_tried;
    m_timer->start();
    return Target{m_current->address, m_current->port};
}

void PeerConnector::connected()
{
    m_timer->stop();
}

void PeerConnector::succeeded()
{
    m_timer->stop();
    m_current.reset();
    m_index = m_addresses.size(); // 收工，不再给地址
}

void PeerConnector::failed(const QString &reason)
{
    recordFailure(reason);
}

void PeerConnector::recordFailure(const QString &reason)
{
    m_timer->stop();
    if (!m_current.has_value())
        return;
    m_failures.append(QStringLiteral("%1:%2 — %3")
                          .arg(m_current->address.toString())
                          .arg(m_current->port)
                          .arg(reason));
    m_current.reset();
}

QString PeerConnector::failureSummary() const
{
    return m_failures.join(QStringLiteral("；"));
}

} // namespace lanpipe::discovery
