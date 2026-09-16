#include "sas.h"

#include "protocol.h"

#include <QCryptographicHash>
#include <QLatin1Char>
#include <QtEndian>

#include <chrono>

namespace lanpipe {

QByteArray computeSas(const Fingerprint &senderFingerprint,
                      const Fingerprint &receiverFingerprint, const QString &cnonce,
                      const QString &snonce)
{
    // 直接拼接，不加分隔符：两个指纹都是定长 32 字节，边界由长度确定，
    // 不存在「谁的字节接到谁头上」的歧义。
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(senderFingerprint.bytes());
    hash.addData(receiverFingerprint.bytes());
    hash.addData(cnonce.toLatin1());
    hash.addData(snonce.toLatin1());
    return hash.result();
}

QString sasCode(const QByteArray &sas)
{
    if (sas.size() < 8)
        return {};

    // 取前 8 字节当无符号整数再取模。模 10^6 的偏差约 2^-43，与这个码的作用
    // 无关——它要防的是「中间人让两端算出同一个码」，概率是 10^-6 那一档。
    const quint64 value = qFromBigEndian<quint64>(sas.constData());
    return QStringLiteral("%1").arg(value % 1000000ULL, proto::kSasCodeDigits, 10,
                                    QLatin1Char('0'));
}

void SasCache::store(const QString &peerDeviceId, Entry entry)
{
    if (peerDeviceId.isEmpty())
        return;
    m_entries.insert(peerDeviceId, std::move(entry));
}

std::optional<SasCache::Entry> SasCache::lookup(const QString &peerDeviceId,
                                                const QDateTime &now) const
{
    const auto it = m_entries.constFind(peerDeviceId);
    if (it == m_entries.constEnd())
        return std::nullopt;

    const auto age = std::chrono::seconds(it->settledAt.secsTo(now));
    if (age > proto::kSasLifetime)
        return std::nullopt;

    return *it;
}

} // namespace lanpipe
