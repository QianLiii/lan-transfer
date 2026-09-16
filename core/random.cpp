#include "random.h"

#include <QByteArray>
#include <QRandomGenerator>

namespace lanpipe {

QString randomHex(int bytes)
{
    if (bytes <= 0)
        return {};

    QByteArray raw;
    raw.reserve(bytes);
    while (raw.size() < bytes) {
        const quint64 word = QRandomGenerator::system()->generate64();
        // 一次取 8 字节，不足 8 的那一轮只取前几个字节。
        for (int byte = 0; byte < 8 && raw.size() < bytes; ++byte)
            raw.append(static_cast<char>(word >> (8 * byte)));
    }
    return QString::fromLatin1(raw.toHex());
}

} // namespace lanpipe
