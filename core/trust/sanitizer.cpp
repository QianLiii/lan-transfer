#include "sanitizer.h"

#include "protocol.h"

#include <QDir>
#include <QFileInfo>
#include <QStringList>

namespace lanpipe::trust {

namespace {

// Windows 保留名。带扩展名的形式（CON.txt）同样被系统拒绝，所以按第一个点之前
// 的主干比对。
const QStringList &reservedNames()
{
    static const QStringList names{
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),
        QStringLiteral("NUL"),  QStringLiteral("COM1"), QStringLiteral("COM2"),
        QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"),
        QStringLiteral("COM6"), QStringLiteral("COM7"), QStringLiteral("COM8"),
        QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"),
        QStringLiteral("LPT6"), QStringLiteral("LPT7"), QStringLiteral("LPT8"),
        QStringLiteral("LPT9"),
    };
    return names;
}

// 控制字符与双向/零宽格式字符。前者在 Windows 上本就非法；后者能让一个文件名
// 在屏幕上显示成另一个样子（U+202E 这类，§5.11）。
bool isControlOrFormat(QChar c)
{
    const char16_t code = c.unicode();
    if (code < 0x20 || code == 0x7F) // C0 与 DEL
        return true;
    if (code >= 0x80 && code <= 0x9F) // C1
        return true;
    if (code == 0x200B || code == 0x200E || code == 0x200F || code == 0xFEFF)
        return true;
    if (code >= 0x202A && code <= 0x202E)
        return true;
    if (code >= 0x2066 && code <= 0x2069)
        return true;
    return false;
}

bool isWindowsIllegal(QChar c)
{
    switch (c.unicode()) {
    case u'<':
    case u'>':
    case u':':
    case u'"':
    case u'|':
    case u'?':
    case u'*':
        return true;
    default:
        return false;
    }
}

} // namespace

std::expected<QString, QString> sanitizeFilename(const QString &raw)
{
    if (raw.isEmpty())
        return std::unexpected(QStringLiteral("文件名为空"));
    if (raw.toUtf8().size() > static_cast<qsizetype>(proto::kMaxDisplayNameBytes))
        return std::unexpected(QStringLiteral("文件名超过 %1 字节").arg(proto::kMaxDisplayNameBytes));

    // 目录分隔符：只取最后一段。`/` 与 `\` 都算——Windows 上两者都是分隔符，
    // 只挡一个等于给另一条留门。
    QString name = raw;
    qsizetype cut = -1;
    for (qsizetype i = 0; i < name.size(); ++i) {
        const QChar c = name.at(i);
        if (c == u'/' || c == u'\\')
            cut = i;
    }
    if (cut >= 0)
        name = name.mid(cut + 1);

    for (const QChar c : name) {
        if (isControlOrFormat(c))
            return std::unexpected(QStringLiteral("文件名含控制字符或双向控制符"));
        if (isWindowsIllegal(c))
            return std::unexpected(
                QStringLiteral("文件名含不可移植的字符 %1").arg(QString(c)));
    }

    if (name.isEmpty() || name == QLatin1String(".") || name == QLatin1String(".."))
        return std::unexpected(QStringLiteral("文件名不是有效名字"));
    if (name.endsWith(u'.') || name.endsWith(u' '))
        return std::unexpected(QStringLiteral("文件名以点或空格结尾"));

    const qsizetype dot = name.indexOf(u'.');
    const QString stem = dot < 0 ? name : name.left(dot);
    for (const QString &reserved : reservedNames()) {
        if (stem.compare(reserved, Qt::CaseInsensitive) == 0)
            return std::unexpected(QStringLiteral("%1 是 Windows 保留名").arg(stem));
    }

    return name;
}

std::expected<void, QString> checkFinalPath(const QString &dir, const QString &name)
{
    const QString full = QDir(dir).filePath(name);

#ifdef Q_OS_WIN
    const qsizetype length = full.size(); // MAX_PATH 按 UTF-16 单元算
    constexpr qsizetype kLimit = 259;
#else
    const qsizetype length = full.toUtf8().size(); // PATH_MAX 按字节算
    constexpr qsizetype kLimit = 4095;
#endif

    if (length > kLimit)
        return std::unexpected(QStringLiteral("完整路径超过本平台的 %1 上限").arg(kLimit));
    return {};
}

bool namesCollide(const QString &a, const QString &b)
{
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    // Windows 与 macOS 默认的卷大小写不敏感，macOS 还会做 NFD 归一化：
    // 不按这个规则比，两个不同名的文件会落到同一个 inode 上。
    return a.normalized(QString::NormalizationForm_D)
               .compare(b.normalized(QString::NormalizationForm_D), Qt::CaseInsensitive)
        == 0;
#else
    return a == b;
#endif
}

QString uniqueName(const QString &dir, const QString &name)
{
    // 自己按**第一个**点切，不用 QFileInfo：它的 completeBaseName() 按最后一个点
    // 切而 completeSuffix() 按第一个点切，两者不互补，会切出 archive.tar + .gz
    // 这种东西。切法要的效果是 photo.jpg → photo (1).jpg、archive.tar.gz →
    // archive (1).tar.gz、.bashrc → .bashrc (1)。
    const qsizetype dot = name.indexOf(u'.');
    const bool hasExtension = dot > 0; // 开头的点属于隐藏文件名，不算扩展名
    const QString stem = hasExtension ? name.left(dot) : name;
    const QString tail = hasExtension ? name.mid(dot) : QString();

    // 连隐藏项一起列：它们同样会被覆盖。
    const QStringList existing = QDir(dir).entryList(QDir::Files | QDir::Dirs | QDir::Hidden
                                                     | QDir::System | QDir::NoDotAndDotDot);

    const auto taken = [&existing](const QString &candidate) {
        for (const QString &entry : existing) {
            if (namesCollide(entry, candidate))
                return true;
        }
        return false;
    };

    if (!taken(name))
        return name;

    for (int i = 1; i <= proto::kMaxFinalNameAttempts; ++i) {
        const QString candidate = QStringLiteral("%1 (%2)%3").arg(stem).arg(i).arg(tail);
        if (!taken(candidate))
            return candidate;
    }
    return {};
}

QString displaySafe(const QString &text)
{
    QString out;
    out.reserve(text.size());
    for (const QChar c : text) {
        if (!isControlOrFormat(c))
            out.append(c);
    }
    return out;
}

} // namespace lanpipe::trust
