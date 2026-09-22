// 文件名净化与改名（§5.11）。全是纯函数，不需要事件循环。
//
// 主体是一张**向量表**：M4 的验收要求「每一个敌意文件名都被处理掉」。处理有两条
// 出路——净化成一个安全的等价物，或直接拒——但两条都必须保证名字逃不出接收目录、
// 也伪装不成别的文件。表就是这条规格的可执行形式。

#include <QtTest>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "protocol.h"
#include "trust/sanitizer.h"

using namespace lanpipe;
using namespace lanpipe::trust;

namespace {

struct FilenameVector
{
    const char *raw;
    const char *expected; // 空指针 = 必须被拒；否则必须是净化后的结果
};

const QList<FilenameVector> &hostileVectors()
{
    static const QList<FilenameVector> vectors{
        // ———— 路径穿越：只取最后一段（§5.11「strip separators」）————
        {"../../etc/passwd", "passwd"},
        {"..\\..\\windows\\system32\\config", "config"},
        {"/absolute/path/file.txt", "file.txt"},
        {"a/b/c/d.txt", "d.txt"},
        {"a/../b.txt", "b.txt"},

        // ———— 纯穿越：什么都不剩，拒 ————
        {"..", nullptr},
        {".", nullptr},
        {"/", nullptr},
        {"a/..", nullptr},
        {"a/.", nullptr},
        {"..\\..", nullptr},
        {"", nullptr},

        // ———— Windows 保留名（带扩展名、大小写不同都算）————
        {"CON", nullptr},
        {"con", nullptr},
        {"CON.txt", nullptr},
        {"PRN", nullptr},
        {"AUX.log", nullptr},
        {"NUL", nullptr},
        {"COM1", nullptr},
        {"com9.dat", nullptr},
        {"LPT1", nullptr},
        {"lpt9.tar.gz", nullptr},
        {"CONIN$", nullptr},   // 控制台设备名，与 CON 同属保留
        {"CONOUT$", nullptr},
        {"conout$", nullptr},
        {"COM\u00B9", nullptr}, // 上标变体在 Windows 上同样是设备名
        {"LPT\u00B2.txt", nullptr},

        // ———— 只是含这些字样，不该误伤 ————
        {"CONSOLE.txt", "CONSOLE.txt"},
        {"COM10", "COM10"},
        {"NULLIFY", "NULLIFY"},
        {"console", "console"},

        // ———— 尾点 / 尾空格：Windows 上会被系统悄悄吃掉，于是名字与用户看到的不符 ————
        {"file.", nullptr},
        {"file ", nullptr},
        {"file.txt.", nullptr},
        {"file.txt ", nullptr},
        {"file.. ", nullptr},

        // ———— 控制字符与双向/零宽格式字符 ————
        // 这些一律写成转义：源文件里出现真正的双向控制字符，本身就是那个隐患。
        {"a\nb", nullptr},
        {"a\rb", nullptr},
        {"a\tb", nullptr},
        {"a\x1b[31mb", nullptr},   // ANSI 转义
        {"a\u202Eb", nullptr},     // 双向覆盖：能让扩展名反向显示
        {"a\u202Db", nullptr},     // 双向嵌入
        {"a\u2066b", nullptr},     // 双向隔离
        {"a\u200Bb", nullptr},     // 零宽空格
        {"a\uFEFFb", nullptr},     // BOM

        // ———— Windows 上根本写不下去的字符 ————
        {"a:b", nullptr},
        {"a?b", nullptr},
        {"a*b", nullptr},
        {"a\"b", nullptr},
        {"a|b", nullptr},
        {"a<b", nullptr},
        {"a>b", nullptr},

        // ———— 正常名字照常通过（净化不是「一律改名」）————
        {"photo.jpg", "photo.jpg"},
        {"报告 2026.pdf", "报告 2026.pdf"},
        {".bashrc", ".bashrc"},
        {"a b  c.txt", "a b  c.txt"},
        {"file (1).tar.gz", "file (1).tar.gz"},
    };
    return vectors;
}

} // namespace

class TestSanitizer : public QObject
{
    Q_OBJECT

private:
    // 净化成功时返回结果，失败就记一笔并返回空串——QFAIL 展开成 `return;`，
    // 放不进有返回值的函数里。
    static QString sanitized(const QString &raw)
    {
        const auto result = sanitizeFilename(raw);
        if (!result.has_value()) {
            QTest::qFail(qPrintable(QStringLiteral("意外拒绝 %1：%2").arg(raw, result.error())),
                         __FILE__, __LINE__);
            return {};
        }
        return *result;
    }

private slots:
    // §5.11 的向量表。
    void hostileVectorTable()
    {
        for (const FilenameVector &vector : hostileVectors()) {
            const QString raw = QString::fromUtf8(vector.raw);
            const auto result = sanitizeFilename(raw);

            if (vector.expected == nullptr) {
                QVERIFY2(!result.has_value(),
                         qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
                continue;
            }

            if (!result.has_value()) {
                QTest::qFail(qPrintable(QStringLiteral("%1 被拒了，但应当净化成 %2：%3")
                                            .arg(raw, QString::fromUtf8(vector.expected),
                                                 result.error())),
                             __FILE__, __LINE__);
                continue;
            }
            QCOMPARE(*result, QString::fromUtf8(vector.expected));
        }
    }

    // 名字长度按字节算：超一个字节也要拒（上限在净化之前就生效）。
    void rejectsOverlongNames()
    {
        const QString atLimit(static_cast<qsizetype>(proto::kMaxDisplayNameBytes), QLatin1Char('a'));
        QCOMPARE(sanitized(atLimit).size(), atLimit.size());

        const QString tooLong(static_cast<qsizetype>(proto::kMaxDisplayNameBytes) + 1,
                              QLatin1Char('a'));
        QVERIFY(!sanitizeFilename(tooLong).has_value());

        // 汉字每个三字节，八十六个就超了。
        const QString wide = QString(86, QChar(0x4E2D));
        QVERIFY(wide.toUtf8().size() > static_cast<qsizetype>(proto::kMaxDisplayNameBytes));
        QVERIFY(!sanitizeFilename(wide).has_value());
    }

    // §5.11：封的是**全路径**，不只是名字——接收目录深的时候名字要更短。
    //
    // 上限随平台不同（Windows 是 259 个 UTF-16 单元，POSIX 是 4095 字节），所以期望值
    // 也从平台推出来，不写死一个数：写死「4000 字符要通过」在 Windows 上必然失败。
    void finalPathLengthIsChecked()
    {
#ifdef Q_OS_WIN
        constexpr qsizetype kLimit = 259;
#else
        constexpr qsizetype kLimit = 4095;
#endif
        const QString name = QStringLiteral("a.txt");
        // QDir::filePath 拼出来是 dir + '/' + name，正好卡在上限上的那条要通过。
        const QString atLimit(kLimit - 1 - name.size(), QLatin1Char('d'));

        // 不用 QVERIFY2 带 .error()：它的消息参数是无条件求值的，成功路径上也会调
        // error()，而 std::expected 在成功时调 error() 会直接断言（tst_identity 里
        // 记着同一条）。这里先取结果，失败了再问原因。
        const auto exact = checkFinalPath(atLimit, name);
        if (!exact.has_value()) {
            QFAIL(qPrintable(QStringLiteral("卡在上限（%1）的路径被拒了：%2")
                                 .arg(kLimit)
                                 .arg(exact.error())));
        }

        const QString tooLong(atLimit.size() + 1, QLatin1Char('d'));
        QVERIFY(!checkFinalPath(tooLong, name).has_value());
    }

    void uniqueNameKeepsNameWhenFree()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QCOMPARE(uniqueName(dir.path(), QStringLiteral("photo.jpg")), QStringLiteral("photo.jpg"));
    }

    void uniqueNameBumpsCounter()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto touch = [&dir](const QString &name) {
            QFile file(QDir(dir.path()).filePath(name));
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write("x");
        };

        touch(QStringLiteral("photo.jpg"));
        QCOMPARE(uniqueName(dir.path(), QStringLiteral("photo.jpg")), QStringLiteral("photo (1).jpg"));

        touch(QStringLiteral("photo (1).jpg"));
        QCOMPARE(uniqueName(dir.path(), QStringLiteral("photo.jpg")), QStringLiteral("photo (2).jpg"));
    }

    void uniqueNameKeepsFullExtension()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QFile file(QDir(dir.path()).filePath(QStringLiteral("archive.tar.gz")));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.close();

        QCOMPARE(uniqueName(dir.path(), QStringLiteral("archive.tar.gz")),
                 QStringLiteral("archive (1).tar.gz"));
    }

    void uniqueNameHandlesNamesWithoutExtension()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QFile file(QDir(dir.path()).filePath(QStringLiteral("README")));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.close();

        QCOMPARE(uniqueName(dir.path(), QStringLiteral("README")), QStringLiteral("README (1)"));

        // 隐藏文件：整个名字都是主干，点不当作扩展名分隔。
        QFile hidden(QDir(dir.path()).filePath(QStringLiteral(".bashrc")));
        QVERIFY(hidden.open(QIODevice::WriteOnly));
        hidden.close();
        QCOMPARE(uniqueName(dir.path(), QStringLiteral(".bashrc")), QStringLiteral(".bashrc (1)"));
    }

    // 冲突判定按目标平台的规则：Windows/macOS 大小写不敏感，Linux 敏感。
    void collisionRuleFollowsThePlatform()
    {
        QVERIFY(namesCollide(QStringLiteral("photo.jpg"), QStringLiteral("photo.jpg")));
        QVERIFY(!namesCollide(QStringLiteral("photo.jpg"), QStringLiteral("other.jpg")));

#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
        QVERIFY(namesCollide(QStringLiteral("Photo.jpg"), QStringLiteral("photo.jpg")));
#else
        QVERIFY(!namesCollide(QStringLiteral("Photo.jpg"), QStringLiteral("photo.jpg")));
#endif
    }

    // 不可信文本打到终端之前要剥掉控制字符，否则一个 ANSI 转义序列就能伪造整行输出。
    void displaySafeStripsEscapes()
    {
        const QString hostile = QStringLiteral("正常\x1b[2K\r已配对 123456");
        const QString safe = displaySafe(hostile);
        QVERIFY(!safe.contains(QChar(0x1B)));
        QVERIFY(!safe.contains(QLatin1Char('\r')));
        QCOMPARE(safe, QStringLiteral("正常[2K已配对 123456"));
    }
};

QTEST_APPLESS_MAIN(TestSanitizer)

#include "tst_sanitizer.moc"
