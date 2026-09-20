// 文件名净化与改名（§5.11）。全是纯函数，不需要事件循环。
//
// 完整敌意向量表是 M4 的验收；这里落的是接收路径真正依赖的那一批：
// 路径穿越、保留名、尾点尾空格、控制字符、长度、以及冲突改名。

#include <QtTest>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "protocol.h"
#include "trust/sanitizer.h"

using namespace lanpipe;
using namespace lanpipe::trust;

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
    void acceptsOrdinaryNames()
    {
        QCOMPARE(sanitized(QStringLiteral("photo.jpg")), QStringLiteral("photo.jpg"));
        QCOMPARE(sanitized(QStringLiteral("报告 2026.pdf")), QStringLiteral("报告 2026.pdf"));
        QCOMPARE(sanitized(QStringLiteral("a b  c.txt")), QStringLiteral("a b  c.txt"));
        // 以点开头不是保留形态，只是隐藏文件。
        QCOMPARE(sanitized(QStringLiteral(".bashrc")), QStringLiteral(".bashrc"));
    }

    // 目录分隔符只取最后一段：`/` 与 `\` 都算。
    void stripsPathSeparators()
    {
        QCOMPARE(sanitized(QStringLiteral("a/b.txt")), QStringLiteral("b.txt"));
        QCOMPARE(sanitized(QStringLiteral("a\\b.txt")), QStringLiteral("b.txt"));
        QCOMPARE(sanitized(QStringLiteral("/etc/passwd")), QStringLiteral("passwd"));
        QCOMPARE(sanitized(QStringLiteral("../../etc/passwd")), QStringLiteral("passwd"));
        QCOMPARE(sanitized(QStringLiteral("a/../b.txt")), QStringLiteral("b.txt"));
    }

    void rejectsParentAndDotNames()
    {
        const QList<QString> bad{
            QString(),
            QStringLiteral("."),
            QStringLiteral(".."),
            QStringLiteral("a/.."),
            QStringLiteral("a/."),
            QStringLiteral("..\\.."),
            QStringLiteral("/"),
        };
        for (const QString &raw : bad) {
            QVERIFY2(!sanitizeFilename(raw).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
        }
    }

    void rejectsWindowsReservedNames()
    {
        const QList<QString> bad{
            QStringLiteral("CON"),   QStringLiteral("con"),    QStringLiteral("CON.txt"),
            QStringLiteral("NUL"),   QStringLiteral("PRN.dat"), QStringLiteral("AUX"),
            QStringLiteral("COM1"),  QStringLiteral("com9.log"), QStringLiteral("LPT1"),
            QStringLiteral("lpt9.tar.gz"),
        };
        for (const QString &raw : bad) {
            QVERIFY2(!sanitizeFilename(raw).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
        }
        // 只挡住主干，不是把含这些字样的名字一律拒了。
        QCOMPARE(sanitized(QStringLiteral("CONSOLE.txt")), QStringLiteral("CONSOLE.txt"));
        QCOMPARE(sanitized(QStringLiteral("COM10")), QStringLiteral("COM10"));
    }

    void rejectsTrailingDotOrSpace()
    {
        const QList<QString> bad{QStringLiteral("a."), QStringLiteral("a "),
                                 QStringLiteral("a.txt "), QStringLiteral("a.. ")};
        for (const QString &raw : bad) {
            QVERIFY2(!sanitizeFilename(raw).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
        }
    }

    // 控制字符与双向控制符：前者在 Windows 上本就非法，后者能让名字在屏幕上
    // 显示成另一个样子。
    void rejectsControlAndFormatCharacters()
    {
        QList<QString> bad;
        bad << QStringLiteral("a\nb");
        bad << QStringLiteral("a\tb");
        bad << QStringLiteral("a%1b").arg(QChar(0x7F));   // DEL
        bad << QStringLiteral("a%1b").arg(QChar(0x9F));   // C1
        bad << QStringLiteral("a%1b").arg(QChar(0x202E)); // 双向覆盖
        bad << QStringLiteral("a%1b").arg(QChar(0x2066)); // 双向隔离
        bad << QStringLiteral("a%1b").arg(QChar(0x200B)); // 零宽空格
        bad << QStringLiteral("a%1b").arg(QChar(0xFEFF)); // BOM

        for (const QString &raw : bad) {
            QVERIFY2(!sanitizeFilename(raw).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
        }
    }

    // 比 §5.11 的清单多出的一类：Windows 上根本写不下去的字符。
    void rejectsCharactersWindowsCannotStore()
    {
        const QList<QString> bad{
            QStringLiteral("a:b.txt"), QStringLiteral("a?b.txt"), QStringLiteral("a*b.txt"),
            QStringLiteral("a|b.txt"), QStringLiteral("a\"b.txt"), QStringLiteral("a<b.txt"),
            QStringLiteral("a>b.txt"),
        };
        for (const QString &raw : bad) {
            QVERIFY2(!sanitizeFilename(raw).has_value(),
                     qPrintable(QStringLiteral("未被拒绝：%1").arg(raw)));
        }
    }

    void rejectsOverlongNames()
    {
        // 上限按字节算：超一个字节也要拒。
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

    void finalPathLengthIsChecked()
    {
        const QString dir = QString(4000, QLatin1Char('d'));
        QVERIFY(checkFinalPath(dir, QStringLiteral("a.txt")).has_value());
        QVERIFY(!checkFinalPath(dir, QString(200, QLatin1Char('n'))).has_value());
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
