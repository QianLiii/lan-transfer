// 桌面端的 FileSource / FileSink 实现（§1.2 第 1 条、§5.6、§5.7）。
//
// 重点在 sink 的三条契约：数据在 commit 之前对外不可见、commit 之后落到净化过的
// 名字上、discard 不留痕迹。

#include <QtTest>

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include "files/localsink.h"
#include "files/localsource.h"
#include "protocol.h"
#include "trust/sanitizer.h"

using namespace lanpipe;
using namespace lanpipe::files;

namespace {

// 十六进制形状的 id，长度与协议常量一致。
const QString kSessionId = QString(proto::kSessionIdBytes * 2, QLatin1Char('a'));
const QString kFileId = QString(proto::kFileIdBytes * 2, QLatin1Char('b'));
const QString kFingerprint = QString(64, QLatin1Char('c'));

} // namespace

class TestLocalFiles : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    static void writeAll(QIODevice *device, const QByteArray &data)
    {
        QCOMPARE(device->write(data), static_cast<qint64>(data.size()));
    }

private slots:
    void initTestCase() { QVERIFY(m_dir.isValid()); }

    // —————————————— FileSource ——————————————

    void sourceReadsTheFileItNames()
    {
        const QString path = m_dir.filePath(QStringLiteral("source.bin"));
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(QByteArray(1000, 'x'));
        file.close();

        LocalFileSource source(path);
        QCOMPARE(source.displayName(), QStringLiteral("source.bin"));
        QCOMPARE(source.size().value_or(0), quint64{1000});

        const auto device = source.open();
        QVERIFY(device != nullptr);
        QCOMPARE(device->readAll().size(), qsizetype{1000});
    }

    // 定不下来与零字节是两件事（§5.14）。
    void sourceSizeIsUnknownForNonFiles()
    {
        LocalFileSource missing(m_dir.filePath(QStringLiteral("nope.bin")));
        QVERIFY(!missing.size().has_value());
        QCOMPARE(missing.displayName(), QStringLiteral("nope.bin"));

        LocalFileSource directory(m_dir.path());
        QVERIFY(!directory.size().has_value());
        QVERIFY(directory.open() == nullptr);
    }

    // —————————————— FileSink ——————————————

    void sinkCommitsIntoTheReceiveDirectory()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("结果.bin"),
                           kFingerprint, 5);
        const auto device = sink.open();
        QVERIFY(device != nullptr);

        writeAll(device.get(), QByteArray("hello"));
        QCOMPARE(sink.bytesWritten(), quint64{5});

        QVERIFY(sink.commit());
        QCOMPARE(sink.finalPath(), QDir(m_dir.path()).filePath(QStringLiteral("结果.bin")));

        QFile landed(sink.finalPath());
        QVERIFY(landed.open(QIODevice::ReadOnly));
        QCOMPARE(landed.readAll(), QByteArray("hello"));
    }

    // 数据在 commit 之前不出现在接收目录里，临时目录里也没有那个名字。
    //
    // 只断言这两条不变量，**不**去数临时目录里有什么：QSaveFile 把数据暂存在哪儿、
    // 那个临时文件叫什么，是它的实现细节，而且随平台不同——Linux 上它用匿名临时文件
    // （readdir 都看不见），其它平台按文档是「在目标同目录建一个具名文件」，
    // 名字未必由我们给的模板拼出来。测这些等于测 Qt。
    void sinkKeepsDataOutOfSightBeforeCommit()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("photo.jpg"),
                           kFingerprint, 3);
        const auto device = sink.open();
        QVERIFY(device != nullptr);
        writeAll(device.get(), QByteArray("abc"));

        QVERIFY(!QFile::exists(QDir(m_dir.path()).filePath(QStringLiteral("photo.jpg"))));

        // §5.7：文件名不参与任何路径构造。所以临时目录里不该出现那个名字的踪影。
        const QStringList inTemp =
            QDir(sink.tempDir()).entryList(QDir::AllEntries | QDir::Hidden | QDir::System);
        for (const QString &entry : inTemp) {
            QVERIFY2(!entry.contains(QStringLiteral("photo")),
                     qPrintable(QStringLiteral("目标名泄漏进了临时目录：%1（全部：%2）")
                                    .arg(entry, inTemp.join(QStringLiteral(", ")))));
        }
        // 我们自己写的那份元数据必须在。
        QVERIFY(QFile::exists(QDir(sink.tempDir()).filePath(kFileId + QStringLiteral(".part.meta"))));

        QVERIFY(sink.commit());
        QVERIFY(QFile::exists(QDir(m_dir.path()).filePath(QStringLiteral("photo.jpg"))));
    }

    // §5.7：元数据在第一个数据字节之前落盘，且写明来源与声明长度。
    void sinkWritesPartMeta()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("来源名.txt"),
                           kFingerprint, 42);
        const auto device = sink.open();
        QVERIFY(device != nullptr);

        QFile meta(QDir(sink.tempDir()).filePath(kFileId + QStringLiteral(".part.meta")));
        QVERIFY(meta.open(QIODevice::ReadOnly));
        const QJsonObject object = QJsonDocument::fromJson(meta.readAll()).object();
        QCOMPARE(object.value(QStringLiteral("sourceName")).toString(), QStringLiteral("来源名.txt"));
        QCOMPARE(object.value(QStringLiteral("sessionId")).toString(), kSessionId);
        QCOMPARE(object.value(QStringLiteral("senderFingerprint")).toString(), kFingerprint);
        QCOMPARE(object.value(QStringLiteral("declaredLength")).toInt(), 42);
    }

    void sinkResolvesNameCollisionAtCommitTime()
    {
        const QString existing = QDir(m_dir.path()).filePath(QStringLiteral("photo.jpg"));
        QFile first(existing);
        QVERIFY(first.open(QIODevice::WriteOnly));
        first.write("old");
        first.close();

        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("photo.jpg"),
                           kFingerprint, 3);
        const auto device = sink.open();
        QVERIFY(device != nullptr);
        writeAll(device.get(), QByteArray("new"));
        QVERIFY(sink.commit());

        QCOMPARE(sink.finalPath(), QDir(m_dir.path()).filePath(QStringLiteral("photo (1).jpg")));

        // 原有的那份没有被覆盖。
        QVERIFY(first.open(QIODevice::ReadOnly));
        QCOMPARE(first.readAll(), QByteArray("old"));
    }

    void sinkDiscardLeavesNothing()
    {
        // 自己一个目录：别的用例会在 m_dir 里留下同名文件。
        QTemporaryDir dir;
        QVERIFY(dir.isValid());

        LocalFileSink sink(dir.path(), kSessionId, kFileId, QStringLiteral("photo.jpg"),
                           kFingerprint, 3);
        auto device = sink.open();
        QVERIFY(device != nullptr);
        writeAll(device.get(), QByteArray("abc"));

        sink.discard();
        // 设备的销毁也是收尾的一部分：cancelWriting() 只是让 commit() 丢弃，
        // 具名的临时文件要到 QSaveFile 析构时才真的从盘上消失（Linux 用匿名临时
        // 文件，所以这一步在那边看不出来）。
        device.reset();

        QVERIFY(!QFile::exists(QDir(dir.path()).filePath(QStringLiteral("photo.jpg"))));
        const QStringList left = QDir(sink.tempDir()).entryList(QDir::Files | QDir::Hidden);
        QVERIFY2(left.isEmpty(),
                 qPrintable(QStringLiteral("discard 之后还有残留：%1")
                                .arg(left.join(QStringLiteral(", ")))));
    }

    // §5.6：重传要从零开始，不能把两次的字节接在一起。QSaveFile 未 commit 就析构
    // 会丢弃临时文件，所以重传天然干净。
    void retriedUploadStartsWithCleanTempData()
    {
        {
            LocalFileSink first(m_dir.path(), kSessionId, kFileId, QStringLiteral("photo.jpg"),
                                kFingerprint, 100);
            const auto device = first.open();
            QVERIFY(device != nullptr);
            writeAll(device.get(), QByteArray(60, 'x'));
            // 连接断了：不 commit，直接丢弃。
            first.discard();
        }

        LocalFileSink second(m_dir.path(), kSessionId, kFileId, QStringLiteral("photo.jpg"),
                             kFingerprint, 4);
        const auto device = second.open();
        QVERIFY(device != nullptr);
        QCOMPARE(second.bytesWritten(), quint64{0});
        writeAll(device.get(), QByteArray("full"));
        QVERIFY(second.commit());

        QFile landed(second.finalPath());
        QVERIFY(landed.open(QIODevice::ReadOnly));
        QCOMPARE(landed.readAll(), QByteArray("full"));
    }

    void commitAndDiscardAreIdempotent()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("once.txt"),
                           kFingerprint, 1);
        const auto device = sink.open();
        QVERIFY(device != nullptr);
        writeAll(device.get(), QByteArray("z"));

        QVERIFY(sink.commit());
        QVERIFY(sink.commit()); // 重复 commit 是无操作
        sink.discard();         // commit 之后 discard 也不该删掉已落位的文件
        QVERIFY(QFile::exists(QDir(m_dir.path()).filePath(QStringLiteral("once.txt"))));
    }

    // 设备的所有权在调用方：它先没了，sink 只能拒绝，不能踩空。
    void commitAfterDeviceIsGoneFailsInsteadOfCrashing()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("gone.txt"),
                           kFingerprint, 1);
        {
            auto device = sink.open();
            QVERIFY(device != nullptr);
            writeAll(device.get(), QByteArray("z"));
        }
        QVERIFY(!sink.commit());
        QVERIFY(sink.finalPath().isEmpty());
    }

    void sinkRefusesASecondOpen()
    {
        LocalFileSink sink(m_dir.path(), kSessionId, kFileId, QStringLiteral("twice.txt"),
                           kFingerprint, 1);
        const auto first = sink.open();
        QVERIFY(first != nullptr);
        QVERIFY(sink.open() == nullptr);
    }
};

QTEST_GUILESS_MAIN(TestLocalFiles)

#include "tst_localfiles.moc"
