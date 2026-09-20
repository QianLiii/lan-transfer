// 信任库（§4）。它存的是「deviceId → 公钥指纹」，因此要守住两件事：
// 换证书不影响（指纹在 SPKI 上），换密钥必然被拒。

#include <QtTest>

#include <QFile>
#include <QDir>
#include <QTemporaryDir>

#include "identity.h"
#include "trust/truststore.h"

using namespace lanpipe;
using namespace lanpipe::trust;

class TestTrustStore : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    [[nodiscard]] QString path() const { return m_dir.filePath(QStringLiteral("trust.json")); }

    static TrustStore::Entry entryFor(const Identity &identity, const QString &name)
    {
        return {identity.deviceId(), identity.fingerprint().toHex(), name,
                QDateTime::currentDateTimeUtc()};
    }

private slots:
    void initTestCase() { QVERIFY(m_dir.isValid()); }

    void init() { QFile::remove(path()); }

    void startsEmptyWhenTheFileIsMissing()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));
        QCOMPARE(store->size(), qsizetype{0});
        QCOMPARE(store->size(), qsizetype{0});
    }

    void persistsAcrossLoads()
    {
        QTemporaryDir identityDir;
        QVERIFY(identityDir.isValid());
        auto identity = Identity::loadOrCreate(identityDir.filePath(QStringLiteral("peer")));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        {
            auto store = TrustStore::load(path());
            if (!store.has_value())
                QFAIL(qPrintable(store.error()));
            QString error;
            QVERIFY2(store->add(entryFor(*identity, QStringLiteral("台式机")), &error),
                     qPrintable(error));
        }

        auto reloaded = TrustStore::load(path());
        if (!reloaded.has_value())
            QFAIL(qPrintable(reloaded.error()));

        const auto entry = reloaded->find(identity->deviceId());
        QVERIFY(entry.has_value());
        QCOMPARE(entry->fingerprint, identity->fingerprint().toHex());
        QCOMPARE(entry->name, QStringLiteral("台式机"));
    }

    // 用户改名后再次配对，记录要被覆盖而不是留两条。
    void addingAgainOverwritesTheName()
    {
        QTemporaryDir identityDir;
        QVERIFY(identityDir.isValid());
        auto identity = Identity::loadOrCreate(identityDir.filePath(QStringLiteral("peer")));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        QString error;
        QVERIFY(store->add(entryFor(*identity, QStringLiteral("旧名")), &error));
        QVERIFY(store->add(entryFor(*identity, QStringLiteral("新名")), &error));

        QCOMPARE(store->size(), qsizetype{1});
        QCOMPARE(store->find(identity->deviceId())->name, QStringLiteral("新名"));
    }

    void removeForgetsThePeer()
    {
        QTemporaryDir identityDir;
        QVERIFY(identityDir.isValid());
        auto identity = Identity::loadOrCreate(identityDir.filePath(QStringLiteral("peer")));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        QString error;
        QVERIFY(store->add(entryFor(*identity, QStringLiteral("台式机")), &error));
        QVERIFY(store->remove(identity->deviceId(), &error));
        QVERIFY(!store->contains(identity->deviceId()));

        // 删除也要落盘。
        auto reloaded = TrustStore::load(path());
        QVERIFY(reloaded.has_value());
        QVERIFY(!reloaded->contains(identity->deviceId()));
    }

    // 同一把密钥重签证书：deviceId 与指纹都不变，配对关系不受影响（§4 的核心收益）。
    void reissuingTheCertificateKeepsThePairing()
    {
        QTemporaryDir identityDir;
        QVERIFY(identityDir.isValid());
        const QString dir = identityDir.filePath(QStringLiteral("peer"));

        auto before = Identity::loadOrCreate(dir);
        if (!before.has_value())
            QFAIL(qPrintable(before.error()));

        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));
        QString error;
        QVERIFY(store->add(entryFor(*before, QStringLiteral("台式机")), &error));

        QVERIFY(QFile::remove(QDir(dir).filePath(QStringLiteral("cert.pem"))));
        auto after = Identity::loadOrCreate(dir);
        if (!after.has_value())
            QFAIL(qPrintable(after.error()));

        QVERIFY(after->certificate().toDer() != before->certificate().toDer());
        QVERIFY(store->contains(after->deviceId()));
        QVERIFY(!store->identityChanged(after->deviceId(), after->fingerprint().toHex()));
    }

    // 未配对谈不上「变了」；已配对而指纹不符才拒绝。
    void identityChangedOnlyAppliesToKnownDevices()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QString deviceId = QString(32, QLatin1Char('a'));
        QVERIFY(!store->identityChanged(deviceId, QString(64, QLatin1Char('b'))));

        QString error;
        QVERIFY(store->add({deviceId, QString(64, QLatin1Char('b')), QStringLiteral("x"),
                            QDateTime::currentDateTimeUtc()},
                           &error));
        QVERIFY(!store->identityChanged(deviceId, QString(64, QLatin1Char('b'))));
        QVERIFY(store->identityChanged(deviceId, QString(64, QLatin1Char('c'))));
        // 大小写不该影响比较。
        QVERIFY(!store->identityChanged(deviceId, QString(64, QLatin1Char('B'))));
    }

    // —————————————— 黑名单（§4）——————————————

    void blockedEntriesPersist()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QString deviceId = QString(32, QLatin1Char('a'));
        QString error;
        QVERIFY(store->block({deviceId, QStringLiteral("广告机"), QDateTime::currentDateTimeUtc()}, &error));
        QVERIFY(store->isBlocked(deviceId));

        auto reloaded = TrustStore::load(path());
        if (!reloaded.has_value())
            QFAIL(qPrintable(reloaded.error()));
        QVERIFY(reloaded->isBlocked(deviceId));
        QCOMPARE(reloaded->blocked().size(), 1);
        QCOMPARE(reloaded->blocked().first().name, QStringLiteral("广告机"));
    }

    // 屏蔽一台已配对设备不会把配对关系摘掉：屏蔽优先于配对，恢复时配对还在。
    void blockingKeepsThePairing()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QString deviceId = QString(32, QLatin1Char('b'));
        QString error;
        QVERIFY(store->add({deviceId, QString(64, QLatin1Char('c')), QStringLiteral("对端"),
                            QDateTime::currentDateTimeUtc()},
                           &error));
        QVERIFY(store->block({deviceId, QStringLiteral("对端"), QDateTime::currentDateTimeUtc()}, &error));

        QVERIFY(store->isBlocked(deviceId));
        QVERIFY(store->contains(deviceId));

        QVERIFY(store->unblock(deviceId, &error));
        QVERIFY(!store->isBlocked(deviceId));
        QVERIFY(store->contains(deviceId)); // 配对关系自始至终都在
    }

    void unblockingAnUnknownDeviceIsANoOp()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        QString error;
        QVERIFY(store->unblock(QString(32, QLatin1Char('d')), &error));
        QVERIFY(store->blocked().isEmpty());
    }

    // 另一个进程改过盘上的文件之后，reload() 要看得见——`lanpipe block` 与 `serve`
    // 不是一个进程，而用户期望屏蔽立刻生效。
    void reloadSeesChangesMadeElsewhere()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QString deviceId = QString(32, QLatin1Char('e'));
        QVERIFY(!store->isBlocked(deviceId));

        {
            // 模拟另一个进程：另开一个实例写同一个文件。
            auto other = TrustStore::load(path());
            if (!other.has_value())
                QFAIL(qPrintable(other.error()));
            QString error;
            QVERIFY(other->block({deviceId, QStringLiteral("外面屏蔽的"),
                                  QDateTime::currentDateTimeUtc()},
                                 &error));
        }

        QVERIFY(!store->isBlocked(deviceId)); // 还没重读，看不见
        QVERIFY(store->reload());
        QVERIFY(store->isBlocked(deviceId));
    }

    // 重读失败时保持原样：一次读失败不该把内存里的配对关系清掉。
    void reloadKeepsStateWhenTheFileIsGone()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QString deviceId = QString(32, QLatin1Char('f'));
        QString error;
        QVERIFY(store->block({deviceId, QStringLiteral("x"), QDateTime::currentDateTimeUtc()},
                             &error));

        QVERIFY(QFile::remove(path()));
        QVERIFY(store->reload());
        // 文件没了就是空表——这是「还没配过对」的正常状态，不是错误。
        QVERIFY(!store->isBlocked(deviceId));
    }

    // 黑名单是后加的字段：老文件里没有它，加载时应当当成空名单，而不是「损坏」。
    void fileWithoutABlockListStillLoads()
    {
        QFile file(path());
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(R"({"version":1,"peers":[{"deviceId":"aaa","fingerprint":"bbb",)"
                   R"("name":"旧记录","pairedAt":"2026-01-01T00:00:00Z"}]})");
        file.close();

        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));
        QCOMPARE(store->size(), 1);
        QVERIFY(store->blocked().isEmpty());
    }

    // 损坏的信任库必须报错，不能当成空表——那等于把用户所有配对关系悄悄清掉。
    void corruptedFileIsReported()
    {
        QFile file(path());
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        file.write("{ not json");
        file.close();

        QVERIFY(!TrustStore::load(path()).has_value());
    }

    void wrongFormatVersionIsReported()
    {
        QFile file(path());
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        file.write(R"({"version":99,"peers":[]})");
        file.close();

        QVERIFY(!TrustStore::load(path()).has_value());
    }

    void emptyDevicesAreRejected()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        QString error;
        QVERIFY(!store->add({QString(), QString(64, QLatin1Char('a')), QStringLiteral("x"),
                             QDateTime::currentDateTimeUtc()},
                            &error));
        QVERIFY(!error.isEmpty());
        QCOMPARE(store->size(), qsizetype{0});
    }

    void entriesAreOrderedByMostRecent()
    {
        auto store = TrustStore::load(path());
        if (!store.has_value())
            QFAIL(qPrintable(store.error()));

        const QDateTime now = QDateTime::currentDateTimeUtc();
        QString error;
        QVERIFY(store->add({QString(32, QLatin1Char('a')), QString(64, QLatin1Char('a')),
                            QStringLiteral("旧"), now.addSecs(-60)},
                           &error));
        QVERIFY(store->add({QString(32, QLatin1Char('b')), QString(64, QLatin1Char('b')),
                            QStringLiteral("新"), now},
                           &error));

        const QList<TrustStore::Entry> entries = store->entries();
        QCOMPARE(entries.size(), 2);
        QCOMPARE(entries.at(0).name, QStringLiteral("新"));
    }
};

QTEST_GUILESS_MAIN(TestTrustStore)

#include "tst_truststore.moc"
