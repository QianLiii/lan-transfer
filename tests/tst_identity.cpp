// 设备身份（§4）。重点在两条不变量：指纹取自 SPKI 而非证书，以及
// 证书重签不改变设备身份。
//
// 注意本文件一律用 `if (!x.has_value()) QFAIL(qPrintable(x.error()));`
// 而不是 `QVERIFY2(x.has_value(), qPrintable(x.error()))`：后者会**无条件**
// 求值消息参数，于是在成功路径上也会调用 error()，触发 std::expected 的内部断言。

#include <QtTest>

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>

#include "identity.h"

using namespace lanpipe;

namespace {

QByteArray readFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return file.readAll();
}

// 把 dir 里的证书改成一天前过期。用 OpenSSL 改 notAfter 并用同一把私钥重签，
// 因此改完之后证书与私钥仍然对应——测的是「过期」，不是「不匹配」。
bool expireCertificate(const QString &dir)
{
    const QByteArray certPem = readFile(QDir(dir).filePath(QStringLiteral("cert.pem")));
    const QByteArray keyPem = readFile(QDir(dir).filePath(QStringLiteral("key.pem")));
    if (certPem.isEmpty() || keyPem.isEmpty())
        return false;

    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    BioPtr certBio{BIO_new_mem_buf(certPem.constData(), static_cast<int>(certPem.size())),
                   &BIO_free_all};
    BioPtr keyBio{BIO_new_mem_buf(keyPem.constData(), static_cast<int>(keyPem.size())),
                  &BIO_free_all};
    if (!certBio || !keyBio)
        return false;

    X509Ptr certificate{PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr), &X509_free};
    KeyPtr key{PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free};
    if (!certificate || !key)
        return false;

    if (X509_gmtime_adj(X509_getm_notAfter(certificate.get()), -24 * 60 * 60) == nullptr)
        return false;
    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) == 0)
        return false;

    BioPtr output{BIO_new(BIO_s_mem()), &BIO_free_all};
    if (!output || PEM_write_bio_X509(output.get(), certificate.get()) != 1)
        return false;

    char *data = nullptr;
    const long length = BIO_get_mem_data(output.get(), &data);
    if (length <= 0 || data == nullptr)
        return false;

    QFile file(QDir(dir).filePath(QStringLiteral("cert.pem")));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    return file.write(QByteArray(data, length)) == length;
}

} // namespace

class TestIdentity : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    [[nodiscard]] QString dirFor(const char *name) const
    {
        return m_dir.filePath(QLatin1String(name));
    }

private slots:
    void initTestCase() { QVERIFY(m_dir.isValid()); }

    // 重启后身份必须不变，否则每次启动都会切断已有配对。
    void identityPersistsAcrossLoads()
    {
        const QString dir = dirFor("persist");

        auto first = Identity::loadOrCreate(dir);
        if (!first.has_value())
            QFAIL(qPrintable(first.error()));

        auto second = Identity::loadOrCreate(dir);
        if (!second.has_value())
            QFAIL(qPrintable(second.error()));

        QCOMPARE(second->fingerprint().toHex(), first->fingerprint().toHex());
        QCOMPARE(second->certificate().toDer(), first->certificate().toDer());
    }

    // §4 的核心：指纹 = SPKI 的 SHA-256，不是证书的哈希。
    // 因此证书可以重签而设备身份不变。
    void reissuingCertificateKeepsIdentity()
    {
        const QString dir = dirFor("reissue");

        auto before = Identity::loadOrCreate(dir);
        if (!before.has_value())
            QFAIL(qPrintable(before.error()));

        QVERIFY(QFile::remove(QDir(dir).filePath(QStringLiteral("cert.pem"))));

        auto after = Identity::loadOrCreate(dir);
        if (!after.has_value())
            QFAIL(qPrintable(after.error()));

        QVERIFY(after->certificate().toDer() != before->certificate().toDer());
        QCOMPARE(after->fingerprint().toHex(), before->fingerprint().toHex());
        QCOMPARE(after->deviceId(), before->deviceId());
    }

    // 若指纹误用证书哈希，这条会立刻失败——是上一条不变量的直接反证。
    void fingerprintIsNotTheCertificateHash()
    {
        auto identity = Identity::loadOrCreate(dirFor("notcerthash"));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        const QByteArray certificateHash = QCryptographicHash::hash(
            identity->certificate().toDer(), QCryptographicHash::Sha256);

        QCOMPARE(identity->fingerprint().bytes().size(), 32);
        QVERIFY(identity->fingerprint().bytes() != certificateHash);
    }

    // 本端与对端必须走同一条计算路径，否则 SAS 两端算出的码不同。
    void fingerprintFromCertificateMatchesIdentity()
    {
        auto identity = Identity::loadOrCreate(dirFor("samepath"));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        const Fingerprint fromCertificate = Fingerprint::fromCertificate(identity->certificate());
        QCOMPARE(fromCertificate.toHex(), identity->fingerprint().toHex());
    }

    void deviceIdIsFingerprintPrefix()
    {
        auto identity = Identity::loadOrCreate(dirFor("deviceid"));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        const QString hex = identity->fingerprint().toHex();
        QCOMPARE(identity->deviceId(), hex.left(proto::kDeviceIdBytes * 2));
        QCOMPARE(identity->deviceId().size(), proto::kDeviceIdBytes * 2);
    }

    // 证书损坏时必须报错，而不是悄悄用同一私钥重签——静默重签会让一次误操作
    // 变成身份变更，而对端看到的只是「设备身份变了」。
    void corruptCertificateIsReportedNotSilentlyReissued()
    {
        const QString dir = dirFor("corrupt");
        QVERIFY(Identity::loadOrCreate(dir).has_value());

        QFile certificate(QDir(dir).filePath(QStringLiteral("cert.pem")));
        QVERIFY(certificate.open(QIODevice::WriteOnly | QIODevice::Truncate));
        certificate.write("not a certificate");
        certificate.close();

        const auto result = Identity::loadOrCreate(dir);
        QVERIFY(!result.has_value());
    }

    // 私钥丢失而证书还在：必须报错，而不是生成新密钥再配上旧证书。
    // 后者会得到一个声称旧指纹、实际持有新公钥的设备。
    void missingPrivateKeyIsReported()
    {
        const QString dir = dirFor("nokey");
        QVERIFY(Identity::loadOrCreate(dir).has_value());

        QVERIFY(QFile::remove(QDir(dir).filePath(QStringLiteral("key.pem"))));

        const auto result = Identity::loadOrCreate(dir);
        QVERIFY(!result.has_value());
        // 不得写入新密钥：那会留下一个永远用不上的文件
        QVERIFY(!QFile::exists(QDir(dir).filePath(QStringLiteral("key.pem"))));
    }

    // 两个文件都在但来自不同的生成过程（复制、只恢复了一半的备份）：
    // 必须拒绝，否则设备声称的身份与实际公钥不符。
    void mismatchedCertificateAndKeyIsRejected()
    {
        const QString dirA = dirFor("pairA");
        const QString dirB = dirFor("pairB");
        QVERIFY(Identity::loadOrCreate(dirA).has_value());
        QVERIFY(Identity::loadOrCreate(dirB).has_value());

        // 把 B 的私钥搬到 A：A 现在是 A 的证书 + B 的私钥
        QVERIFY(QFile::remove(QDir(dirA).filePath(QStringLiteral("key.pem"))));
        QVERIFY(QFile::copy(QDir(dirB).filePath(QStringLiteral("key.pem")),
                            QDir(dirA).filePath(QStringLiteral("key.pem"))));

        const auto result = Identity::loadOrCreate(dirA);
        QVERIFY(!result.has_value());
    }

    // 过期证书应当自动从**同一把**私钥重签，设备身份不变——用户什么都不用做。
    // 这正是把指纹定义在 SPKI 而非证书上的收益。
    void expiredCertificateIsRenewedKeepingIdentity()
    {
        const QString dir = dirFor("expired");
        auto before = Identity::loadOrCreate(dir);
        if (!before.has_value())
            QFAIL(qPrintable(before.error()));

        const QByteArray keyBefore = readFile(QDir(dir).filePath(QStringLiteral("key.pem")));
        QVERIFY(!keyBefore.isEmpty());
        QVERIFY(expireCertificate(dir));

        auto after = Identity::loadOrCreate(dir);
        if (!after.has_value())
            QFAIL(qPrintable(after.error()));

        // 证书换了……
        QVERIFY(after->certificate().toDer() != before->certificate().toDer());
        // ……但私钥没换，身份也没变
        QCOMPARE(readFile(QDir(dir).filePath(QStringLiteral("key.pem"))), keyBefore);
        QCOMPARE(after->fingerprint().toHex(), before->fingerprint().toHex());
        QCOMPARE(after->deviceId(), before->deviceId());
        // 新证书重新有了完整的有效期
        QVERIFY(after->certificate().expiryDate() > QDateTime::currentDateTimeUtc().addYears(9));
    }

    void certificateValidityIsAboutTenYears()
    {
        auto identity = Identity::loadOrCreate(dirFor("validity"));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        const QDateTime expiry = identity->certificate().expiryDate();
        const QDateTime now = QDateTime::currentDateTimeUtc();
        QVERIFY(expiry > now.addYears(9));
        QVERIFY(expiry < now.addYears(11));
    }

    void hexRoundTripsAndRejectsBadInput()
    {
        auto identity = Identity::loadOrCreate(dirFor("hex"));
        if (!identity.has_value())
            QFAIL(qPrintable(identity.error()));

        const auto parsed = Fingerprint::fromHex(identity->fingerprint().toHex());
        QVERIFY(parsed.has_value());
        QCOMPARE(parsed->bytes(), identity->fingerprint().bytes());

        QVERIFY(!Fingerprint::fromHex(QStringLiteral("abcd")).has_value());
        QVERIFY(!Fingerprint::fromHex(QString()).has_value());
    }

    void invalidFingerprintHasNoDeviceId()
    {
        QCOMPARE(deviceIdFrom(Fingerprint{}), QString());
    }

#ifndef Q_OS_WIN
    // 私钥不应对其他用户可读。
    void privateKeyIsOwnerOnly()
    {
        const QString dir = dirFor("perms");
        QVERIFY(Identity::loadOrCreate(dir).has_value());

        const QFile::Permissions permissions =
            QFile::permissions(QDir(dir).filePath(QStringLiteral("key.pem")));

        QVERIFY(!(permissions & QFileDevice::ReadGroup));
        QVERIFY(!(permissions & QFileDevice::ReadOther));
        QVERIFY(!(permissions & QFileDevice::WriteGroup));
        QVERIFY(!(permissions & QFileDevice::WriteOther));
    }
#endif
};

QTEST_GUILESS_MAIN(TestIdentity)

#include "tst_identity.moc"
