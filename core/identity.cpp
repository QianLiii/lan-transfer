#include "identity.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>

namespace lanpipe {

namespace {

// OpenSSL 对象的 RAII 包装，避免任何一条提前返回的路径漏释放。
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using Asn1IntPtr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;

// 证书有效期 10 年。指纹取自 SPKI，所以到期重签不会改变设备身份。
constexpr long kValiditySeconds = 10L * 365 * 24 * 60 * 60;

QString lastOpenSslError()
{
    const unsigned long code = ERR_get_error();
    if (code == 0)
        return QStringLiteral("(OpenSSL 未给出错误码)");
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return QString::fromLatin1(buffer);
}

QByteArray bioToByteArray(const BioPtr &bio)
{
    char *data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr)
        return {};
    return QByteArray(data, length);
}

QByteArray pemFromKey(EVP_PKEY *key)
{
    BioPtr bio{BIO_new(BIO_s_mem()), &BIO_free_all};
    if (!bio)
        return {};
    if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        return {};
    return bioToByteArray(bio);
}

QByteArray pemFromCertificate(X509 *certificate)
{
    BioPtr bio{BIO_new(BIO_s_mem()), &BIO_free_all};
    if (!bio)
        return {};
    if (PEM_write_bio_X509(bio.get(), certificate) != 1)
        return {};
    return bioToByteArray(bio);
}

EvpKeyPtr keyFromPem(const QByteArray &pem)
{
    BioPtr bio{BIO_new_mem_buf(pem.constData(), static_cast<int>(pem.size())), &BIO_free_all};
    if (!bio)
        return {nullptr, &EVP_PKEY_free};
    return {PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free};
}

// 证书剩余有效期少于这个天数就从同一私钥重签。留出窗口是为了避免
// 「启动时还有效、跑到一半过期」，而不只是为了处理已过期的情况。
constexpr int kRenewalWindowDays = 30;

// 已过期或临近过期。
bool certificateNeedsRenewal(const QSslCertificate &certificate)
{
    const QDateTime expiry = certificate.expiryDate();
    if (!expiry.isValid())
        return true;
    return expiry <= QDateTime::currentDateTimeUtc().addDays(kRenewalWindowDays);
}

// 用 OpenSSL 的专用接口校验证书与私钥是否对应，比自行比对 DER 可靠。
bool certificateMatchesKey(const QSslCertificate &certificate, EVP_PKEY *key)
{
    const QByteArray der = certificate.toDer();
    if (der.isEmpty())
        return false;
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.constData());
    X509Ptr parsed{d2i_X509(nullptr, &cursor, der.size()), &X509_free};
    if (!parsed)
        return false;
    return X509_check_private_key(parsed.get(), key) == 1;
}

// 原子写入：先写临时文件再改名。中途崩溃不会留下半截文件，
// 否则下次启动只会看到「无法解析」这类只能靠删文件恢复的状态。
bool writeFileAtomically(const QString &path, const QByteArray &data, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        *error = QStringLiteral("无法写入 %1：%2").arg(path, file.errorString());
        return false;
    }
    if (file.write(data) != data.size()) {
        *error = QStringLiteral("写入 %1 不完整").arg(path);
        return false;
    }
    if (!file.commit()) {
        *error = QStringLiteral("提交 %1 失败：%2").arg(path, file.errorString());
        return false;
    }
    return true;
}

// EC P-256。选 EC 而不是 RSA：更小更快，而两端都是我们自己的实现，
// 不必迁就只支持 RSA 的老栈。
EvpKeyPtr generateKey()
{
    return {EVP_EC_gen("prime256v1"), &EVP_PKEY_free};
}

X509Ptr issueSelfSignedCertificate(EVP_PKEY *key)
{
    X509Ptr certificate{X509_new(), &X509_free};
    if (!certificate)
        return {nullptr, &X509_free};

    if (X509_set_version(certificate.get(), 2) != 1) // X.509 v3
        return {nullptr, &X509_free};

    // 序列号随机：OpenSSL 3 起不再推荐小或递增的序列号。
    BnPtr serial{BN_new(), &BN_free};
    Asn1IntPtr asn1Serial{ASN1_INTEGER_new(), &ASN1_INTEGER_free};
    if (!serial || !asn1Serial)
        return {nullptr, &X509_free};
    if (BN_rand(serial.get(), 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1)
        return {nullptr, &X509_free};
    if (BN_to_ASN1_INTEGER(serial.get(), asn1Serial.get()) == nullptr)
        return {nullptr, &X509_free};
    if (X509_set_serialNumber(certificate.get(), asn1Serial.get()) != 1)
        return {nullptr, &X509_free};

    if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) == nullptr)
        return {nullptr, &X509_free};
    if (X509_gmtime_adj(X509_getm_notAfter(certificate.get()), kValiditySeconds) == nullptr)
        return {nullptr, &X509_free};

    // 主题固定，不放设备名：名字是可变元数据（用户随时可改），证书是身份，
    // 而身份由公钥承载、不由 CN 承载。
    X509_NAME *name = X509_get_subject_name(certificate.get());
    const auto addField = [name](const char *field, const char *value) {
        return X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                          reinterpret_cast<const unsigned char *>(value),
                                          -1, -1, 0)
            == 1;
    };
    if (!addField("O", "lanpipe") || !addField("CN", "device"))
        return {nullptr, &X509_free};

    if (X509_set_issuer_name(certificate.get(), name) != 1) // 自签
        return {nullptr, &X509_free};
    if (X509_set_pubkey(certificate.get(), key) != 1)
        return {nullptr, &X509_free};
    if (X509_sign(certificate.get(), key, EVP_sha256()) == 0)
        return {nullptr, &X509_free};

    return certificate;
}

} // namespace

Fingerprint Fingerprint::fromCertificate(const QSslCertificate &certificate)
{
    Fingerprint fingerprint;

    const QByteArray der = certificate.toDer();
    if (der.isEmpty())
        return fingerprint;

    // 直接从证书 DER 取 SubjectPublicKeyInfo，而不是经 QSslKey::toDer()：
    // 后者是 PEM 往返，编码形态取决于 Qt 生成的 PEM 头（"PUBLIC KEY" 才是
    // SubjectPublicKeyInfo），依赖它会让指纹的含义随 Qt 版本漂移，
    // 而指纹是整个信任模型的地基。
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.constData());
    X509Ptr parsed{d2i_X509(nullptr, &cursor, der.size()), &X509_free};
    if (!parsed)
        return fingerprint;

    unsigned char *raw = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(parsed.get()), &raw);
    if (length <= 0 || raw == nullptr)
        return fingerprint;

    // i2d_* 用 OPENSSL_malloc 分配，必须配对 OPENSSL_free。
    const QByteArray spki(reinterpret_cast<const char *>(raw), length);
    OPENSSL_free(raw);

    fingerprint.m_bytes = QCryptographicHash::hash(spki, QCryptographicHash::Sha256);
    return fingerprint;
}

std::optional<Fingerprint> Fingerprint::fromHex(const QString &hex)
{
    const QByteArray raw = QByteArray::fromHex(hex.toLatin1());
    if (raw.size() != 32)
        return std::nullopt;

    Fingerprint fingerprint;
    fingerprint.m_bytes = raw;
    return fingerprint;
}

QString Fingerprint::toHex() const
{
    return QString::fromLatin1(m_bytes.toHex());
}

QString Fingerprint::shortForm() const
{
    return QString::fromLatin1(m_bytes.left(8).toHex());
}

QString deviceIdFrom(const Fingerprint &fingerprint)
{
    if (!fingerprint.isValid())
        return {};
    return QString::fromLatin1(fingerprint.bytes().left(proto::kDeviceIdBytes).toHex());
}

QString Identity::defaultDir()
{
    return QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation))
        .filePath(QStringLiteral("identity"));
}

std::expected<Identity, QString> Identity::loadOrCreate(const QString &dir)
{
    QDir directory(dir);
    if (!directory.mkpath(QStringLiteral(".")))
        return std::unexpected(QStringLiteral("无法创建身份目录：%1").arg(dir));

    const QString keyPath = directory.filePath(QStringLiteral("key.pem"));
    const QString certPath = directory.filePath(QStringLiteral("cert.pem"));

    // 证书还在、私钥没了：身份已无法恢复，因为证书只是公钥的容器。
    // 这里必须拦住，否则会生成一把新密钥再配上旧证书——得到一个声称旧指纹、
    // 实际持有新公钥的设备。这是用户必须显式决定的事。
    if (QFile::exists(certPath) && !QFile::exists(keyPath)) {
        return std::unexpected(
            QStringLiteral("私钥已丢失，但证书仍在：%1\n"
                           "身份无法从证书恢复。删除证书 %2 可生成全新的设备身份，"
                           "代价是需要与所有对端重新配对。")
                .arg(keyPath, certPath));
    }

    // ———— 私钥：有就加载，没有就生成 ————
    QByteArray keyPem;
    QFile keyFile(keyPath);
    if (keyFile.exists()) {
        if (!keyFile.open(QIODevice::ReadOnly))
            return std::unexpected(
                QStringLiteral("无法读取私钥 %1：%2").arg(keyPath, keyFile.errorString()));
        keyPem = keyFile.readAll();
        keyFile.close();
    } else {
        const EvpKeyPtr generated = generateKey();
        if (!generated)
            return std::unexpected(QStringLiteral("生成密钥失败：%1").arg(lastOpenSslError()));

        keyPem = pemFromKey(generated.get());
        if (keyPem.isEmpty())
            return std::unexpected(QStringLiteral("导出私钥失败：%1").arg(lastOpenSslError()));

        QString writeError;
        if (!writeFileAtomically(keyPath, keyPem, &writeError))
            return std::unexpected(writeError);
        // 私钥只留给属主。Windows 上不生效，也不做特殊处理。
        QFile::setPermissions(keyPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }

    // 解析成 EVP_PKEY：既用于校验证书与私钥是否对应，也用于缺证书时重签。
    const EvpKeyPtr key = keyFromPem(keyPem);
    if (!key)
        return std::unexpected(
            QStringLiteral("无法从 PEM 解析私钥（文件被替换或损坏？）：%1").arg(keyPath));

    Identity identity;
    identity.m_privateKey = QSslKey(keyPem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
    if (identity.m_privateKey.isNull())
        return std::unexpected(
            QStringLiteral("私钥无法解析为 EC 私钥（文件被替换或损坏？）：%1").arg(keyPath));

    // ———— 证书：从私钥派生。缺失就地签发，损坏则报错 ————
    QFile certFile(certPath);
    if (certFile.exists()) {
        if (!certFile.open(QIODevice::ReadOnly))
            return std::unexpected(
                QStringLiteral("无法读取证书 %1：%2").arg(certPath, certFile.errorString()));
        identity.m_certificate = QSslCertificate(certFile.readAll(), QSsl::Pem);
        certFile.close();
        if (identity.m_certificate.isNull()) {
            // 损坏与过期的处理刻意不同：过期重签用的是同一把私钥，指纹不变，
            // 因而是安全的；损坏则可能意味着文件被替换，必须由用户决定。
            return std::unexpected(
                QStringLiteral("证书损坏：%1\n"
                               "删除该文件可从同一私钥重新签发，"
                               "设备身份（SPKI 指纹）不变。")
                    .arg(certPath));
        }
    }

    if (identity.m_certificate.isNull() || certificateNeedsRenewal(identity.m_certificate)) {
        // 证书缺失或到期：从同一私钥重签。这正是 SPKI 指纹的价值——
        // 证书可以随便重签，而配对关系不受影响（§4）。
        const bool renewing = !identity.m_certificate.isNull();

        const X509Ptr issued = issueSelfSignedCertificate(key.get());
        if (!issued)
            return std::unexpected(QStringLiteral("签发证书失败：%1").arg(lastOpenSslError()));

        const QByteArray certPem = pemFromCertificate(issued.get());
        if (certPem.isEmpty())
            return std::unexpected(QStringLiteral("导出证书失败：%1").arg(lastOpenSslError()));

        QString writeError;
        if (!writeFileAtomically(certPath, certPem, &writeError))
            return std::unexpected(writeError);

        identity.m_certificate = QSslCertificate(certPem, QSsl::Pem);
        if (identity.m_certificate.isNull())
            return std::unexpected(QStringLiteral("新签发的证书无法被 Qt 解析：%1").arg(certPath));

        // 自动重签是静默发生的状态变化，留一行日志便于事后排查。
        if (renewing)
            qInfo("lanpipe: 设备证书已到期或临近到期，已从同一私钥重签；设备身份不变。");
    }

    // 证书必须与私钥对应。这条检查不是多余的：key.pem 丢失或被删而 cert.pem
    // 尚在时，上面的分支会生成新密钥，随后这里会把旧证书配上去——设备对外
    // 声称的指纹来自旧证书、实际持有的却是新公钥，要到握手时才以难以定位的
    // 方式失败（备份只恢复了一半就是最常见的成因）。
    if (!certificateMatchesKey(identity.m_certificate, key.get())) {
        return std::unexpected(
            QStringLiteral("证书与私钥不对应：%1 与 %2 不是同一次生成的。\n"
                           "删除这两者可以重新生成身份（设备指纹会变，需要重新配对），"
                           "或从备份中恢复到匹配的那一份。")
                .arg(certPath, keyPath));
    }

    identity.m_fingerprint = Fingerprint::fromCertificate(identity.m_certificate);
    if (!identity.m_fingerprint.isValid())
        return std::unexpected(QStringLiteral("无法从证书计算 SPKI 指纹：%1").arg(certPath));

    return identity;
}

} // namespace lanpipe
