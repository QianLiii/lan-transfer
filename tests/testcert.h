#pragma once

// 测试助手：把身份目录里的证书改成已过期或尚未生效。
//
// 用 OpenSSL 改有效期字段并用**同一把私钥**重签，所以改完之后证书与私钥仍然互相对应
// ——测的是「有效期」，不是「不匹配」。
//
// 两个地方用它：identity 测到期自动重签，httptransport 测「有效期不参与身份判定」。

#include <QByteArray>
#include <QDir>
#include <QFile>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>

namespace testcert {

enum class Validity {
    Expired,      // notAfter 挪到一天前
    NotYetValid,  // notBefore 挪到一天后
};

inline QByteArray readFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return file.readAll();
}

inline bool setValidity(const QString &dir, Validity validity)
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

    constexpr long kOneDay = 24 * 60 * 60;
    const bool shifted = validity == Validity::Expired
        ? X509_gmtime_adj(X509_getm_notAfter(certificate.get()), -kOneDay) != nullptr
        : X509_gmtime_adj(X509_getm_notBefore(certificate.get()), kOneDay) != nullptr;
    if (!shifted)
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

} // namespace testcert
