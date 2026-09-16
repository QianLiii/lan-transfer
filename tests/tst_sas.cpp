// SAS 与它的缓存（§4 配对）。
//
// 这个文件里的断言都在守同一件事：两端只要输入相同就必须算出同一个码，
// 输入一旦不同（中间人必然造成这种情况）就必须不同。

#include <QtTest>

#include "protocol.h"
#include "sas.h"

using namespace lanpipe;

namespace {

// 两个固定的、互不相同的指纹。
const Fingerprint kSender = *Fingerprint::fromHex(
    QStringLiteral("1111111111111111111111111111111111111111111111111111111111111111"));
const Fingerprint kReceiver = *Fingerprint::fromHex(
    QStringLiteral("2222222222222222222222222222222222222222222222222222222222222222"));

const QString kCnonce = QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
const QString kSnonce = QStringLiteral("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

} // namespace

class TestSas : public QObject
{
    Q_OBJECT

private slots:
    void bothSidesAgreeOnTheSameInput()
    {
        // 两端调用的参数顺序不同、取值相同，结果必须一致。
        const QByteArray senderSide = computeSas(kSender, kReceiver, kCnonce, kSnonce);
        const QByteArray receiverSide = computeSas(kSender, kReceiver, kCnonce, kSnonce);

        QCOMPARE(senderSide, receiverSide);
        QCOMPARE(sasCode(senderSide), sasCode(receiverSide));
    }

    void everyInputParticipates()
    {
        const QByteArray baseline = computeSas(kSender, kReceiver, kCnonce, kSnonce);

        // 四项输入各自变化都必须改变结果。少用一项（例如漏掉 snonce）时，
        // 中间人只要重复上一轮的取值就能让两端算出同一个码。
        QVERIFY(computeSas(kReceiver, kSender, kCnonce, kSnonce) != baseline); // 顺序
        QVERIFY(computeSas(kSender, kReceiver, kSnonce, kCnonce) != baseline); // 两个 nonce 互换
        QVERIFY(computeSas(kSender, kSender, kCnonce, kSnonce) != baseline);   // 指纹
        QVERIFY(computeSas(kSender, kReceiver, kSnonce, kSnonce) != baseline); // cnonce
        QVERIFY(computeSas(kSender, kReceiver, kCnonce, kCnonce) != baseline); // snonce
    }

    // 中间人的两条连接各有一对 nonce，算出的码必然不同——用户一比就能看出来。
    void differentNoncesDifferentCodes()
    {
        const QByteArray left = computeSas(kSender, kReceiver, kCnonce, kSnonce);
        const QByteArray right = computeSas(kSender, kReceiver, kCnonce,
                                            QStringLiteral("cccccccccccccccccccccccccccccccc"));
        QVERIFY(left != right);
    }

    void codeIsSixDigits()
    {
        const QString code = sasCode(computeSas(kSender, kReceiver, kCnonce, kSnonce));
        QCOMPARE(code.size(), 6);
        for (const QChar c : code)
            QVERIFY(c.isDigit());
    }

    void codeKeepsLeadingZeros()
    {
        // 8 字节大端值的低 6 位十进制。前导零必须保留，否则界面上的 6 位
        // 会缩成 1 位，两端显示的长度都不一样。
        QCOMPARE(sasCode(QByteArray::fromHex("0000000000000007")), QStringLiteral("000007"));
        QCOMPARE(sasCode(QByteArray::fromHex("00000000000f4240")), QStringLiteral("000000")); // 1000000
        QCOMPARE(sasCode(QByteArray::fromHex("00000000000f4241")), QStringLiteral("000001"));
        QCOMPARE(sasCode(QByteArray::fromHex("0000000000000000")), QStringLiteral("000000"));
    }

    void shortInputHasNoCode()
    {
        QCOMPARE(sasCode(QByteArray()), QString());
        QCOMPARE(sasCode(QByteArray(7, '\0')), QString());
    }

    // —————————————— 缓存 ——————————————

    void cacheReturnsWhatWasStored()
    {
        SasCache cache;
        const QDateTime now = QDateTime::currentDateTimeUtc();
        cache.store(QStringLiteral("peer1"), {QStringLiteral("123456"), kSender, now});

        const auto entry = cache.lookup(QStringLiteral("peer1"), now);
        QVERIFY(entry.has_value());
        QCOMPARE(entry->code, QStringLiteral("123456"));
        QCOMPARE(entry->peerFingerprint.bytes(), kSender.bytes());
    }

    void cacheExpiresOldEntries()
    {
        SasCache cache;
        const QDateTime now = QDateTime::currentDateTimeUtc();
        cache.store(QStringLiteral("peer1"), {QStringLiteral("123456"), kSender, now});

        // 未过期
        QVERIFY(cache.lookup(QStringLiteral("peer1"),
                             now + proto::kSasLifetime - std::chrono::seconds(1))
                    .has_value());
        // 刚过期
        QVERIFY(!cache.lookup(QStringLiteral("peer1"),
                              now + proto::kSasLifetime + std::chrono::seconds(1))
                     .has_value());
    }

    void cacheIsPerDevice()
    {
        SasCache cache;
        const QDateTime now = QDateTime::currentDateTimeUtc();
        cache.store(QStringLiteral("peer1"), {QStringLiteral("111111"), kSender, now});
        cache.store(QStringLiteral("peer2"), {QStringLiteral("222222"), kReceiver, now});

        QCOMPARE(cache.lookup(QStringLiteral("peer1"), now)->code, QStringLiteral("111111"));
        QCOMPARE(cache.lookup(QStringLiteral("peer2"), now)->code, QStringLiteral("222222"));
        QVERIFY(!cache.lookup(QStringLiteral("peer3"), now).has_value());
    }

    void cacheRejectsEmptyDeviceId()
    {
        SasCache cache;
        cache.store(QString(), {QStringLiteral("123456"), kSender, QDateTime::currentDateTimeUtc()});
        QCOMPARE(cache.size(), qsizetype{0});
    }
};

QTEST_APPLESS_MAIN(TestSas)

#include "tst_sas.moc"
