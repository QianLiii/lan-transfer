// SAS（§4 配对）。
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
const Fingerprint kMitm = *Fingerprint::fromHex(
    QStringLiteral("3333333333333333333333333333333333333333333333333333333333333333"));

const QString kCnonce = QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

} // namespace

class TestSas : public QObject
{
    Q_OBJECT

private slots:
    void bothSidesAgreeOnTheSameInput()
    {
        // 两端调用的参数顺序不同、取值相同，结果必须一致。
        const QByteArray senderSide = computeSas(kSender, kReceiver, kCnonce);
        const QByteArray receiverSide = computeSas(kSender, kReceiver, kCnonce);
        QCOMPARE(senderSide, receiverSide);

        // 同一个 SAS，两端的取用方式相反：发送方显示前半、要求后半；
        // 接收方显示后半、要求前半。于是每一端要求输入的都是对方屏幕上的那串。
        const SasCode sender = sasCode(SasRole::Sender, senderSide);
        const SasCode receiver = sasCode(SasRole::Receiver, receiverSide);

        QCOMPARE(sender.shown, receiver.asked);
        QCOMPARE(sender.asked, receiver.shown);
        QVERIFY(sender.matches(receiver.shown));
        QVERIFY(receiver.matches(sender.shown));
    }

    // 中间人两侧的输入不同（这是它无法避免的），12 位必然不同，两端各自都会发现
    // 「对方屏幕上的那半与本端算出的不一致」。
    void eachSideRejectsWhatTheOtherWouldShowUnderMitm()
    {
        // 左侧：发送方看到的是中间人的证书；右侧：接收方看到的也是中间人的证书。
        const SasCode sender = sasCode(SasRole::Sender, computeSas(kSender, kMitm, kCnonce));
        const SasCode receiver = sasCode(SasRole::Receiver, computeSas(kMitm, kReceiver, kCnonce));

        QVERIFY(!sender.matches(receiver.shown));
        QVERIFY(!receiver.matches(sender.shown));
    }

    void everyInputParticipates()
    {
        const QByteArray baseline = computeSas(kSender, kReceiver, kCnonce);

        // 三项输入各自变化都必须改变结果。少用一项时，中间人只要重复上一轮的取值
        // 就能让两端算出同一个码。
        QVERIFY(computeSas(kReceiver, kSender, kCnonce) != baseline); // 两个指纹的顺序
        QVERIFY(computeSas(kSender, kMitm, kCnonce) != baseline);     // 发送方看到的指纹
        QVERIFY(computeSas(kMitm, kReceiver, kCnonce) != baseline);   // 接收方看到的指纹
        QVERIFY(computeSas(kSender, kReceiver,
                           QStringLiteral("cccccccccccccccccccccccccccccccc"))
                != baseline); // cnonce
    }

    // 中间人的两条连接各有一个 cnonce，算出的码必然不同。
    void differentNoncesDifferentCodes()
    {
        const QByteArray left = computeSas(kSender, kReceiver, kCnonce);
        const QByteArray right = computeSas(kSender, kReceiver,
                                            QStringLiteral("cccccccccccccccccccccccccccccccc"));
        QVERIFY(left != right);
    }

    void eachHalfIsSixDigits()
    {
        const SasCode code = sasCode(SasRole::Sender, computeSas(kSender, kReceiver, kCnonce));
        QCOMPARE(code.shown.size(), 6);
        QCOMPARE(code.asked.size(), 6);
        for (const QChar c : code.shown + code.asked)
            QVERIFY(c.isDigit());
    }

    void codeKeepsLeadingZeros()
    {
        // 8 字节大端值的低 12 位十进制。前导零必须保留，否则界面上的 6 位
        // 会缩成 1 位，两端显示的长度都不一样。
        const SasCode zeros = sasCode(SasRole::Sender, QByteArray::fromHex("0000000000000000"));
        QCOMPARE(zeros.shown, QStringLiteral("000000"));
        QCOMPARE(zeros.asked, QStringLiteral("000000"));

        const SasCode small = sasCode(SasRole::Sender, QByteArray::fromHex("0000000000000007"));
        QCOMPARE(small.shown, QStringLiteral("000000"));
        QCOMPARE(small.asked, QStringLiteral("000007"));

        // 10^12 回绕：恰好整除，两半都归零。
        const SasCode wrap = sasCode(SasRole::Sender, QByteArray::fromHex("000000e8d4a51000"));
        QCOMPARE(wrap.shown, QStringLiteral("000000"));
        QCOMPARE(wrap.asked, QStringLiteral("000000"));
    }

    void shortInputHasNoCode()
    {
        QCOMPARE(sasCode(SasRole::Sender, QByteArray()).shown, QString());
        QCOMPARE(sasCode(SasRole::Sender, QByteArray(7, '\0')).asked, QString());
    }

    // 用户输入只忽略空白，别的一律不接受。matches() 是本端唯一的判定入口，
    // 它必须对空输入与半截输入都给出「不匹配」。
    void matchesOnlyAcceptsTheExactSixDigits()
    {
        const SasCode code = sasCode(SasRole::Sender, computeSas(kSender, kReceiver, kCnonce));

        QVERIFY(code.matches(code.asked));
        QVERIFY(code.matches(QStringLiteral(" %1 ").arg(code.asked)));

        QVERIFY(!code.matches(QString()));
        QVERIFY(!code.matches(QStringLiteral("     ")));
        QVERIFY(!code.matches(code.shown));         // 本端显示的那串不是答案
        QVERIFY(!code.matches(code.asked.left(5))); // 少一位
        QVERIFY(!code.matches(code.asked + QLatin1Char('0')));
        QVERIFY(!code.matches(QStringLiteral("abcdef")));
    }
};

QTEST_APPLESS_MAIN(TestSas)

#include "tst_sas.moc"
