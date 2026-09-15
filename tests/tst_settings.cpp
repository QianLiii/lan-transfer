// Settings 的读写与默认值测试。
//
// 每个用例都传入临时 ini 路径（§settings.h 的构造参数就是为此存在的），
// 因此测试永远不会碰到开发者本机的真实配置。

#include <QtTest>

#include <QSettings>
#include <QTemporaryDir>

#include "settings.h"

using lanpipe::ReceivePolicy;
using lanpipe::Settings;

class TestSettings : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    [[nodiscard]] QString iniPath() const { return m_dir.filePath(QStringLiteral("s.ini")); }

    // 绕过 Settings 直接改盘上的值，用于模拟用户手改 ini。
    void writeRaw(const QString &key, const QVariant &value)
    {
        QSettings raw(iniPath(), QSettings::IniFormat);
        raw.setValue(key, value);
    }

private slots:
    void initTestCase() { QVERIFY(m_dir.isValid()); }

    // 全新配置：字符串项为空（表示「尚未设置」），由调用方决定回退值。
    void unsetValuesAreEmpty()
    {
        Settings s(iniPath());
        QVERIFY(s.deviceName().isEmpty());
        QVERIFY(s.receiveDir().isEmpty());
        QVERIFY(!s.openMode());
        QCOMPARE(s.fixedPort(), quint16{0});
    }

    // §4：默认策略是 PromptAlways。自动接受必须被显式选择——
    // 这条断言是安全相关的，改动它需要先改设计文档。
    void defaultPolicyIsPromptAlways()
    {
        Settings s(iniPath());
        QCOMPARE(s.receivePolicy(), ReceivePolicy::PromptAlways);
    }

    void valuesRoundTrip()
    {
        {
            Settings s(iniPath());
            s.setDeviceName(QStringLiteral("书房的台式机")); // 非 ASCII 也要能原样往返
            s.setReceiveDir(QStringLiteral("/tmp/接收"));
            s.setReceivePolicy(ReceivePolicy::AutoAcceptPaired);
            s.setOpenMode(true);
            s.setFixedPort(53001);
        }

        Settings s(iniPath());
        QCOMPARE(s.deviceName(), QStringLiteral("书房的台式机"));
        QCOMPARE(s.receiveDir(), QStringLiteral("/tmp/接收"));
        QCOMPARE(s.receivePolicy(), ReceivePolicy::AutoAcceptPaired);
        QVERIFY(s.openMode());
        QCOMPARE(s.fixedPort(), quint16{53001});
    }

    // 取值损坏必须从严，而不是从严松的那一侧回落。
    //
    // 失败方向不对称：回落成 PromptAlways 只是多弹一次审批，用户会去检查 ini；
    // 回落成 AutoAcceptPaired 则是「用户明确要求的一律审批」被静默取消，
    // 安全控制无声失效。
    void unrecognizedPolicyFallsBackToPromptAlways()
    {
        writeRaw(QStringLiteral("receive/policy"), QStringLiteral("prompt-alway")); // 少一个 s
        Settings s(iniPath());
        QCOMPARE(s.receivePolicy(), ReceivePolicy::PromptAlways);
    }

    void emptyPolicyFallsBackToPromptAlways()
    {
        writeRaw(QStringLiteral("receive/policy"), QString());
        Settings s(iniPath());
        QCOMPARE(s.receivePolicy(), ReceivePolicy::PromptAlways);
    }

    void integerPolicyFallsBackToPromptAlways()
    {
        // 早期设想是用整数落盘。若盘上残留了整数，也必须从严。
        writeRaw(QStringLiteral("receive/policy"), 0);
        Settings s(iniPath());
        QCOMPARE(s.receivePolicy(), ReceivePolicy::PromptAlways);
    }

    // 端口越界一律回落到「由系统分配」，而不是让监听带着一个非法值失败。
    void outOfRangePortFallsBackToEphemeral()
    {
        writeRaw(QStringLiteral("network/fixedPort"), 70000);
        Settings s(iniPath());
        QCOMPARE(s.fixedPort(), quint16{0});
    }

    // openMode 是全应用最宽松的开关（接受任何人且不弹审批），
    // 因此「含义不明的取值」必须一律落到关闭，而不能落到开启。
    //
    // 这条曾经真的失败过：QVariant::toBool() 把任何非空且非 "false"/"0" 的字符串
    // 都当作真，于是在 ini 里手写 "yes" 会静默开启开放模式。
    void openModeRejectsAmbiguousStrings()
    {
        const QStringList ambiguous{
            QStringLiteral("yes"), QStringLiteral("on"), QStringLiteral("enabled"),
            QStringLiteral("真"),  QStringLiteral("y"),
        };
        for (const QString &value : ambiguous) {
            writeRaw(QStringLiteral("receive/openMode"), value);
            Settings s(iniPath());
            QVERIFY2(!s.openMode(), qPrintable(QStringLiteral("取值 \"%1\" 被当成了开启").arg(value)));
        }
    }

    // 反向也要成立：我们自己写下去的形态必须能被读回来。
    // 否则「拒绝含糊取值」会退化成「这个开关根本打不开」。
    void openModeAcceptsExplicitTrue()
    {
        for (const QString &value : {QStringLiteral("true"), QStringLiteral("TRUE"),
                                     QStringLiteral("1")}) {
            writeRaw(QStringLiteral("receive/openMode"), value);
            Settings s(iniPath());
            QVERIFY2(s.openMode(), qPrintable(QStringLiteral("取值 \"%1\" 未被识别为开启").arg(value)));
        }
    }
};

QTEST_GUILESS_MAIN(TestSettings)

#include "tst_settings.moc"
