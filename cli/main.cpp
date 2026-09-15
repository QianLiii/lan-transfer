// lanpipe —— headless 命令行工具（§8 cli/）。
//
// M0 只搭骨架：解析子命令与标志、固定 TLS 后端、给出可预测的退出码。
// 三个子命令的实际功能随里程碑落地（serve → M1/M3，send → M3，pair → M4）。
//
// 它的第二个身份是 CI 工具：M1–M4 的验收全部靠它驱动，因此必须有
// 非交互路径（--yes / --pin），否则配对流程需要人工比对 6 位码就无法自动化。

#include "protocol.h"
#include "tlsbackend.h"

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QTextStream>

#ifdef Q_OS_WIN
#  include <windows.h>
#endif

namespace {

// 退出码是对外契约：CI 依据它区分「环境不对」与「功能没写」。
// 不用 sysexits 的取值，避免与 shell 惯例冲突。
enum ExitCode {
    kExitOk = 0,             // 成功
    kExitFailure = 1,        // 运行期失败
    kExitUsage = 2,          // 参数错误
    kExitTlsBackend = 3,     // TLS 后端不可用（环境问题，不是代码问题）
    kExitNotImplemented = 10 // 该里程碑尚未实现
};

struct Options
{
    QString command;
    QStringList args;
    bool assumeYes = false; // --yes：所有审批一律接受（仅测试用，绝不可用于日常）
    bool showVersion = false;
    QString pin;  // --pin <fp>：预置信任指纹，跳过人工比对 SAS
    int port = 0; // --port <n>：0 表示临时端口（默认，§3.1）
};

// 参数解析的三种结局。把「已处理」与「出错」分开，是因为 --help 应当以 0 退出，
// 而参数错误应当以 kExitUsage 退出，两者的退出码不同。
enum class ParseResult {
    Ok,      // 继续执行
    Handled, // 已打印输出并正常结束（--help）
    Error    // 参数错误，已打印原因
};

void writeStdout(const QString &text)
{
    QTextStream out(stdout);
    out << text << Qt::endl;
}

void writeStderr(const QString &text)
{
    QTextStream err(stderr);
    err << text << Qt::endl;
}

QString usageText()
{
    return QStringLiteral(
        "lanpipe —— 局域网文件传输\n"
        "\n"
        "用法：\n"
        "  lanpipe serve [--port <n>]              作为接收方监听（M1 起）\n"
        "  lanpipe send <目标> <文件>...            发送文件（M3 起）\n"
        "  lanpipe pair <目标>                      配对并写入信任库（M4 起）\n"
        "\n"
        "通用选项：\n"
        "  --yes              非交互：自动接受所有审批（仅用于自动化测试）\n"
        "  --pin <fp>         非交互：预置对端指纹，跳过 SAS 人工比对\n"
        "  --version          打印版本与环境信息\n"
        "  -h, --help         显示本帮助\n");
}

ParseResult parseOptions(const QStringList &argv, Options *out)
{
    for (int i = 0; i < argv.size(); ++i) {
        const QString &arg = argv.at(i);

        if (arg == QLatin1String("--help") || arg == QLatin1String("-h")) {
            writeStdout(usageText());
            return ParseResult::Handled;
        }
        if (arg == QLatin1String("--version")) {
            out->showVersion = true;
            continue;
        }
        if (arg == QLatin1String("--yes")) {
            out->assumeYes = true;
            continue;
        }
        if (arg == QLatin1String("--pin") || arg == QLatin1String("--port")) {
            if (i + 1 >= argv.size()) {
                writeStderr(QStringLiteral("错误：%1 需要一个参数").arg(arg));
                return ParseResult::Error;
            }
            const QString value = argv.at(++i);
            if (arg == QLatin1String("--pin")) {
                out->pin = value;
            } else {
                // M2 的验收要在同一台机器上跑两个实例，端口必须可覆盖，
                // 否则两个监听会撞在一起。
                bool ok = false;
                const int port = value.toInt(&ok);
                if (!ok || port < 0 || port > 65535) {
                    writeStderr(QStringLiteral("错误：--port 取值非法：%1").arg(value));
                    return ParseResult::Error;
                }
                out->port = port;
            }
            continue;
        }
        if (arg.startsWith(QLatin1String("--"))) {
            // 未知标志一律报错而不是忽略：静默忽略会让 CI 里的拼写错误
            // 表现为「测试通过了但没测到东西」。
            writeStderr(QStringLiteral("错误：无法识别的选项 %1").arg(arg));
            return ParseResult::Error;
        }

        if (out->command.isEmpty())
            out->command = arg;
        else
            out->args.append(arg);
    }
    return ParseResult::Ok;
}

void printVersion()
{
    writeStdout(QStringLiteral("lanpipe 协议版本 %1").arg(lanpipe::proto::kVersion));
    writeStdout(QStringLiteral("Qt %1").arg(QLatin1String(QT_VERSION_STR)));
    // 后端名只在 forceOpenSslBackend() 成功之后才有意义（见 tlsbackend.h）。
    writeStdout(QStringLiteral("TLS 后端 %1").arg(lanpipe::activeBackendName()));
}

int runServe(const Options &options)
{
    Q_UNUSED(options);
    writeStderr(QStringLiteral("serve：尚未实现（M1 起：身份 + TLS + 接收服务端）"));
    return kExitNotImplemented;
}

int runSend(const Options &options)
{
    Q_UNUSED(options);
    writeStderr(QStringLiteral("send：尚未实现（M3 起：传输引擎）"));
    return kExitNotImplemented;
}

int runPair(const Options &options)
{
    Q_UNUSED(options);
    writeStderr(QStringLiteral("pair：尚未实现（M4 起：SAS 配对与信任库）"));
    return kExitNotImplemented;
}

} // namespace

int main(int argc, char *argv[])
{
    // Windows 控制台默认不是 UTF-8 代码页，中文错误信息会显示为乱码——
    // 在 CI 日志里尤其难以辨认。必须在任何输出之前设置。
#ifdef Q_OS_WIN
    SetConsoleOutputCP(CP_UTF8);
#endif

    // 先建 QCoreApplication 再固定 TLS 后端：插件查找依赖它的库路径。
    // 顺序仍然满足「早于任何 SSL 对象」——构造 QCoreApplication 不会创建 SSL 对象。
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("lanpipe"));

    // 后端不可用就直接退出。带着一个会漂移的证书校验行为继续运行，
    // 会让问题在握手阶段才暴露，且症状与配置错误难以区分。
    if (const QString error = lanpipe::forceOpenSslBackend(); !error.isEmpty()) {
        writeStderr(error);
        return kExitTlsBackend;
    }

    Options options;
    switch (parseOptions(app.arguments().mid(1), &options)) {
    case ParseResult::Handled:
        return kExitOk; // 用法已经打印过
    case ParseResult::Error:
        return kExitUsage;
    case ParseResult::Ok:
        break;
    }

    if (options.showVersion) {
        printVersion();
        return kExitOk;
    }

    if (options.command.isEmpty()) {
        writeStderr(usageText());
        return kExitUsage;
    }

    if (options.command == QLatin1String("serve"))
        return runServe(options);
    if (options.command == QLatin1String("send"))
        return runSend(options);
    if (options.command == QLatin1String("pair"))
        return runPair(options);

    writeStderr(QStringLiteral("错误：未知子命令 %1").arg(options.command));
    writeStderr(usageText());
    return kExitUsage;
}
