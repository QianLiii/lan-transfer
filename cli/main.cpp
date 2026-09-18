// lanpipe —— headless 命令行工具（§8 cli/）。
//
// M0 只搭骨架：解析子命令与标志、固定 TLS 后端、给出可预测的退出码。
// 三个子命令的实际功能随里程碑落地（serve → M1/M3，send → M3，pair → M4）。
//
// 它的第二个身份是 CI 工具：M1–M4 的验收全部靠它驱动，因此必须有
// 非交互路径（--yes / --pin），否则配对流程需要人工比对 6 位码就无法自动化。

#include "discovery/broadcastdiscovery.h"
#include "discovery/peerconnector.h"
#include "discovery/peerdirectory.h"
#include "http/httpserver.h"
#include "identity.h"
#include "protocol.h"
#include "sas.h"
#include "settings.h"
#include "tlsbackend.h"
#include "transfer/ping.h"
#include "transfer/pingclient.h"
#include "trust/truststore.h"

// 平台后端只在对应平台上编译：这两个头都依赖各自平台才有的东西
// （Avahi 要 QtDBus 的包含路径，Win32 DNS-SD 要 Windows SDK），
// 在别的平台上连包含都不该发生。
#ifdef LANPIPE_HAVE_AVAHI
#  include "discovery/avahidiscovery.h"
#endif

#ifdef LANPIPE_HAVE_WINDNSSD
#  include "discovery/windnssddiscovery.h"
#endif

#include <QCoreApplication>
#include <QDateTime>
#include <QSysInfo>
#include <QElapsedTimer>
#include <QString>
#include <QStringList>
#include <QTextStream>
#include <QUrl>

#include <cstdio>
#include <memory>
#include <optional>

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
        "  lanpipe serve [--port <n>]              作为接收方监听并应答 /ping\n"
        "  lanpipe send <目标> <文件>...            发送文件（M3 起）\n"
        "  lanpipe pair <目标> [--pin <fp>]        与目标配对：两端各显示 6 位、各输入对方的\n"
        "                                          目标可以是 deviceId 的十六进制前缀\n"
        "                                          （先广播发现），或 host:port（手工地址）\n"
        "\n"
        "通用选项：\n"
        "  --yes              非交互：自动接受所有审批（仅用于自动化测试）\n"
        "  --pin <fp>         非交互：要求对端指纹等于 <fp>，不符即拒绝\n"
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

// 加载本机身份。失败时打印原因并返回空值。
std::optional<lanpipe::Identity> loadIdentity()
{
    auto identity = lanpipe::Identity::loadOrCreate(lanpipe::Identity::defaultDir());
    if (!identity.has_value()) {
        writeStderr(identity.error());
        return std::nullopt;
    }
    return *identity;
}

// 发现后端：系统 DNS-SD 优先，取不到就退回 UDP 广播（§3.6）。
// 返回已经 start() 过的后端；广播那条路的失败原因由调用方读 lastError()。
std::unique_ptr<lanpipe::discovery::Discovery> startDiscovery(
    bool announce, const lanpipe::discovery::Advertisement &self)
{
    using namespace lanpipe;

#ifdef LANPIPE_HAVE_WINDNSSD
    // Win32 的 DNS-SD 在 Windows 10 1809+ 上总是存在，失败（例如没有可用网络时
    // DnsServiceBrowse 返回 ERROR_NO_NETWORK）由 start() 后的 lastError 报告，
    // 随后退回 UDP 广播。
    {
        discovery::WinDnsSdDiscovery::Config config;
        config.self = self;
        config.announce = announce;
        auto backend = std::make_unique<discovery::WinDnsSdDiscovery>(config);
        backend->start();
        if (backend->lastError().isEmpty())
            return backend;
        writeStderr(QStringLiteral("系统 DNS-SD 不可用（%1），改用 UDP 广播")
                        .arg(backend->lastError()));
    }
#endif

#ifdef LANPIPE_HAVE_AVAHI
    if (discovery::AvahiDiscovery::isAvailable()) {
        discovery::AvahiDiscovery::Config config;
        config.self = self;
        config.announce = announce;
        auto backend = std::make_unique<discovery::AvahiDiscovery>(config);
        backend->start();
        if (backend->lastError().isEmpty())
            return backend;
        writeStderr(QStringLiteral("Avahi 不可用（%1），改用 UDP 广播")
                        .arg(backend->lastError()));
    }
#endif

    discovery::BroadcastDiscovery::Config config;
    config.self = self;
    config.announce = announce;
    auto backend = std::make_unique<discovery::BroadcastDiscovery>(config);
    backend->start();
    return backend;
}

// 设备名。Settings 为空时回退到主机名并落盘——这个名字会广播到局域网（§3.2），
// GUI 上会让用户确认一次；CLI 用主机名足够，但必须有个名字，否则接收方的用户是在
// 为一条没有名字的连接输入配对码。
void ensureDeviceName(lanpipe::Settings &settings)
{
    if (settings.deviceName().isEmpty())
        settings.setDeviceName(QSysInfo::machineHostName());
}

void printIdentity(const lanpipe::Identity &identity)
{
    writeStdout(QStringLiteral("deviceId %1").arg(identity.deviceId()));
    writeStdout(QStringLiteral("指纹     %1").arg(identity.fingerprint().toHex()));
}

int runServe(const Options &options)
{
    using namespace lanpipe;

    const auto identity = loadIdentity();
    if (!identity.has_value())
        return kExitFailure;

    // 身份、设置、信任库三者的生命周期必须覆盖整个服务期，因此都放在这里。
    Settings settings;
    ensureDeviceName(settings);
    auto trust = trust::TrustStore::load();
    if (!trust.has_value()) {
        writeStderr(trust.error());
        return kExitFailure;
    }

    http::HttpServer server;
    transfer::PingService ping(*identity, settings, *trust, &server);

    QObject::connect(
        &ping, &transfer::PingService::inputRequired,
        [&ping](const QString &peerDeviceId, const QString &peerName, const SasCode &code) {
            writeStdout(QStringLiteral("配对请求：%1（%2）").arg(peerName, peerDeviceId.left(8)));
            writeStdout(QStringLiteral("本机显示的码 %1 —— 请念给对方").arg(code.shown));
            writeStdout(
                QStringLiteral("请输入对方屏幕上显示的 %1 位数字：").arg(proto::kSasCodeDigits));

            // 同步读一行：这一刻整个服务都停在这里，这是单会话模型的直接后果，
            // 也意味着 kSasInputWindow 的计时器在 CLI 下不会响（事件循环没在转）。
            // 对端放弃时会通过连接的 finished 把这次配对作废，所以不会留下
            // 「对方早已走了、我们却记下配对」的记录。GUI 版（M5）用异步输入。
            QTextStream in(stdin);
            ping.submitInput(in.readLine());
        });

    QObject::connect(&ping, &transfer::PingService::pairingFinished,
                     [](const QString &peerDeviceId, transfer::PingService::Outcome outcome) {
                         using Outcome = transfer::PingService::Outcome;
                         const QString peer = peerDeviceId.left(8);
                         switch (outcome) {
                         case Outcome::Accepted:
                             writeStdout(QStringLiteral("已配对 %1，已写入信任库。").arg(peer));
                             break;
                         case Outcome::Mismatch:
                             writeStderr(QStringLiteral(
                                 "配对码不一致：%1 屏幕上显示的与本机算出的不同。\n"
                                 "若不是输错了，这条连接的另一端就不是你以为的那台设备。")
                                             .arg(peer));
                             break;
                         case Outcome::TimedOut:
                             writeStderr(QStringLiteral("等对方输入超时（%1）。")
                                             .arg(peer));
                             break;
                         case Outcome::Rejected:
                             writeStderr(QStringLiteral("配对被拒绝（%1）。").arg(peer));
                             break;
                         }
                     });

    server.setHandler([&ping](http::HttpConnection &connection) {
        if (transfer::PingService::handles(connection.head().target)) {
            ping.handle(connection);
            return;
        }
        connection.respond(http::Response::text(http::Status::NotFound,
                                                QStringLiteral("未知目标")));
    });

    const auto port = server.listen(*identity, static_cast<quint16>(options.port));
    if (!port.has_value()) {
        writeStderr(port.error());
        return kExitFailure;
    }

    // 发现只在服务起来之后启动：通告里必须是实际监听的那个端口（§3.1）。
    discovery::PeerDirectory directory;
    discovery::Advertisement self;
    self.deviceId = identity->deviceId();
    self.name = settings.deviceName();
    self.fingerprint = identity->fingerprint().toHex();
    self.version = proto::kVersion;
    self.port = *port;
    const std::unique_ptr<discovery::Discovery> discover = startDiscovery(true, self);
    if (!discover->lastError().isEmpty())
        writeStderr(QStringLiteral("%1 后端不可用：%2")
                        .arg(discover->backendName(), discover->lastError()));
    directory.addSource(discover.get());
    QObject::connect(&directory, &discovery::PeerDirectory::peerAdded,
                     [](const QString &deviceId) {
                         writeStdout(QStringLiteral("发现 %1").arg(deviceId.left(8)));
                     });
    QObject::connect(&directory, &discovery::PeerDirectory::peerRemoved,
                     [](const QString &deviceId) {
                         writeStdout(QStringLiteral("掉线 %1").arg(deviceId.left(8)));
                     });
    printIdentity(*identity);
    writeStdout(QStringLiteral("正在监听 %1，协议版本 %2").arg(*port).arg(proto::kVersion));
    return QCoreApplication::exec();
}

int runSend(const Options &options)
{
    Q_UNUSED(options);
    writeStderr(QStringLiteral("send：尚未实现（M3 起：传输引擎）"));
    return kExitNotImplemented;
}

// pair 的目标：手工给的 host:port（§3.5），或 deviceId 前缀（先发现再连）。
struct PairTarget
{
    bool byDeviceId = false;
    QString host;
    quint16 port = 0;
    QString deviceIdPrefix;
};

std::optional<PairTarget> parsePairTarget(const QString &text)
{
    PairTarget target;

    const qsizetype colon = text.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && colon < text.size() - 1) {
        bool portOk = false;
        const int port = text.mid(colon + 1).toInt(&portOk);
        if (portOk && port > 0 && port <= 65535) {
            target.host = text.left(colon);
            target.port = static_cast<quint16>(port);
            return target;
        }
        return std::nullopt;
    }

    // deviceId 的十六进制前缀。允许短前缀是为了少打字；32 位是完整长度。
    const QString prefix = text.toLower();
    if (prefix.size() < 4 || prefix.size() > lanpipe::proto::kDeviceIdBytes * 2)
        return std::nullopt;
    for (const QChar c : prefix) {
        if (!((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f')))
            return std::nullopt;
    }

    target.byDeviceId = true;
    target.deviceIdPrefix = prefix;
    return target;
}

int runPair(const Options &options)
{
    using namespace lanpipe;
    using lanpipe::transfer::PingClient;

    if (options.args.isEmpty()) {
        writeStderr(QStringLiteral("错误：pair 需要一个目标：deviceId 前缀或 host:port"));
        return kExitUsage;
    }

    const auto target = parsePairTarget(options.args.first());
    if (!target.has_value()) {
        writeStderr(QStringLiteral("错误：目标应当是 deviceId 的十六进制前缀，"
                                   "或者 host:port，收到 %1")
                        .arg(options.args.first()));
        return kExitUsage;
    }

    std::optional<Fingerprint> expected;
    if (!options.pin.isEmpty()) {
        expected = Fingerprint::fromHex(options.pin);
        if (!expected.has_value()) {
            writeStderr(QStringLiteral("错误：--pin 需要 64 位十六进制指纹，收到 %1")
                            .arg(options.pin));
            return kExitUsage;
        }
    }

    const auto identity = loadIdentity();
    if (!identity.has_value())
        return kExitFailure;

    auto trust = trust::TrustStore::load();
    if (!trust.has_value()) {
        writeStderr(trust.error());
        return kExitFailure;
    }

    Settings settings;
    ensureDeviceName(settings);

    // 逐地址尝试用到的状态。runPair 要一直活到 exec() 返回，所以这些都能是局部量。
    discovery::PeerDirectory directory;
    discovery::Advertisement browseSelf;
    browseSelf.deviceId = identity->deviceId();
    browseSelf.name = settings.deviceName();
    browseSelf.fingerprint = identity->fingerprint().toHex();
    browseSelf.version = proto::kVersion;
    // 只找人不被找：发送方没有在监听，注册出去只会让别人连到一个不存在的端口。
    const std::unique_ptr<discovery::Discovery> discover = startDiscovery(false, browseSelf);
    std::optional<discovery::PeerConnector> connector;
    bool answered = false; // peerAdopted 是否已经发生过：决定失败后是换地址还是停下

    PingClient client(*trust);

    // 换下一个地址再试一次。
    const auto tryNextAddress = [&] {
        if (!connector.has_value())
            return;
        answered = false;
        const auto next = connector->startNext();
        if (!next.has_value()) {
            writeStderr(QStringLiteral("这台设备的每个地址都试过了：\n  %1")
                            .arg(connector->failureSummary()));
            QCoreApplication::exit(kExitFailure);
            return;
        }
        writeStdout(QStringLiteral("尝试 %1:%2").arg(next->address.toString()).arg(next->port));
        client.start(QUrl(QStringLiteral("https://%1:%2")
                              .arg(next->address.toString())
                              .arg(next->port)),
                     *identity, settings.deviceName(), expected);
    };

    const auto connectToPeer = [&](const discovery::PeerDirectory::Peer &peer) {
        if (connector.has_value())
            return; // 已经在连了
        writeStdout(QStringLiteral("发现 %1（%2），%3 个地址")
                        .arg(peer.name, peer.deviceId.left(8))
                        .arg(peer.addresses.size()));
        connector.emplace(peer.addresses, proto::kAddressConnectTimeout);
        QObject::connect(&*connector, &discovery::PeerConnector::attemptTimedOut,
                         [&tryNextAddress] { tryNextAddress(); });
        tryNextAddress();
    };

    QObject::connect(&directory, &discovery::PeerDirectory::peerAdded,
                     [&](const QString &deviceId) {
                         if (target->byDeviceId
                             && deviceId.startsWith(target->deviceIdPrefix)
                             && directory.peer(deviceId).has_value()) {
                             connectToPeer(*directory.peer(deviceId));
                         }
                     });

    // 本端那半在握手完成时就能显示，**早于响应**——接收方那边正等着它的用户
    // 输入这一半，所以它必须先出现在屏幕上。
    QObject::connect(&client, &PingClient::peerAdopted, [&](const SasCode &code) {
        answered = true;
        if (connector.has_value())
            connector->connected(); // 握手过了，这个地址的时限撤掉
        writeStdout(QStringLiteral("本机显示的码 %1 —— 请念给对方").arg(code.shown));
    });

    QObject::connect(&client, &PingClient::finished,
                     [&](const PingClient::Result &result) {
                         if (!result.ok) {
                             // 没跟那台设备说上话 → 这个地址不行，换下一个。
                             // 说上话了却被拒 → 换地址没有意义，那是对方的选择。
                             if (connector.has_value() && !answered) {
                                 connector->failed(result.error);
                                 tryNextAddress();
                                 return;
                             }
                             writeStderr(result.error);
                             QCoreApplication::exit(kExitFailure);
                             return;
                         }

                         writeStdout(QStringLiteral("设备名   %1").arg(result.info.name));
                         writeStdout(QStringLiteral("deviceId %1").arg(result.info.deviceId));
                         writeStdout(QStringLiteral("指纹     %1")
                                         .arg(result.peerFingerprint.toHex()));

                         // 非交互路径：--pin 已经指定了对端指纹，--yes 是测试开关
                         // （见 usageText 的说明）。两者都不需要人工比对。
                         if (!options.pin.isEmpty() || options.assumeYes) {
                             QCoreApplication::exit(kExitOk);
                             return;
                         }

                         // 在槽里同步读一行：此刻这条连接已经结束，没有别的事件要处理。
                         writeStdout(QStringLiteral(
                             "请输入对方屏幕上显示的 %1 位数字（本机不显示它）：")
                                         .arg(proto::kSasCodeDigits));

                         // 窗口用「读完看耗时」来判：Qt 没有跨平台的定时 stdin 读
                         // （QSocketNotifier 对 Windows 控制台句柄不适用），而起线程
                         // 只为计时不值当。晚到的答案一律拒绝。
                         QElapsedTimer timer;
                         timer.start();
                         QTextStream in(stdin);
                         const QString input = in.readLine();
                         const bool late = std::chrono::milliseconds(timer.elapsed())
                             > proto::kSasInputWindow;

                         if (late) {
                             writeStderr(QStringLiteral("等输入超过了 %1 秒，本次配合作废。")
                                             .arg(std::chrono::duration_cast<std::chrono::seconds>(
                                                      proto::kSasInputWindow)
                                                      .count()));
                             QCoreApplication::exit(kExitFailure);
                             return;
                         }

                         if (!result.code.matches(input)) {
                             writeStderr(QStringLiteral(
                                 "配对码不一致。\n"
                                 "  对方屏幕上应当显示的：%1\n"
                                 "若对方屏幕上显示的确实是这几位，那是输错了；\n"
                                 "若不是，这条连接的另一端就不是你以为的那台设备，不要继续。")
                                             .arg(result.code.asked));
                             QCoreApplication::exit(kExitFailure);
                             return;
                         }

                         // 本端比对通过后写入信任库，写的是握手时观察到的指纹。
                         QString error;
                         if (!trust->add({result.info.deviceId, result.peerFingerprint.toHex(),
                                          result.info.name, QDateTime::currentDateTimeUtc()},
                                         &error)) {
                             writeStderr(error);
                             QCoreApplication::exit(kExitFailure);
                             return;
                         }

                         writeStdout(QStringLiteral("配对码一致，已配对 %1，已写入信任库。")
                                         .arg(result.info.deviceId.left(8)));
                         QCoreApplication::exit(kExitOk);
                     });

    printIdentity(*identity);

    if (!target->byDeviceId) {
        writeStdout(QStringLiteral("正在连接 %1:%2").arg(target->host).arg(target->port));
        client.start(QUrl(QStringLiteral("https://%1:%2").arg(target->host).arg(target->port)),
                     *identity, settings.deviceName(), expected);
        return QCoreApplication::exec();
    }

    // 先发现再连接。等待上限由本端决定：对方每 2 秒广播一次，10 秒足够覆盖
    // 几次丢包，又不至于让人干等。
    constexpr auto kLookupTimeout = std::chrono::seconds(10);
    writeStdout(QStringLiteral("正在查找 deviceId 以 %1 开头的设备…").arg(target->deviceIdPrefix));

    directory.addSource(discover.get());
    if (discover->lastError().isEmpty())
        writeStdout(QStringLiteral("发现后端：%1").arg(discover->backendName()));
    else
        writeStderr(QStringLiteral("发现不可用：%1").arg(discover->lastError()));

    // 已经在广播里的对端可能在我们开始听之前就报过到了——不会，但开始听之后
    // 第一条通告要等下一个周期，所以先扫一遍现有列表。
    for (const auto &peer : directory.peers()) {
        if (peer.deviceId.startsWith(target->deviceIdPrefix)) {
            connectToPeer(peer);
            break;
        }
    }

    auto *deadline = new QTimer(&directory);
    deadline->setSingleShot(true);
    QObject::connect(deadline, &QTimer::timeout, [&] {
        if (connector.has_value())
            return; // 已经在连了，超时由每个地址的时限负责
        writeStderr(QStringLiteral(
            "没有发现 deviceId 以 %1 开头的设备。\n"
            "  可能是组播/广播被过滤、两台设备不在同一网段，或者对方没有在跑 serve。\n"
            "  也可以直接给地址：lanpipe pair <host:port>")
                        .arg(target->deviceIdPrefix));
        QCoreApplication::exit(kExitFailure);
    });
    deadline->start(kLookupTimeout);

    return QCoreApplication::exec();
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
