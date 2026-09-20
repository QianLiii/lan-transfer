#pragma once

// LanPipe 协议常量（§5）。
//
// 本文件刻意不依赖 Qt：它是纯常量，测试可以直接断言取值，也不需要起事件循环。
//
// 两条贯穿全协议的约束，改动它们等同于改协议：
//
//   1. 每条 TLS 连接只处理一个请求，响应一律带 Connection: close（§5.15）。
//      发送方必须为每个请求新建连接，不能依赖连接复用。
//      这样做的收益是整类消除 keep-alive 上的请求走私与请求体 drain 缺陷。
//
//   2. sessionId 与 fileId 都是十六进制字符串，路径中不含任何需要百分号解码的
//      字符——解析器不做解码，也不接受任何其它形态（§5.15）。
//
//   3. 线格式里只有指纹，没有 deviceId。deviceId 由收到它的那一端从指纹的前
//      kDeviceIdBytes 字节现算（deviceIdFromHex），因此它永远不是「对端声称的值」，
//      也就没有「声称的 deviceId 与证书不符」这类检查要写。

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace lanpipe::proto {

// —————————————————————— 版本 ——————————————————————

// 协议版本。出现在 TXT 的 ver 字段与 /ping 的响应中（§3.2）。
inline constexpr int kVersion = 1;

// 对端版本是否可用。目前要求完全相等；将来若需要兼容次版本，
// 在此处放宽为「主版本相同」即可，调用方无需改动。
[[nodiscard]] constexpr bool isVersionCompatible(int peer) noexcept
{
    return peer == kVersion;
}

// —————————————————————— 服务发现（§3）——————————————————————

// 服务类型。完整实例名是 _lanpipe._tcp.local。
inline constexpr std::string_view kServiceType = "_lanpipe._tcp";

// TXT 字段名，广播载荷用的是同一组（§3.2）。
//   fp   —— SPKI 指纹（64 个十六进制字符）。deviceId 由收到它的那一端现算，
//           它是身份提示里唯一的传输字段；仅作连接提示，永不是信任锚（§3.2、§4）
//   name —— 设备名，任意 UTF-8，单条 TXT 串上限 255 字节须转义截断
//   ver  —— 协议版本，整数
inline constexpr std::string_view kTxtKeyFp   = "fp";
inline constexpr std::string_view kTxtKeyName = "name";
inline constexpr std::string_view kTxtKeyVer  = "ver";

// UDP 广播兜底（§3.4）。端口固定，载荷字段与 TXT 一致并额外带 port。
inline constexpr std::uint16_t kBroadcastPort = 53001;
inline constexpr auto kBroadcastInterval = std::chrono::seconds(2);

// 每次通告在间隔上加的随机抖动。同一网段上的机器若同时启动，不加抖动会
// 形成周期性的一窝蜂。
inline constexpr auto kBroadcastJitter = std::chrono::milliseconds(500);

// 多久没再听到一个对端就认为它掉线（§3.3）。广播每 2 秒一次，
// 这个值容许连丢四次。
inline constexpr auto kPeerExpiry = std::chrono::seconds(10);

// 一个后端把「这个对端还在」重新报一次的间隔。DNS-SD 的浏览结果是稳定列表，
// 不像广播那样每 2 秒自己响一次，所以由后端按这个间隔重发——只有这样，
// PeerDirectory 的超时判定对两种后端才是同一套。
inline constexpr auto kPeerRefreshInterval = std::chrono::seconds(2);

// 端口 0 表示由系统分配临时端口，端口号经 SRV 与广播载荷通告（§3.1）。
inline constexpr std::uint16_t kEphemeralPort = 0;

// deviceId 的字节数：指纹的截断形式，128 位足够区分设备，又不会把 TXT 记录撑大
// （§3.2）。十六进制形式是它的两倍字符数。
inline constexpr int kDeviceIdBytes = 16;

// —————————————————————— 端点路径（§5）——————————————————————

inline constexpr std::string_view kPathPing    = "/api/v1/ping";
inline constexpr std::string_view kPathPrepare = "/api/v1/prepare";
inline constexpr std::string_view kPathUploadPrefix   = "/api/v1/upload/";
inline constexpr std::string_view kPathCompletePrefix = "/api/v1/complete/";
inline constexpr std::string_view kPathAbortPrefix    = "/api/v1/abort/";

// 路径构造。集中在此处以免收发两端各拼一次、拼法漂移。
// 参数必须是十六进制字符串（见文件头约束 2）。
[[nodiscard]] inline std::string uploadPath(std::string_view sessionId, std::string_view fileId)
{
    std::string path{kPathUploadPrefix};
    path += sessionId;
    path += '/';
    path += fileId;
    return path;
}

[[nodiscard]] inline std::string completePath(std::string_view sessionId)
{
    std::string path{kPathCompletePrefix};
    path += sessionId;
    return path;
}

[[nodiscard]] inline std::string abortPath(std::string_view sessionId)
{
    std::string path{kPathAbortPrefix};
    path += sessionId;
    return path;
}

// —————————————————————— 时序常量（§5.8、§5.9）——————————————————————

// 接收方的审批决策窗口。超时后 prepare 返回 504。
inline constexpr auto kApprovalWindow = std::chrono::seconds(30);

// 等用户输入配对码的上限，两端各自适用：发送方在本机等自己的用户，
// 接收方在 /ping 的处理里等自己的用户。
//
// 两端都要有界，因为比对发生在 ping 那一刻，任何一端的人不来，这次配对就不成立。
inline constexpr auto kSasInputWindow = std::chrono::minutes(2);

// 发送方的 HTTP 超时。必须显式设置，且必须大于所等待的那一侧的窗口——
// 现在最长的一环是接收方等它自己的用户输入配对码（kSasInputWindow）。
// 切勿使用 QNetworkRequest::setTransferTimeout() 的无参形式：它取默认值
// 30000 ms，会与接收方的审批窗口精确竞争（§5.9）。
inline constexpr auto kSenderHttpTimeout = std::chrono::minutes(3);

// 发送方在 prepare / complete / abort 上的 HTTP 超时（§5.9）。这三处等的最长
// 一环是接收方的审批窗口（kApprovalWindow），45 秒比它高出一截，又不至于让人
// 在对方已经 504 之后还干等。PUT 用 kStallTimeout：它是按进度重置的空闲超时，
// 大文件不会被总时长误杀。
inline constexpr auto kSenderRequestTimeout = std::chrono::seconds(45);

// 会话空闲多久即作废（§5.6 的 TTL）。发送方在 prepare 之后消失时，接收方没有
// 任何连接可等——只有 TTL 能把这个唯一的活动会话名额放出来。
//
// 必须大于发送方的任一请求超时，否则发送方还在等、会话已经没了；
// 又必须小于 kTempRetention，否则两次清理互相打脸，而活着的进程清理不了自己。
inline constexpr auto kSessionTtl = std::chrono::minutes(5);

// 临时数据的周期清扫间隔（§5.7）。启动时另扫一次。
inline constexpr auto kTempSweepInterval = std::chrono::hours(1);

// 逐个地址尝试时，每个地址的**连接建立**时限（§3.3）。同一台设备在多个网段上都有
// 地址，连错一个要等 30–75 秒的 SYN 重试；换下一个比等它快得多。
inline constexpr auto kAddressConnectTimeout = std::chrono::seconds(3);

// 传输停滞判定：上传阶段「零进度」持续这么久即判定连接已死，双向适用（§5.8）。
// 只在上传阶段计时——prepare 等待审批期间没有字节流动，用同一个值会误杀审批中的会话。
inline constexpr auto kStallTimeout = std::chrono::seconds(30);

// —————————————————————— 配对（§4）——————————————————————

// cnonce 的字节数。16 字节足够，也让请求体保持短。
inline constexpr int kNonceBytes = 16;

// SAS 每一半的位数。两端各显示一半、各要求输入另一半，合计 12 位（§4 配对）——
// 拆成两半是为了让中间人无法只磨出 6 位就能通过。
inline constexpr int kSasCodeDigits = 6;

// —————————————————————— 传输参数与本地布局（§5.1、§5.7）——————————————————

// 发送方每次读入 socket 的分块大小。10 GB 文件的额外内存占用不得超过一块。
inline constexpr std::size_t kChunkSize = 256 * 1024;

// 接收方临时目录名，位于接收目录之下：<receive-dir>/.lanpipe-tmp/<sessionId>/<fileId>
// 文件名不参与路径构造，因此路径穿越在写入那一刻就不可能发生。
inline constexpr std::string_view kTempDirName = ".lanpipe-tmp";

// 临时数据的保留时长。超期条目由启动扫描与周期性清理移除（§5.7）。
inline constexpr auto kTempRetention = std::chrono::hours(24);

// 同时只允许一个活动会话，其余 prepare 收到 409（§5.13）。
inline constexpr std::size_t kMaxActiveSessions = 1;

// sessionId 与 fileId 的字节数，十六进制形式是它的两倍字符数。两者都只由
// randomHex() 产生、只出现在路径里，且路径里不含任何需要解码的字符（约束 2）。
// sessionId 要猜不出来（128 位）；fileId 只需在会话内唯一。
inline constexpr int kSessionIdBytes = 16;
inline constexpr int kFileIdBytes = 8;

// prepare 请求体的上限。文件列表在它里面，所以远比 ping 的体大；设上限的意义
// 是不把内存上限交给对端（§5.15 的同一思路）。
inline constexpr std::size_t kMaxPrepareBodySize = 256 * 1024;

// 一次会话的文件数上限，与体上限一起封住 prepare 的资源占用。
inline constexpr std::size_t kMaxFilesPerSession = 1024;

// 设备名与文件名在**净化之前**的字节上限。净化会缩短名字，但缩短之前得先有个界。
inline constexpr std::size_t kMaxDisplayNameBytes = 255;

// 空闲空间检查的余量。留给元数据与文件系统自身的开销，免得「刚好够」的传输
// 在最后一个字节上失败。
inline constexpr std::uint64_t kFreeSpaceSlack = 1024 * 1024;

// 最终名冲突时的最大重试次数（photo.jpg → photo (1).jpg → photo (2).jpg …）。
inline constexpr int kMaxFinalNameAttempts = 100;

// —————————————————————— 解析器上限（§5.15）——————————————————————

// /ping 请求体的上限。实际载荷约 400 字节（cnonce + 设备名），留足余量。
inline constexpr std::size_t kMaxPingBodySize = 4 * 1024;

// 解析器是封闭子集：只接受 Content-Length 分帧，任何 Transfer-Encoding、
// 重复 Content-Length、超限的 header 块一律 400 并断连，请求体一个字节都不读。
//
// 这些上限与连接上限共同构成拒绝服务的第一道防线。
inline constexpr std::size_t kMaxHeaderFieldCount = 32;
inline constexpr std::size_t kMaxHeaderLineLength = 4096;
inline constexpr std::size_t kMaxHeaderBlockSize  = 16 * 1024;

// 监听 socket 允许的最大并发连接数（§5.13）。
// 常量远比线程池模型容易做到这一步：阻塞式服务的线程数就是并发上限。
inline constexpr std::size_t kMaxConnections = 8;

// TLS 握手的最长时间。连上却不发 ClientHello 的客户端否则能白占一个连接位。
// Qt 的默认值同样是 5 秒；写在这里是为了让这个上限出现在协议的常量表里，
// 而不是散落在某个 Qt 默认值中。
inline constexpr int kHandshakeTimeoutMs = 5000;

} // namespace lanpipe::proto
