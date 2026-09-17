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

// TXT 字段名。
//   id   —— deviceId 的截断形式，完整值从 /ping 取（§3.2）
//   fp   —— SPKI 指纹，仅作连接提示，永不是信任锚（§3.2、§4）
//   name —— 设备名，任意 UTF-8，单条 TXT 串上限 255 字节须转义截断
//   ver  —— 协议版本，整数
inline constexpr std::string_view kTxtKeyId   = "id";
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
[[nodiscard]] inline std::string pingPath(std::string_view cnonce)
{
    std::string path{kPathPing};
    path += "?cnonce=";
    path += cnonce;
    return path;
}

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

// 发送方的 HTTP 超时，必须显式设置为大于 kApprovalWindow。
// 切勿使用 QNetworkRequest::setTransferTimeout() 的无参形式——它取默认值
// 30000 ms，会与接收方的决策窗口精确竞争（§5.9）。
inline constexpr auto kSenderHttpTimeout = std::chrono::seconds(45);

// 传输停滞判定：上传阶段「零进度」持续这么久即判定连接已死，双向适用（§5.8）。
// 只在上传阶段计时——prepare 等待审批期间没有字节流动，用同一个值会误杀审批中的会话。
inline constexpr auto kStallTimeout = std::chrono::seconds(30);

// —————————————————————— 配对（§4）——————————————————————

// nonce 的字节数（cnonce 与 snonce）。16 字节足够，且让 URL 保持短。
inline constexpr int kNonceBytes = 16;

// SAS 显示成几位数字。
inline constexpr int kSasCodeDigits = 6;

// SAS 缓存的寿命。发送方每次 prepare 前都会重新 ping，所以这个值只需覆盖
// 「ping 到接收方在审批框里显示同一个码」这段时间（§4 规则 3）。
inline constexpr auto kSasLifetime = std::chrono::minutes(5);

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

// —————————————————————— 解析器上限（§5.15）——————————————————————

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
