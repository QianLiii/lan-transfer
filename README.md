# LanPipe

局域网内的设备到设备文件传输。C++23 / Qt 6.11，自签证书 + 双向 TLS，设备身份由公钥指纹
承载而非证书。

用途是个人自己的几台设备之间传文件，不上架、不分发、只侧载。当前只有命令行（`cli/`），
图形界面在 M5。

- 设计与决策全文：`TECHNICAL_ROUTE.md`（英文，726 行，含每处选型的理由）
- 接手须知（完成度、未验证清单、踩过的坑、改动前须知的四条不变量）：`docs/handover.md`
- 端到端时序图：`docs/sequence-diagram.puml`（`plantuml` 渲染）

## 现在能做什么

**「发现 → 配对 → 双方写入信任库 → 传文件」这一段是通的了**，端到端实测过：

| 能力 | 状态 |
|---|---|
| 设备身份（EC P-256、自签证书、SPKI 指纹、到期自动重签） | 完成 |
| 双向 TLS + 自写的 HTTP/1.1 封闭子集 | 完成，含解析器负向用例 |
| `/ping` 配对：两端各显示 6 位、各输入对方的、各自机器比对 | 完成，见 `TECHNICAL_ROUTE.md` §4 |
| 信任库（持久化、原子写入、指纹变更即拒） | 完成 |
| 发现：UDP 广播、Linux Avahi、Windows Win32 DNS-SD | 完成（Windows 那条的真机往返尚未验证，见下） |
| 多地址回退（一个 `deviceId` 一组地址，逐个短超时尝试） | 完成 |
| 传文件（prepare / upload / complete / abort） | 完成。1 GB 本机端到端逐字节验过；**10 GB 的内存验收没跑**（见下） |
| 接收方的审批、拒绝、双向取消、会话超时、文件名净化 | 完成 |
| 发送方只发给已配对的设备（信任库或 `--pin` 指定指纹） | 完成 |
| 图形界面 | 未开始（M5） |

单文件与多文件都可以；一次一个会话、文件顺序上传、每个文件在自己的 PUT 返回 200 时就位
（不等到 `complete`）。没有断点续传：中途断了重传从零开始。

## 构建

需要 CMake ≥ 3.21、Ninja、Qt 6.11.x（`Core` / `Network` / `Test`，Linux 上还要
`DBus`）、OpenSSL 3。

### Linux

```bash
sudo apt install libssl-dev ninja-build cmake g++
export QTDIR=/path/to/Qt/6.11.1/gcc_64
cmake --preset dev && cmake --build --preset dev
ctest --preset dev
```

用 Avahi 后端还需要 `avahi-daemon` 在运行；只看验收输出另需 `avahi-utils`（提供
`avahi-browse`）。

### Windows

完整链见 `docs/handover.md` 的「Windows 环境」一节——其中包括三处不写下来就会踩的坑
（aqtinstall 要装 git master 版、MSVC 环境不能少、运行时需要 OpenSSL 的两个 DLL）。

### macOS

OpenSSL 需要 Homebrew 的 `openssl@3`，且要显式给出路径（keg-only）：

```bash
brew install openssl@3
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
export DYLD_FALLBACK_LIBRARY_PATH="$OPENSSL_ROOT_DIR/lib"
export QTDIR=/path/to/Qt/6.11.1/macos
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
```

macOS 上目前只有 UDP 广播可用（系统 DNS-SD 后端要等 Network.framework 那一版）。

## 跑一次

接收方：

```bash
lanpipe serve --port 4490
# deviceId bc28f694… / 指纹 bc28f694…eb6d / 正在监听 4490
```

发送方（另一台设备；同一台机器上跑两个实例需要不同的 `$HOME`，否则 `deviceId` 相同，
会被自己的通告过滤掉）：

```bash
lanpipe pair bc28f694          # deviceId 前缀，走发现
lanpipe pair 192.168.31.123:4490   # 或直接给地址
```

两端各显示 6 位数字，把**对方屏幕上的那串**输进自己这一端，两端各自比对。一致即各自写入
信任库。之后发送方就能发文件了：

```bash
lanpipe send bc28f694 /path/to/file      # deviceId 前缀，走发现
lanpipe send 192.168.31.123:4490 <文件>  # 或直接给地址（对方也必须是已配对设备）
```

接收方会列出**是谁、几个文件、多大**并要求确认；传输期间每 10% 打一行进度。
接收方按 Ctrl-C 可以取消当前传输。

非交互路径（CI 与自动化用，见 `--help`）：`--pin <64 位十六进制指纹>` 指定对端指纹、
`--yes` 自动接受一切审批。

## 测试与 CI

19 个 QtTest 套件，`ctest --preset dev` 全跑：

```
tst_protocol  tst_settings  tst_identity  tst_httprequest  tst_sas
tst_httptransport  tst_ping  tst_peerdirectory  tst_peerconnector
tst_truststore  tst_broadcast  tst_avahi  tst_windnssd
tst_sanitizer  tst_localfiles  tst_policy  tst_transfer
tst_receiveservice  tst_sendclient
```

CI（`.github/workflows/ci.yml`）在 Linux / Windows / macOS 三格各跑「构建 + ctest」。
两处需要知道的行为：

- `tst_avahi` 在没有 avahi-daemon 的机器上跳过；`tst_windnssd` 在解析不出 mDNS 的机器上
  跳过并以退出码 77 结束，ctest 显示 `***Skipped`（CI runner 就是这种情况）。跳过原因由
  CI 的一步从 `LastTest.log` 里捞出来打印，并附一条 warning 注解。
- macOS 那一格是刻意的可移植性探针，不是发布目标。

## 代码索引（按这个顺序读）

1. `TECHNICAL_ROUTE.md` §0–§1（是什么、分层约束）、§4（身份与配对）、§5（传输协议全文）。
2. `core/protocol.h` —— 全部协议常量。文件头三条约束改动即等于改协议。
3. `core/identity.{h,cpp}` —— 密钥、自签证书、SPKI 指纹、到期重签。
4. `core/mtls.{h,cpp}`、`core/http/httpserver.{h,cpp}` —— **身份判定只有连接层这一处**。
5. `core/http/httprequest.{h,cpp}` —— 请求头解析器与其上限（负向用例在 `tests/`）。
6. `core/sas.{h,cpp}`、`core/transfer/ping.{h,cpp}`、`pingclient.{h,cpp}` —— 配对往返。
7. `core/transfer/` —— 传输：`transfer.{h,cpp}`（线格式与校验）→ `receivesession` /
   `receiveservice`（接收方四端点与会话）→ `sendclient`（发送方状态机）→
   `peerpinning.{h,cpp}`（**发送方判定「对端是谁」的唯一一处**，与配对共用）。
8. `core/trust/` —— `truststore`（配对关系）、`sanitizer`（文件名净化与改名）、
   `policy`（接收策略的纯函数）。
9. `core/files/` —— `FileSource` / `FileSink` 接口与桌面实现（接收方写临时文件、
   提交时改名进接收目录）。
10. `core/discovery/` —— `discovery.h`（接口）→ `peerdirectory`（合并）→ `peerconnector`
    （多地址回退）→ 三个后端（`broadcast` / `avahi` / `windnssd`）。
11. `cli/main.cpp` —— 目前唯一的界面，也是全部接线处。
12. `tests/` —— 验收标准的可执行形式；负向用例比正向用例多，那是解析器与端点的规格。
