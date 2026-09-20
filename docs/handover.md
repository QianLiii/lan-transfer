# 接手须知

给下一位开发者。`README.md` 讲怎么构建和跑，这份讲**现在的真实状态、什么没被验证过、以及
动手前必须知道的几条约束**。

设计与决策的理由在 `TECHNICAL_ROUTE.md`，本文不重复。

## 一、完成度

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 骨架 | 完成 | CMake + 三平台 CI + CLI 骨架 |
| M1 身份 + TLS + 接收服务端 | 完成 | 身份、解析器、mTLS、`/ping`、解析器负向用例。**用 curl 独立验证过**（另一套 TLS/HTTP 栈） |
| M2 发现 | 基本完成 | 接口、对端目录、多地址回退、UDP 广播、Linux Avahi、Windows Win32 DNS-SD 都已落地。**缺**：macOS 的 Network.framework 后端、mjansson 兜底、以及两台真机的验收 |
| M3 传输引擎 | 完成 | `prepare` / `upload` / `complete` / `abort`、会话与 TTL、临时目录、文件名净化、双向取消、空闲超时。**1 GB 端到端逐字节验过**（见下） |
| M4 配对与策略 | 完成（CLI 面） | SAS、信任库、自动接受、黑名单、提示限流都已落地。CLI 上有 `devices` / `block` / `unblock`，审批提示接受 `y`/`n`/`b`。**审批框本身是 M5**——CLI 现在是同步读一行 |
| M5 图形界面 | 未开始 | |
| M6 桌面 1.0 | 未开始 | |

M1 与 M4 的边界是刻意挪过的：原计划把 SAS 放在 M4，实际随 M1 的 `/ping` 一起落了地。
`TECHNICAL_ROUTE.md` §9 的验收表里因此有一条位置不对（见下）。

## 二、未验证清单

**「测试通过」不等于「功能可用」。** 以下是已知未经证明的部分：

| 未验证项 | 为什么没验 | 怎么验 |
|---|---|---|
| Windows 的系统 DNS-SD 往返 | CI runner 的 mDNS 解析不出任何东西（浏览回调一次都不触发），`tst_windnssd` 在那里以退出码 77 跳过 | 在一台有正常网络的 Windows 桌面上跑 `ctest -R tst_windnssd`。**这是这一项唯一的验收场** |
| 两台真机的发现 | 一直只在单机（两个身份）上跑过 | 按 `TECHNICAL_ROUTE.md` §9 的 M2 验收：两台机器互相发现、`avahi-browse` 能看到服务、关掉 mDNS 后广播仍有效、错误首选地址在连接超时内回退 |
| macOS 上除广播以外的发现 | 后端还没写 | 写 Network.framework 后端 |
| 10 GB 传输的内存持平 | M3 只跑了 1 GB。本机 `/` 只剩 9 GB 可用（`/tmp` 与 `$HOME` 同一文件系统），10 GB 那项峰值要三份 10 GB，物理上跑不了 | 在一台有 30 GB 空闲磁盘的机器上跑 `lanpipe send`，同时按秒采 `/proc/<pid>/status` 的 `VmRSS`：1 GB 那次是 25.0 → 25.8 MB 持平，10 GB 应当同样平 |
| 接收方在传输中途崩溃后的残留 | 没构造过「接收方进程 crash」这一路 | 杀接收方进程后看 `<接收目录>/.lanpipe-tmp`：分片是 QSaveFile 的临时文件，崩溃时会留下，由 24 小时清扫收走（§5.7）。要验清扫就改系统时间或直接调 `sweepStaleTempData(now)` |
| 黑名单与限流在两台真机上 | 只在单机（两个 `$HOME`）验过 | 一台屏蔽另一台，确认对方拿到 403 且**不弹框**；连续发起 4 次 prepare，第 4 次应当被限流拒掉 |
| 两个进程同时写信任库 | 没有并发保护，后写的覆盖先写的 | 真要验就同时跑 `lanpipe block` 与一次配对，然后看 `trust.json` 里丢了哪一边。个人使用下这是可接受的 |

另外几处**已知与设计不符**的地方，动手前先读：

1. **「设备身份已变」这条检查触发不了正常路径。** 线格式里没有 `deviceId`，它一律由指纹
   现算，所以写入信任库的两项（键与指纹）必然出自同一次握手；收到通告的那一侧同理。
   换过密钥的设备表现为一个**全新的、未配对的 `deviceId`**，不是「同一个 `deviceId`
   指纹不符」。`TrustStore::identityChanged()` 现在只剩两条路可走：记录被外部改过
   （`load()` 不校验 `deviceId` 是不是 `fingerprint` 的前 32 个字符），或前缀相撞
   （随机一把新密钥撞上的概率 2^-128，找到一个的成本 2^128）。它是廉价兜底，不是密钥
   轮换检测。
2. **接收方的输入在 CLI 里是同步阻塞的。** 配对（`kSasInputWindow`）与传输审批
   （`kApprovalWindow`）都是这样：`serve` 在等用户输入时整个事件循环停住，那两个计时器
   在 CLI 下不会响。配对的实际界限是发送方那 3 分钟超时；审批则没有上界——发送方 45 秒
   就会放弃，接收方这边却还停在提示行上，直到用户敲回车（那时写回的是一个已经没有对端
   的会话，随即被 `finished` 收掉）。图形界面（M5）用异步输入才真正生效。

3. **传输没有断点续传**：中途断掉的分片随 QSaveFile 析构被丢弃，重传从零开始。
   这是 §5.6「截断而非追加」的落地方式，不是缺陷——续传是 v2。

## 三、环境（踩过的坑）

### Windows

```powershell
# 1. MSVC 与 Windows SDK（后者提供 windns.h，Win32 DNS-SD 在里面）
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Python.Python.3.12 -e

# 2. aqtinstall 要装 git master 版：PyPI 上最新是 2025-06-02 的 3.3.0，它不认识
#    Qt 6.11 改过的 Windows 仓库布局，会拼出一个 404 的路径。
pip install "aqtinstall @ git+https://github.com/miurahr/aqtinstall@master"
aqt install-qt windows desktop 6.11.2 win64_msvc2022_64 -O C:\Qt

winget install --id ShiningLight.OpenSSL.Light -e   # 装到 C:\Program Files\OpenSSL-Win64
winget install --id Kitware.CMake -e
winget install --id Ninja-build.Ninja -e
```

```powershell
# 3. 必须在「x64 Native Tools Command Prompt for VS 2022」里构建：
#    Ninja 从 PATH 找编译器，系统上若有 MinGW 或 Strawberry Perl 带的 g++，
#    CMake 会挑到它，而 Qt 是 MSVC ABI 的，链接必失败。
cmake -S . -B build/local -G Ninja -DCMAKE_BUILD_TYPE=Debug `
      -DCMAKE_PREFIX_PATH=C:\Qt\6.11.2\msvc2022_64 `
      -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
cmake --build build/local
ctest --test-dir build/local --output-on-failure
```

两个只在运行期出现的坑：

- **Qt 的 openssl 后端是运行时 dlopen** `libssl-3-x64.dll` / `libcrypto-3-x64.dll`。
  不把 OpenSSL 的 `bin` 加进 PATH（或把两个 DLL 拷到 exe 旁边），程序会以**退出码 3**
  拒绝启动，提示「TLS 后端已选定为 openssl，但它无法工作」。
- `python` 若解析到 `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe`，那是微软商店的
  转发桩而不是真 Python。装完真 Python 后要去「设置 → 应用 → 高级应用设置 → 应用执行
  别名」把 `python.exe` / `python3.exe` 关掉，并**开新终端**（PATH 改动不对已有终端生效）。

### Linux

- Avahi 后端要 `avahi-daemon` 在跑；它是走 **D-Bus**（QtDBus）调用的，不链
  `libavahi-client`——少一个构建与打包依赖，失败模式相同。CMake 找不到 QtDBus 时会跳过
  这个后端。
- 验收里「`avahi-browse` 能看到服务」需要 `avahi-utils`。
- 同一台机器上跑两个实例做测试，**必须给不同的 `$HOME`**。两个理由，都踩过：身份按
  `QStandardPaths` 落在 `$HOME` 下，同身份的两个实例指纹相同，会被自己的通告过滤掉；
  而且 Avahi 的实例名由 deviceId 前缀拼出，同身份的两个实例会抢同一个名字，后注册的
  那个直接失败（`Local name collision`）。
- 手工起过的 `serve` 进程要记得杀：残留实例会占着 Avahi 注册，让 `tst_avahi` 莫名其妙
  地失败。`pgrep -x lanpipe` 看一眼（`pkill -f lanpipe` 会连自己的 shell 一起匹配掉）。

### macOS

- 系统不自带 OpenSSL，Homebrew 的 `openssl@3` 是 keg-only：`OPENSSL_ROOT_DIR` 给编译期，
  `DYLD_FALLBACK_LIBRARY_PATH` 给运行期（Qt 的后端插件是 dlopen 的）。
- 这一格的 CI 是**可移植性探针**，不是发布目标：它的作用是尽早暴露 Clang 差异与
  「Apple 上没有系统 OpenSSL」这件事。

### 测试里的平台差异

CI 三格都跑，所以只在本机（Linux）绿是不够的。下面是 2026-09 这轮真的挂过的三类，
根子都是**把 Linux 的行为当成了契约**：

- **`QSaveFile` 的临时文件在 Linux 上看不见。** Qt 文档写明它建在**目标同目录**，
  而只有 Linux 会尝试匿名临时文件（`O_TMPFILE`）——那条路上 `open()` 返回 true 而
  `exists()` 是 false，`readdir` 也什么都看不到。于是「临时目录里恰好只有 X」这种
  断言在 Windows/macOS 上必挂。另外 `cancelWriting()` 只是让 `commit()` 丢弃，
  **真正的删除发生在 `QSaveFile` 析构时**。
- **路径长度上限不同**：Windows 是 259 个 UTF-16 单元，POSIX 是 4095 字节。写死一个
  长度去测边界，在另一半平台必挂（`tst_sanitizer` 就是这么挂的）。
- **短窗口的时序**：共享的 macOS runner 比本机慢得多。会话 TTL 设成 50–80 毫秒、
  然后在 TTL 之前断言「目录还在、PUT 已开始」，会在这类机器上翻车。推进测试要用
  「等到某个信号真的发生」，而不是睡一个固定时长。

一条规则够了：**断言我们自己的不变量，不要断言 Qt 或文件系统的实现细节。**

### CI

- 三格各跑「构建 + ctest」。日志要鉴权才能下载，所以跳过与失败的原因由一步从
  `LastTest.log` 里捞出来打印，并在有跳过时发一条 warning 注解。
- GitHub 的 bash 步骤是 `set -e`：`grep` 无匹配返回 1 会掐断整步，所以那一步每条命令都带
  `|| true`。
- Windows 那一格编译了 `core/discovery/windnssddiscovery.*`——**这个文件在 Linux 上永远
  不参与编译**，相关的错只有 MSVC 能发现。

## 四、动手前须知的六条不变量

改动触及这些地方时，先确认没有把它们弄反。每一条的理由都在对应文件头或
`TECHNICAL_ROUTE.md` 里。

1. **身份判定只有连接层一处。** 握手完成后解析一次对端证书，处理器只读结果，不再自己碰
   证书。把检查抄进每个处理器，迟早有一个会漏——而漏掉时不会报错。
2. **每条连接只处理一个请求**，响应一律带 `Connection: close`。发送方必须为每个请求新建
   连接。这一条整类消除了 keep-alive 上的请求走私与请求体残留缺陷。
3. **SAS 是 12 位、拆成两半、两端各输入对方那一半**；参与量只有两个指纹与发送方出的
   `cnonce`。**不要给接收方加回一个 nonce**：那样发送方在收到响应之前算不出任何一半，
   而接收方要输入的是发送方显示的那半，三方互等，成死锁。
4. **交给 Win32 DNS-SD API 的句柄与上下文一律进程级存活**（故意不释放）：那个 API 没有
   「回调已停止」的回执，对象一析构它的内部线程就可能踩到已释放的内存。它的三个回调来自
   系统线程池，不是 Qt 线程——非原子的状态一律经队列投递到 Qt 线程，只有原子量可以就地改。

5. **线格式里只有指纹，没有 deviceId。** 收到它的一端从指纹现算（`deviceIdFromHex`），
   写入信任库时用的也是握手时亲眼看到的那个指纹（`cli/main.cpp` 的配对收尾）。改动通告
   载荷、`/ping` 响应或 `prepare` 请求体时不要把 id 加回去：那会把「声称的 deviceId 与
   证书是否相符」重新变成一道每个处理器都要记得做的检查。

6. **存下来的 `HttpConnection*` 必须在它自己的 `finished` 槽里置空。** 连接在 `finished`
   之后会被 `deleteLater()`，留着指针就是悬垂。这一条是踩出来的：`m_upload` 曾经漏了，
   而对端只要在一次上传中途断连，接收方就会在五分钟之后（TTL 到点拆除时）自己崩掉——
   不需要用户做任何事。**每一条能结束这件事的路径都要走同一个函数**
   （`ReceiveService::releaseUpload()`）。

## 五、下一步

M3 与 M4 都已落地，接下来是 **M5：QML 前端**（Send / Receive / Devices / Pairing /
Settings），核心一行不用改——界面要的信号都在：`ReceiveService::approvalRequired` /
`submitApproval` / `submitBlock`、`fileProgress`、`fileCommitted`、`sessionFinished`、
`peerBlocked`，`PingService::inputRequired` / `submitInput`，以及 `PeerDirectory`。

两处 M5 必须处理的东西，先记下来：

1. **CLI 的同步输入换成异步之后，两个计时器才真正生效**：`kSasInputWindow` 与
   `kApprovalWindow` 现在因为事件循环被阻塞而形同虚设（见「已知与设计不符」第 2 条）。
2. **审美疲劳那条防线要靠 UI 兜住**：限流只挡得住同一条设备的密集请求，真正的
   「未知设备」仍会一次次弹框——界面上要让「拒绝并屏蔽」比「接受」更难误点。

**发送方的 `--yes` / `--pin` 不写信任库**（`cli/main.cpp` 的 `pair` 收尾）——这是 M1 就
留下的行为：那两条是给 CI 用的非交互路径。因此 `send` 的两条合法凭据是「信任库里有记录」
或「`--pin` 指定了指纹」，后者比前者更强，`PeerPin::setRequirePaired()` 认这两种。
