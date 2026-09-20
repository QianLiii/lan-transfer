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
| M3 传输引擎 | **未开始** | `prepare` / `upload` / `complete` / `abort`、会话、临时目录、文件名净化、空闲超时 |
| M4 配对与策略 | 部分 | SAS（12 位拆半、两端各自输入）与信任库已完成。**缺**：黑名单、提示限流、自动接受的策略接线、以及把审批框做出来 |
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
| M3 及以后的一切 | 未实现 | —— |

另外两处**已知与设计不符**的地方，动手前先读：

1. **「设备身份已变」这条检查近乎空转。** `deviceId` 本身就是指纹的截断前缀，所以换过密钥的
   设备表现为一个**全新的、未配对的 `deviceId`**，而不是「同一个 `deviceId` 指纹不符」。
   `TrustStore::identityChanged()` 只在记录被篡改或前缀相撞（约 2^-128）时才可能触发；它是
   廉价兜底，不是密钥轮换检测。真实的用户可见行为是「未配对设备」。
2. **接收方的输入在 CLI 里是同步阻塞的。** `serve` 在等用户输入时整个事件循环停住，
   所以 `kSasInputWindow` 的计时器在 CLI 下不会响（实际界限是发送方那 3 分钟超时）。
   对端放弃时由连接的 `finished` 把这次配对作废。图形界面（M5）用异步输入才真正生效。

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
- 同一台机器上跑两个实例做测试，**必须给不同的 `$HOME`**：身份按 `QStandardPaths` 落在
  `$HOME` 下，两个实例同身份时 `deviceId` 相同，会被自己的通告过滤掉。

### macOS

- 系统不自带 OpenSSL，Homebrew 的 `openssl@3` 是 keg-only：`OPENSSL_ROOT_DIR` 给编译期，
  `DYLD_FALLBACK_LIBRARY_PATH` 给运行期（Qt 的后端插件是 dlopen 的）。
- 这一格的 CI 是**可移植性探针**，不是发布目标：它的作用是尽早暴露 Clang 差异与
  「Apple 上没有系统 OpenSSL」这件事。

### CI

- 三格各跑「构建 + ctest」。日志要鉴权才能下载，所以跳过与失败的原因由一步从
  `LastTest.log` 里捞出来打印，并在有跳过时发一条 warning 注解。
- GitHub 的 bash 步骤是 `set -e`：`grep` 无匹配返回 1 会掐断整步，所以那一步每条命令都带
  `|| true`。
- Windows 那一格编译了 `core/discovery/windnssddiscovery.*`——**这个文件在 Linux 上永远
  不参与编译**，相关的错只有 MSVC 能发现。

## 四、动手前须知的四条不变量

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

## 五、下一步

按依赖顺序，第一件事是 **M3 的传输引擎**（`TECHNICAL_ROUTE.md` §5 的全部端点与规则）。
开工前值得先定一件事：**接收方的审批框放在哪一层**。M4 的策略（未知设备提示、已配对是否
自动接受、黑名单、限流）都要挂在它上面，而 `Settings` 里已有 `ReceivePolicy` 枚举，缺省是
`PromptAlways`。
