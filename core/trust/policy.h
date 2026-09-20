#pragma once

// 接收策略（§4 接收策略）。
//
// `decide()` 是纯函数：不看时钟、不弹框、不碰网络，只回答「这个请求该不该被接」。
// 需要问用户的那种情况返回 Prompt，由调用方去问——CLI 同步读一行，QML 异步弹框。
//
// 调用顺序由调用方保证：**先查身份变化（identityChanged → 拒），再问策略**。
// 反过来的话，一个换过密钥的已配对设备在开放模式下会被直接放行（§4 规则 5）。
//
// 限流本身有状态，所以它不在 `decide()` 里：拿到 Prompt 之后由调用方问
// `PromptLimiter` 一句，问得太频繁就直接拒——那条路正是提示疲劳的入口。

#include "identity.h"
#include "mtls.h"
#include "protocol.h"
#include "settings.h"
#include "truststore.h"

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>

namespace lanpipe::trust {

enum class Decision {
    Accept, // 直接接受，不打扰用户
    Prompt, // 问用户
    Reject, // 直接拒绝
};

// peer 必须来自连接层（握手看到的证书），不取请求里的任何字段。
//
// 顺序是设计的一部分：**黑名单优先于一切，包括开放模式**（用户明确说了不要它）；
// 然后是开放模式；再是「已配对 + 自动接受」；其余一律问用户。
[[nodiscard]] Decision decide(const Settings &settings, const TrustStore &trust,
                              const net::PeerIdentity &peer);

// 按 deviceId 限制审批提示的频率（§4）。没有它，局域网里任何一台设备都能无限弹框，
// 而用户点几次「接受」之后就不再看了——那是这套机制里最短的攻击路径。
class PromptLimiter
{
public:
    PromptLimiter(int maxPrompts = proto::kMaxPromptsPerWindow,
                  std::chrono::seconds window = proto::kPromptWindow);

    // 记一次提示。false 表示这台设备在窗口内问得太频繁，调用方应当直接拒绝。
    [[nodiscard]] bool allowPrompt(const QString &deviceId,
                                   const QDateTime &now = QDateTime::currentDateTimeUtc());

    void clear() { m_history.clear(); }

private:
    int m_maxPrompts;
    std::chrono::seconds m_window;
    QHash<QString, QList<QDateTime>> m_history;
};

} // namespace lanpipe::trust
