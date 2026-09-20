#pragma once

// 接收策略（§4 接收策略）。
//
// 纯函数：不看时钟、不弹框、不碰网络，只回答「这个请求该不该被接」。需要问用户
// 的那种情况返回 Prompt，由调用方去问——CLI 同步读一行，QML 异步弹框。
//
// 这一版只用 Settings 里已有的三个取值。黑名单与提示限流是 M4。
//
// 调用顺序由调用方保证：**先查身份变化（identityChanged → 拒），再问策略**。
// 反过来的话，一个换过密钥的已配对设备在开放模式下会被直接放行（§4 规则 5）。

#include "identity.h"
#include "mtls.h"
#include "settings.h"
#include "truststore.h"

namespace lanpipe::trust {

enum class Decision {
    Accept, // 直接接受，不打扰用户
    Prompt, // 问用户
    Reject, // 直接拒绝
};

// peer 必须来自连接层（握手看到的证书），不取请求里的任何字段。
[[nodiscard]] Decision decide(const Settings &settings, const TrustStore &trust,
                              const net::PeerIdentity &peer);

} // namespace lanpipe::trust
