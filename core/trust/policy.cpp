#include "policy.h"

namespace lanpipe::trust {

Decision decide(const Settings &settings, const TrustStore &trust, const net::PeerIdentity &peer)
{
    // 开放模式：接受任何设备，连配对都不要。默认关闭，开启后审批这道唯一的
    // 实时防线就没了（§4）。
    if (settings.openMode())
        return Decision::Accept;

    // 已配对且用户选了自动接受，才静默收下。默认策略是 PromptAlways——
    // 自动接受必须被显式选择过（settings.cpp 里损坏取值一律回落到较严的一侧）。
    if (settings.receivePolicy() == ReceivePolicy::AutoAcceptPaired && trust.contains(peer.deviceId))
        return Decision::Accept;

    return Decision::Prompt;
}

} // namespace lanpipe::trust
