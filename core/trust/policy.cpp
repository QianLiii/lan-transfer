#include "policy.h"

namespace lanpipe::trust {

Decision decide(const Settings &settings, const TrustStore &trust, const net::PeerIdentity &peer)
{
    // 黑名单优先于一切，包括开放模式：用户明确说过不要这台设备，那个开关不该
    // 把它放回来。
    if (trust.isBlocked(peer.deviceId))
        return Decision::Reject;

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

PromptLimiter::PromptLimiter(int maxPrompts, std::chrono::seconds window)
    : m_maxPrompts(maxPrompts), m_window(window)
{
}

namespace {

// 每隔这么多次调用扫一遍整张表，或表大到一定程度就扫。
//
// 扫是必要的：只清时间戳不删键的话，键会随「见过的设备数」单调增长，而 deviceId 是
// 自签证书现算的——每个连接换一把密钥就是一个新键。扫描本身是 O(设备数)，所以不能
// 每次调用都扫（那会变成 O(n²)），这两个阈值把它的摊还成本压到常数级。
constexpr int kSweepEveryNthCall = 64;
constexpr int kSweepWhenLargerThan = 512;

} // namespace

void PromptLimiter::sweep(const QDateTime &now)
{
    m_callsSinceSweep = 0;
    const qint64 windowMs = std::chrono::milliseconds(m_window).count();

    for (auto it = m_history.begin(); it != m_history.end();) {
        QList<QDateTime> &history = it.value();
        while (!history.isEmpty() && history.first().msecsTo(now) > windowMs)
            history.removeFirst();

        if (history.isEmpty())
            it = m_history.erase(it);
        else
            ++it;
    }
}

bool PromptLimiter::allowPrompt(const QString &deviceId, const QDateTime &now)
{
    if (++m_callsSinceSweep >= kSweepEveryNthCall || m_history.size() > kSweepWhenLargerThan)
        sweep(now);

    auto it = m_history.find(deviceId);
    if (it == m_history.end())
        it = m_history.insert(deviceId, {});
    QList<QDateTime> &history = it.value();

    // 只留窗口内的那几次。
    while (!history.isEmpty() && history.first().msecsTo(now) > m_window.count() * 1000)
        history.removeFirst();

    if (history.size() >= m_maxPrompts)
        return false;

    history.append(now);
    return true;
}

} // namespace lanpipe::trust
