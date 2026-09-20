#pragma once

// 已配对设备与黑名单（§4）。
//
// 配对表存的是「deviceId → 公钥指纹」，**不是证书**：证书会到期重签，指纹不会变。
// 身份由公钥承载，这张表就是那个事实的落地。
//
// 配对成功的那一刻写入，此后每条连接用它作准（§4 规则 5）：
//   - 表里没有 → 未配对，走配对流程或按策略提示；
//   - 表里有、指纹相符 → 已配对；
//   - 表里有、指纹不符 → 设备身份已变，必须拒绝（§4 规则 5），绝不静默重新配对。
//
// 黑名单与配对表放在同一个文件里（§8 的布局），但语义是两件事：屏蔽一台已配对设备
// 不会把它从配对表里摘掉——屏蔽优先于配对，恢复时配对关系还在。屏蔽优先于一切，
// 包括开放模式。

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>

#include <expected>
#include <optional>

namespace lanpipe::trust {

class TrustStore
{
public:
    struct Entry
    {
        QString deviceId;
        QString fingerprint; // SPKI 指纹的十六进制形式
        QString name;
        QDateTime pairedAt;

        friend bool operator==(const Entry &, const Entry &) = default;
    };

    // 从 path 加载。文件不存在视为空表；文件损坏则报错——静默当成空表等于
    // 把用户所有的配对关系悄悄清掉，那比启动失败糟得多。path 为空时用默认位置。
    [[nodiscard]] static std::expected<TrustStore, QString> load(const QString &path = {});

    // 默认位置：QStandardPaths::AppDataLocation 下的 trust.json，与身份目录同级。
    [[nodiscard]] static QString defaultPath();

    // 从磁盘重新读一遍，替换内存里的两份名单。
    //
    // 存在的理由：黑名单与配对关系可以被**另一个进程**改动（`lanpipe block` 与
    // `serve` 不是一个进程）。接收方在每次 prepare 之前调一次，用户在外面屏蔽一台
    // 设备就能立刻生效。本进程自己的写入本来就在盘上，重读不会丢。
    //
    // 失败时保持原状态并返回 false：一次读失败不该把内存里的配对关系清掉。
    // 两个进程同时写同一个文件会互相覆盖（后写的赢），这是已知限制。
    [[nodiscard]] bool reload(QString *error = nullptr);

    [[nodiscard]] std::optional<Entry> find(const QString &deviceId) const;
    [[nodiscard]] QList<Entry> entries() const;
    [[nodiscard]] bool contains(const QString &deviceId) const { return m_entries.contains(deviceId); }
    [[nodiscard]] qsizetype size() const { return m_entries.size(); }

    // 写入并立即落盘。同 deviceId 已存在则覆盖（名字可能改了）。
    [[nodiscard]] bool add(Entry entry, QString *error);
    [[nodiscard]] bool remove(const QString &deviceId, QString *error);
    // 清空并落盘（「删除全部配对」）。
    [[nodiscard]] bool clear(QString *error);

    // 已配对，但这次看到的指纹与记录不符。调用方必须拒绝这条连接。
    [[nodiscard]] bool identityChanged(const QString &deviceId,
                                       const QString &observedFingerprint) const;

    // —————————————— 黑名单 ——————————————

    struct BlockedEntry
    {
        QString deviceId;
        QString name;
        QDateTime blockedAt;

        friend bool operator==(const BlockedEntry &, const BlockedEntry &) = default;
    };

    [[nodiscard]] bool isBlocked(const QString &deviceId) const;
    // 最近屏蔽的在前。
    [[nodiscard]] QList<BlockedEntry> blocked() const;
    [[nodiscard]] bool block(BlockedEntry entry, QString *error);
    [[nodiscard]] bool unblock(const QString &deviceId, QString *error);

private:
    [[nodiscard]] bool save(QString *error) const;

    QString m_path;
    QHash<QString, Entry> m_entries;
    QHash<QString, BlockedEntry> m_blocked;
};

} // namespace lanpipe::trust
