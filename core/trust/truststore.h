#pragma once

// 已配对设备（§4）。
//
// 这里存的是「deviceId → 公钥指纹」，**不是证书**：证书会到期重签，指纹不会变。
// 身份由公钥承载，这张表就是那个事实的落地。
//
// 配对成功的那一刻写入，此后每条连接用它作准（§4 规则 5）：
//   - 表里没有 → 未配对，走配对流程或按策略提示；
//   - 表里有、指纹相符 → 已配对；
//   - 表里有、指纹不符 → 设备身份已变，必须拒绝（§4 规则 5），绝不静默重新配对。

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

private:
    [[nodiscard]] bool save(QString *error) const;

    QString m_path;
    QHash<QString, Entry> m_entries;
};

} // namespace lanpipe::trust
