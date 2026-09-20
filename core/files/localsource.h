#pragma once

// 桌面端的 FileSource：一个本地路径（§1.2 第 1 条）。
//
// 路径只出现在实现里。接口本身不吃路径，所以将来 Android 的 content:// URI
// 实现塞进同一个接口时，传输引擎一行都不用改。

#include "filesource.h"

#include <QString>

#include <memory>
#include <optional>

namespace lanpipe::files {

class LocalFileSource : public FileSource
{
public:
    explicit LocalFileSource(QString path);

    [[nodiscard]] std::unique_ptr<QIODevice> open() override;
    [[nodiscard]] std::optional<quint64> size() const override;
    [[nodiscard]] QString displayName() const override;

private:
    QString m_path;
};

} // namespace lanpipe::files
