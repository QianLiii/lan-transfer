#pragma once

// 待发送文件的读取抽象（§1.2 第 1 条）。
//
// 为什么 core 不允许直接吃 QString 路径：
//
//   桌面端「一个本地路径就能读」成立，移动端不成立。Android 的文件选择器返回
//   content:// URI，其大小可能为 null（远程或虚拟文档）；iOS 需要对
//   security-scoped URL 显式开启访问。这些都能塞进同一个接口，但接口必须先存在——
//   否则 M3 的传输引擎会写成吃路径的形式，到移动端要重写引擎本身而不是加一个实现。
//
// 这个接口在 M0 只声明形状，实现随 M3 的传输引擎落地。

#include <QString>
#include <QtGlobal>

#include <memory>
#include <optional>

class QIODevice;

namespace lanpipe::files {

class FileSource
{
public:
    virtual ~FileSource() = default;

    // 必须显式写出来：下面的拷贝构造是用户声明的（哪怕 = delete），
    // 隐式的默认构造因此不再生成，派生类会构造不出来。
    FileSource() = default;
    FileSource(const FileSource &) = delete;
    FileSource &operator=(const FileSource &) = delete;

    // 打开一个供流式读取的设备。所有权归调用方，读到末尾不需要额外的收尾调用。
    // 失败返回 nullptr。
    //
    // 调用方按固定大小分块读取（proto::kChunkSize），不得整文件读入内存（§5.1）。
    [[nodiscard]] virtual std::unique_ptr<QIODevice> open() = 0;

    // 文件字节数。返回 nullopt 表示无法确定——这在 Android 的部分 provider 上是
    // 常态而非异常，不是错误。
    //
    // 返回空值时必须由调用方决定策略（§5.14）：拒绝并给出可读错误，或者在审批界面
    // 标为「大小未知」并把进度显示改为不确定态。无论哪种，prepare 的 size 字段与
    // 审批界面显示的总体积都必须与这里的取值一致——用户批准的数字就是传输的硬上限。
    [[nodiscard]] virtual std::optional<quint64> size() const = 0;

    // 展示给用户并通过 prepare 传给接收方的文件名，不含路径。
    // 接收方会先净化再构造路径（§5.11），因此这里不需要预先净化，但也不应伪造。
    [[nodiscard]] virtual QString displayName() const = 0;
};

} // namespace lanpipe::files
