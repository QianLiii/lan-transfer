#pragma once

// 接收文件的写入抽象（§1.2 第 1 条）。
//
// 与 FileSource 对称：core 不直接操作路径，而是经由此接口写入。桌面实现基于
// .lanpipe-tmp 下的本地文件（§5.7）；移动端实现可能是 MediaStore 的待发布项或
// SAF 文档，但那部分工作推迟到移动端启动时。
//
// 这个接口在 M0 只声明形状，实现随 M3 的传输引擎落地。

#include <QtGlobal>

#include <memory>

class QIODevice;

namespace lanpipe::files {

class FileSink
{
public:
    virtual ~FileSink() = default;

    // 理由同 FileSource：用户声明的拷贝构造会抑制隐式默认构造。
    FileSink() = default;
    FileSink(const FileSink &) = delete;
    FileSink &operator=(const FileSink &) = delete;

    // 开始写入并返回写入用的设备，所有权归调用方。失败返回 nullptr。
    //
    // 「写到哪个位置」由实现决定，core 只关心语义：在 commit 之前，这些数据
    // 对外不可见，丢弃也不留痕迹。
    [[nodiscard]] virtual std::unique_ptr<QIODevice> open() = 0;

    // 已落盘的字节数。这是接收方进度的权威计数（§5.10），也是「批准体积即上限」
    // 的强制依据（§5.3）——超限时由调用方切断传输并 discard。
    [[nodiscard]] virtual quint64 bytesWritten() const = 0;

    // 把已写完的数据落到最终位置并对外可见（桌面实现即改名到净化后的最终名）。
    // commit 之后再调用 commit 或 discard 都是无操作。
    [[nodiscard]] virtual bool commit() = 0;

    // 丢弃全部已写数据，不留痕迹。用于取消、超限、校验失败（§5.5、§5.7）。
    virtual void discard() = 0;
};

// 尚未定型的部分：接收目录本身的解析（§1.2 第 3 条）需要另一个接口——桌面是自由
// 路径，Android 是应用私有目录或 SAF 树，iOS 是 Documents。它与 FileSink 是两件事：
// 前者回答「写到哪里」，后者回答「怎么写、怎么落定」。M3 落地时再定形状。

} // namespace lanpipe::files
