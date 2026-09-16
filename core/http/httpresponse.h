#pragma once

// 响应的构造与序列化（§5.15）。
//
// 一条铁律：响应里的每一个字节都由本文件产生，绝不复制请求里的任何字节。
// 那正是 CRLF 响应拆分那一类缺陷的唯一入口。

#include <QByteArray>
#include <QJsonObject>
#include <QString>

namespace lanpipe::http {

// 只列出协议用到的状态码（§5 的响应表）。
enum class Status {
    Ok = 200,
    BadRequest = 400,
    Forbidden = 403,
    NotFound = 404,
    Conflict = 409,
    Gone = 410,
    InternalError = 500,
    NotImplemented = 501,
    GatewayTimeout = 504,
    InsufficientStorage = 507,
};

struct Response
{
    Status status = Status::Ok;
    QByteArray contentType;
    QByteArray body;

    // 纯文本原因，给人工排查用（接口约定一律用 JSON）。
    [[nodiscard]] static Response text(Status status, const QString &text);
    [[nodiscard]] static Response json(Status status, const QJsonObject &object);
};

[[nodiscard]] QByteArray serializeResponse(const Response &response);

} // namespace lanpipe::http
