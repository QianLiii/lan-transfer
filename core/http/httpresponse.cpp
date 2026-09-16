#include "httpresponse.h"

#include <QJsonDocument>

namespace lanpipe::http {

namespace {

QByteArray reasonPhrase(Status status)
{
    switch (status) {
    case Status::Ok: return "OK";
    case Status::BadRequest: return "Bad Request";
    case Status::Forbidden: return "Forbidden";
    case Status::NotFound: return "Not Found";
    case Status::Conflict: return "Conflict";
    case Status::Gone: return "Gone";
    case Status::InternalError: return "Internal Server Error";
    case Status::NotImplemented: return "Not Implemented";
    case Status::GatewayTimeout: return "Gateway Timeout";
    case Status::InsufficientStorage: return "Insufficient Storage";
    }
    return "Unknown";
}

} // namespace

Response Response::text(Status status, const QString &text)
{
    Response response;
    response.status = status;
    response.contentType = "text/plain; charset=utf-8";
    response.body = text.toUtf8();
    return response;
}

Response Response::json(Status status, const QJsonObject &object)
{
    Response response;
    response.status = status;
    response.contentType = "application/json";
    response.body = QJsonDocument(object).toJson(QJsonDocument::Compact);
    return response;
}

QByteArray serializeResponse(const Response &response)
{
    QByteArray out;
    out += "HTTP/1.1 ";
    out += QByteArray::number(static_cast<int>(response.status));
    out += ' ';
    out += reasonPhrase(response.status);
    out += "\r\n";

    if (!response.contentType.isEmpty()) {
        out += "Content-Type: ";
        out += response.contentType;
        out += "\r\n";
    }

    // 长度由 body 现算，调用方无处填错。
    out += "Content-Length: ";
    out += QByteArray::number(response.body.size());
    out += "\r\n";

    // 每条连接只处理一个请求，响应必须明说这一点（§5.15）。
    out += "Connection: close\r\n";
    out += "\r\n";
    out += response.body;
    return out;
}

} // namespace lanpipe::http
