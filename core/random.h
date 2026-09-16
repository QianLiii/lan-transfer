#pragma once

#include <QString>

namespace lanpipe {

// 随机字节的十六进制表示。nonce（§4）、sessionId 与 fileId（§5）都用它。
// 长度以字节计，返回值是它的两倍字符数；bytes <= 0 时返回空串。
//
// 用 QRandomGenerator::system()：Qt 保证它取自操作系统的密码学安全随机源。
// global() 是可复现的 PRNG，在这里等于把 nonce 变成常量。
[[nodiscard]] QString randomHex(int bytes);

} // namespace lanpipe
