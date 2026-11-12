# goproxy

一个用 Go 实现的 HTTP / HTTPS / SOCKS5 代理服务器。三种协议共用同一个监听端口，根据客户端发来的第一个字节自动识别协议。

## 功能

- HTTP 代理：转发普通 HTTP 请求，并通过 `CONNECT` 建立 HTTPS 隧道
- HTTPS 代理：客户端使用 TLS 连接代理本身，代理仍按 HTTP 代理协议工作
- SOCKS5：支持 `CONNECT` 命令、IPv4、IPv6 和域名目标
- 统一的用户名密码认证
  - HTTP/HTTPS：`Proxy-Authorization: Basic ...`
  - SOCKS5：RFC 1929 用户名密码认证
- 不配置证书时自动生成自签名 TLS 证书，并输出 SHA-256 指纹
- 支持自定义 PEM 证书和私钥
- 优雅退出、请求日志和连接超时

## 构建与运行

要求 Go 1.26.11 或更高版本。构建发布包时请使用仍受 Go 官方支持的最新补丁版本。

在 Windows 上运行 `build.bat`，可一次构建 Windows amd64、Linux amd64 和 Linux arm64 版本。可执行文件位于脚本所在目录的 `dist` 下。

```bash
go build -o goproxy.exe .
./goproxy.exe
```

默认监听 `127.0.0.1:8080`，HTTP、HTTPS 和 SOCKS5 都使用该端口：

```text
listening on 127.0.0.1:8080 (HTTP / HTTPS / SOCKS5)
```

监听所有网卡：

```bash
./goproxy.exe -listen 0.0.0.0:8080
```

> 如果监听在公网地址，请务必设置用户名和密码，否则它就是一个开放代理。

## 配置来源

配置优先级从高到低为命令行参数、进程环境变量、启动时工作目录下的 `.env`、默认值。环境变量名使用 `GOPROXY_` 前缀，将参数名转成大写，并把连字符改成下划线。比如 `-max-connections` 对应 `GOPROXY_MAX_CONNECTIONS`，`-v` 对应 `GOPROXY_V`。

可以在启动程序的目录创建 `.env`，然后直接运行程序：

```dotenv
GOPROXY_LISTEN=127.0.0.1:8080
GOPROXY_MAX_CONNECTIONS=128
GOPROXY_USER=alice
GOPROXY_PASS='替换成你的密码'
GOPROXY_DIAL_TIMEOUT=10s
GOPROXY_V=false
```

`.env` 使用一行一个 `KEY=VALUE` 的格式，支持空行和 `#` 注释。单引号或双引号可保留值中的空格和 `#`，文件中的 `$` 和反斜杠按原样读取。证书和私钥的相对路径以启动时的工作目录为准。含密码的 `.env` 应限制文件读取权限。

也可以通过 PowerShell 为当前会话设置普通参数，例如 `$env:GOPROXY_MAX_CONNECTIONS = '128'`，随后启动代理。需要清除文件中的某个字符串配置时，可以用显式空值覆盖。

## 客户端使用

### HTTP / HTTPS 网站

把 HTTP 代理配置为 `127.0.0.1:8080`。访问 HTTPS 网站时会自动使用 `CONNECT`，代理不会解密 TLS 流量。

```bash
# 普通 HTTP
curl -x http://127.0.0.1:8080 http://example.com

# HTTPS 通过 CONNECT
curl -x http://127.0.0.1:8080 https://example.com
```

浏览器中把 HTTP 和 HTTPS 代理都填为 `127.0.0.1:8080` 即可。

### SOCKS5

```bash
# socks5h 表示由代理端解析域名
curl -x socks5h://127.0.0.1:8080 https://example.com
```

浏览器中选择 SOCKS5，地址 `127.0.0.1`，端口 `8080`。如需代理端解析 DNS，请启用 “远程 DNS” / “Proxy DNS” 选项。

### HTTPS 代理

这里的 HTTPS 代理是指“客户端到代理服务器之间使用 TLS”，而不是中间人解密 HTTPS 内容：

```bash
# 默认使用临时自签名证书，因此跳过代理证书校验
curl -x https://127.0.0.1:8080 --proxy-insecure https://example.com
```

正式使用时应提供受客户端信任的证书。自签名证书的 SHA-256 指纹会在启动日志中输出。

### 认证

启用认证时，用户名和密码必须同时提供，各占 1 至 255 字节，且都不能包含 ASCII 控制字符。用户名不能包含冒号，密码可以包含冒号。通过 `GOPROXY_USER` 和 `GOPROXY_PASS` 提供凭据，可避免将密码写入代理进程的命令行。

HTTP Basic 要求凭据为有效的 UTF-8，并使用 `golang.org/x/text/unicode/norm` 按 Unicode 规范等价规则比较。SOCKS5 使用配置中的原始字节，非 UTF-8 凭据仅可用于 SOCKS5。

```bash
# HTTP 代理
curl -x http://alice:secret@127.0.0.1:8080 https://example.com

# SOCKS5
curl -x socks5h://alice:secret@127.0.0.1:8080 https://example.com

# HTTPS 代理
curl -x https://alice:secret@127.0.0.1:8080 --proxy-insecure https://example.com
```

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-listen` | `127.0.0.1:8080` | 监听地址，三种协议共用 |
| `-max-connections` | `256` | 三种协议共用的客户端并发连接上限，含认证前连接、HTTP 长连接和隧道。必须为正整数，满额时关闭新连接 |
| `-user` | 空 | 用户名，必须和 `-pass` 一起使用 |
| `-pass` | 空 | 密码，必须和 `-user` 一起使用 |
| `-cert` | 空 | HTTPS 代理证书（PEM） |
| `-key` | 空 | HTTPS 代理私钥（PEM） |
| `-dial-timeout` | `10s` | 连接目标网站的超时时间 |
| `-request-read-timeout` | `15s` | 读取 HTTP 请求头和请求体的总时限。大文件上传可按需调大 |
| `-response-header-timeout` | `15s` | HTTP 请求发送完毕后等待上游响应头的时限 |
| `-upstream-write-timeout` | `15s` | 上游连接就绪后发送 HTTP 请求的时限 |
| `-client-write-timeout` | `15s` | 向客户端写入或刷新 HTTP 响应的单次时限 |
| `-response-body-idle-timeout` | `60s` | 等待上游响应正文继续到达的时限。事件流的静默间隔较长时可按需调大 |
| `-tunnel-half-close-timeout` | `60s` | SOCKS5 和 CONNECT 隧道一侧半关闭后，另一侧无数据转发的时限 |
| `-tunnel-write-timeout` | `15s` | SOCKS5 和 CONNECT 隧道单次写入的时限 |
| `-v` | `false` | 输出每个已建立连接/请求的日志 |

## 使用自定义证书

例如用 OpenSSL 生成一个有效期 365 天的证书：

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout proxy.key -out proxy.crt -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

./goproxy.exe -listen 127.0.0.1:8080 -cert proxy.crt -key proxy.key
```

客户端信任 `proxy.crt` 后，使用 HTTPS 代理时就不需要跳过证书校验了。

## 工作方式

1. 监听 TCP 连接，读取第一个字节：
   - `0x05`：SOCKS5
   - `0x16`：TLS ClientHello，按 HTTPS 代理处理
   - 其他：按 HTTP 代理处理
2. HTTP 请求交给 `net/http` 的代理处理器：
   - 普通请求通过 `http.Transport` 转发，并移除逐跳（hop-by-hop）头
   - `CONNECT` 请求必须显式指定 `host:port`，且不能带请求体。目标 TCP 连接建立后直接双向转发字节
3. SOCKS5 握手和认证由本程序实现，只接受 `CONNECT` 命令。客户端应在收到成功应答后发送隧道数据。拨号期间，超过读取缓冲区的提前数据会取消拨号。
4. 建立隧道后使用半关闭（`CloseWrite`）正确传递两个方向的 EOF

## 测试

```bash
go test ./...
go vet ./...
```

集成测试覆盖：

- HTTP 请求转发
- HTTP `CONNECT` 访问 HTTPS
- HTTPS 代理（含认证和 `CONNECT`）
- SOCKS5 认证与数据转发
- HTTP 407 认证流程
- 目标地址解析和逐跳头清理

## 限制

- 代理仅拨号到通过公网地址检查的目标。回环、私网、链路本地、共享地址、保留地址和代理主机网卡自身的地址均被拦截。域名也按实际拨号的 IP 检查。使用公网 IP 编址的内部服务需要由网络层的出站访问规则限制。

- SOCKS5 仅支持 TCP `CONNECT`，不支持 `BIND` 和 `UDP ASSOCIATE`
- 不做 TLS 中间人解密
- 普通 HTTP 代理不转发 HTTP Upgrade（WebSocket）；`wss://` 走 `CONNECT`，可以正常使用
- 不支持上游代理链
- HTTPS 代理端点使用 HTTP/1.1

## 目录结构

```text
.
├── main.go                  # 命令行入口
├── go.mod
└── internal/proxy
    ├── server.go            # 监听、协议识别、连接生命周期
    ├── http.go              # HTTP 代理与 CONNECT
    ├── socks5.go            # SOCKS5 协议实现
    ├── auth.go              # HTTP/SOCKS5 认证
    ├── relay.go             # 双向隧道
    ├── tls.go               # TLS 配置与自签名证书
    └── proxy_test.go        # 集成测试
```
