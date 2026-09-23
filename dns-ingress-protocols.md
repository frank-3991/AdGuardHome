# DNS 多入口协议语义转换分析

本文基于当前仓库以及 go.mod 锁定的 github.com/AdguardTeam/dnsproxy v0.84.2。入口协议包括明文 UDP、明文 TCP，以及 DoT、DoH、DoQ；DNSCrypt 在同一套 dnsproxy 抽象中实现，作为加密入口的补充对照。

AdGuardHome 不直接实现每种协议的 socket 循环。`dnsforward.Server.Prepare` 负责把监听地址、TLS 配置、上游、缓存和处理器装配成 `proxy.Config`，再创建 `proxy.Proxy`：

- 配置装配：[internal/dnsforward/config.go:343](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:343)
- 创建代理：[internal/dnsforward/dnsforward.go:486](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/dnsforward.go:486)
- 监听初始化顺序：[proxy/server.go:21](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go:21)
- goroutine 启动顺序：[proxy/server.go:50](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go:50)

处理器链在配置时固定为：

```text
ratelimit middleware
  -> log middleware
  -> dnsforward.Server.Wrap
       -> ClientID 解析、访问控制、域名访问控制
       -> dnsforward.Server.ServeDNS
            -> 初始处理、DDR、DHCP、预过滤、上游、后过滤、ipset、日志统计
```

对应代码是 `ratelimitMw.Wrap(logMw.Wrap(s.Wrap(s)))`，见 [internal/dnsforward/config.go:370](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:370)。共享处理模块列表见 [internal/dnsforward/requesthandler.go:33](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/requesthandler.go:33)。

关键边界是：入口层负责把不同连接和报文变成统一的 `*proxy.DNSContext`；共享层只消费 `Req`、`Res`、`Proto`、`Addr`、协议句柄和少量协议元数据。

## 1. 各阶段职责

| 阶段 | UDP | TCP | DoT | DoH | DoQ |
|---|---|---|---|---|---|
| 监听建立 | 无连接 `UDPConn` | `TCPListener` | TCP listener 外包 `tls.Listener` | 当前 AGH 由 Web 服务路由承接；`dnsproxy` 自身只在 `HTTPConfig.ListenAddresses` 非空时监听 | UDP socket 上建立 QUIC `EarlyListener` |
| 接收单位 | 一个 datagram 一个请求 | 一个连接可连续读多个请求 | 同 TCP，字节经 TLS | 一个 HTTP 请求承载一个 DNS 报文 | 一个 QUIC connection 多个 stream，一个 stream 一个请求 |
| 加密处理 | 无 | 无 | Go TLS 握手与解密 | Web HTTPS/HTTP3 层完成；处理器读取 `r.TLS`、`Host`、路径 | `quic-go` 完成 QUIC/TLS 1.3，ALPN 为 `doq` 及兼容值 |
| DNS 分帧 | datagram 直接 `Unpack` | 2 字节长度前缀加消息体 | 同 TCP | GET 解码 `dns` 参数；POST 读取 `application/dns-message` | RFC 版有 2 字节前缀；旧 draft 可无前缀 |
| 请求结束 | 回包到源地址 | 循环退出后关闭连接 | 同 TCP | HTTP 事务由 Web/HTTP2/HTTP3 管理 | 正常关闭 stream；致命协议错误关闭整个 QUIC connection |
| 客户端地址 | UDP 源地址，另记录目的本地 IP | TCP remote address | TLS remote address | 默认 socket remote；可信代理时可读取代理头 | QUIC remote address |
| 协议身份 | 无 ClientID | 无 ClientID | SNI 可编码 ClientID | 路径优先，其次 SNI/Host | SNI 可编码 ClientID |

### 1.1 监听和连接处理

`preparePlain` 在允许明文 DNS 时填入 UDP/TCP 地址，见 [internal/dnsforward/config.go:817](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:817)。`prepareTLS` 填入 DoT 与 DoQ 地址并安装 `tlsManager.TLSConfig()`，见 [internal/dnsforward/config.go:721](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:721)。

UDP 接收循环每次读到 datagram 后复制字节，并在信号量允许时启动 goroutine，见 [serverudp.go:86](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverudp.go:86)。TCP/DoT 共用 `tcpPacketLoop` 和 `handleTCPConnection`，差别只在 listener 是否经过 TLS 包装以及 `Proto` 取值，见 [servertcp.go:93](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:93)。

DoQ 先 accept QUIC connection，再 accept bidirectional stream。连接复用、stream 不复用，代码注释明确 “One query - one stream”，见 [serverquic.go:211](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:211) 和 [serverquic.go:309](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:309)。

当前 AdGuardHome 的 DoH 不依赖 `dnsproxy` 自己的 HTTPS listener：`newProxyConfig` 只设置 `ServerHeader` 和 `InsecureEnabled`，没有设置 `HTTPConfig.ListenAddresses`。实际路由由 Web mux 注册到 `dnsforward.Server`：

- [internal/dnsforward/config.go:354](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:354)
- [internal/home/dns.go:134](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/home/dns.go:134)
- 默认路由见 [internal/home/config.go:404](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/home/config.go:404)

因此，DoH 的 TLS/HTTP3 监听器属于 Web 服务；HTTPS/HTTP3 服务器分别在 [internal/home/web.go:463](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/home/web.go:463) 和 [internal/home/web.go:498](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/home/web.go:498) 使用同一个 TLS 配置启动。`dnsforward.Server.ServeHTTP` 只做运行态检查后转给 `prx.ServeHTTP`，见 [internal/dnsforward/dnsforward.go:890](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/dnsforward.go:890)。`TLSConf.HTTPSListenAddrs` 在本仓库主要用于 DDR SVCB 通告。

### 1.2 TLS 与加密语义

DoT 在 TCP listener 上调用 `tls.NewListener`，见 [servertcp.go:66](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:66)。DoQ 克隆 TLS 配置后设置 ALPN 为 `doq`、`doq-i02`、`doq-i00`、`dq`，见 [serverquic.go:105](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:105)。

严格 SNI 检查通过包装 `tls.Config.GetCertificate` 实现。SNI 不匹配证书名称时，错误发生在 TLS 握手阶段，请求不会进入 DNS 处理链；实现见 [internal/dnsforward/config.go:781](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/config.go:781)。

DoH 的路径型 ClientID 不要求证书包含 `clientid.server-name`，因为路径已经给出身份；DoT/DoQ 若通过 SNI 表达 ClientID，证书需要覆盖相应即时子域名，常见方式是通配证书。

DNSCrypt 的证书、provider 和 UDP/TCP 监听地址在 `prepareDNSCrypt` 中装入 proxy，加解密由 `github.com/AdguardTeam/dnscrypt` 承担；AdGuardHome 的共享处理器只看到 `ProtoDNSCrypt` 和解密后的 `dns.Msg`。

### 1.3 请求解析

所有入口最终都得到 `*miekg/dns.Msg`，但解析失败的反馈层级不同：

- UDP：完全没有可用 DNS 头时丢弃；有可用头但 body 非法时回 `FORMERR`，见 [serverudp.go:149](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverudp.go:149)。
- TCP/DoT：长度前缀读取失败、连接中断、消息过大或 `Unpack` 失败都只结束当前连接处理，不构造 DNS 错误，见 [servertcp.go:168](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:168)。
- DoH：HTTP 方法、媒体类型、base64/body 和 DNS 解析错误映射成 `405`、`415`、`400` 等 HTTP 状态，见 [serverhttps.go:140](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverhttps.go:140)。
- DoQ：短读只结束 stream；DNS 解析失败或违反 DoQ 协议则用 `DOQ_PROTOCOL_ERROR` 关闭 QUIC connection，见 [serverquic.go:331](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:331)。

一旦 wire message 成功解析，协议中立的 DNS 校验由 `handleDNSRequest` 统一执行。问题数不为 1 回 `FORMERR`，拒绝 ANY 回 `NOTIMPLEMENTED`，递归检测和外部客户端请求私有 ARPA 回 `NXDOMAIN`，见 [proxy/proxy.go:944](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:944)。这些响应随后由各协议自己的 writer 发回客户端。

### 1.4 客户端识别

客户端识别分两层：

1. 网络地址：入口层填充 `DNSContext.Addr`，`handleDNSRequest` 立即用配置的私网集合计算 `IsPrivateClient`，见 [proxy/server.go:88](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go:88)。
2. 逻辑身份：DoT/DoQ 可由 SNI 提取，DoH 可由路径或 Host/TLS SNI 提取；明文 UDP/TCP 没有 ClientID。实现见 [internal/dnsforward/middleware.go:95](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/middleware.go:95) 和 [internal/dnsforward/clientid.go:88](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/clientid.go:88)。

DoH 反代头的优先级是 `CF-Connecting-IP`、`True-Client-IP`、`X-Real-IP`、`X-Forwarded-For`。只有直连代理地址属于 `TrustedProxies` 时才使用头中的 IP，否则回退为代理自身地址，见 [serverhttps.go:357](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverhttps.go:357)。头中端口不可得，因此构造的 `AddrPort` 端口为 0。

### 1.5 入口异常和共享异常的响应差异

入口异常发生在 `handleDNSRequest` 之前，因此只能按所属传输协议结束：UDP 可能静默丢弃或回 DNS `FORMERR`；TCP/DoT 关闭 TCP/TLS 连接；DoH 回 HTTP 4xx/5xx；DoQ 关闭 stream 或带应用错误码关闭 QUIC connection。TLS 握手失败甚至还没有 DNS 消息，不能返回 DNS rcode。

共享异常发生在已经有 `Req` 和 `DNSContext` 后，所以能生成 DNS 语义响应或由统一 writer 编码：

- 协议中立校验失败：统一生成 `FORMERR`、`NOTIMPLEMENTED` 或 `NXDOMAIN`。
- ClientID 提取错误：`Server.Wrap` 生成 `SERVFAIL`，见 [internal/dnsforward/middleware.go:28](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/middleware.go:28)。
- 访问控制命中：UDP 和 DNSCrypt 返回 `ErrDrop` 不回包，防止放大；TCP、DoT、DoQ、DoH 收到 DNS `REFUSED`，见 [internal/dnsforward/middleware.go:57](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/middleware.go:57)。
- 上游无响应：`handleExchangeResult` 在 `DNSContext.Res` 中放入 DNS `SERVFAIL`，见 [proxy/proxy.go:836](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:836)。即使 `Resolve` 同时返回普通错误，`handleDNSRequest` 也只对 `ErrDrop` 短路，其他错误仍会带着已有 `Res` 进入统一响应分发。
- 过滤引擎或共享处理器返回内部错误且未设置 `Res`：错误沿 handler 返回，由入口按“无响应”处理：UDP/DNSCrypt 静默结束，TCP/DoT 关闭连接，DoH 回 HTTP 500，DoQ 回内部错误。
- 过滤、DDR、健康检查、DHCP 本地名等：共享层设置 `pctx.Res`，入口 writer 只负责按协议序列化。

`ErrDrop` 是入口层和共享层之间的显式协议信号。`handleDNSRequest` 遇到它后不调用 `respond`，见 [proxy/server.go:93](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go:93)。速率限制中间件也只对 UDP 启用限流并返回 `ErrDrop`，这解释了 UDP 与面向连接协议的第一个行为差异。

## 2. 上下文进入共享处理链前后的变化

### 2.1 从传输对象到 DNSContext

`newDNSContext` 只初始化协议、请求、客户端地址和全局唯一 `RequestID`，见 [proxy/dnscontext.go:101](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/dnscontext.go:101)。各入口随后补充自己的传输句柄：

| 字段 | 填充入口 | 后续用途 |
|---|---|---|
| `Proto` | 所有入口 | 选择 writer、UDP truncate、日志协议标记、访问控制响应方式 |
| `Req` | 所有入口 | 统一过滤、转发、缓存和响应生成 |
| `Addr` | 所有入口 | 私网判断、访问控制、持久客户端、ECS、日志统计 |
| `Conn` | UDP/TCP/DoT | UDP 回包或 TCP/DoT 长度前缀写回；DoT 还用于读取 SNI |
| `HTTPRequest`/`HTTPResponseWriter` | DoH | 路径 ClientID、Host/SNI、HTTP 状态和 body 写回 |
| `QUICConnection`/`QUICStream` | DoQ | SNI、DoQ 错误关闭、stream 写回 |
| `DoQVersion` | DoQ | 决定响应是否添加 2 字节长度前缀 |
| `localIP` | UDP | 多地址主机上按正确本地地址回包 |

`handleDNSRequest` 进入业务处理器前会做三件事：丢弃误入的 response 报文、计算 `IsPrivateClient`、执行统一 DNS 校验。也就是说，业务处理器看到的 `pctx` 已经带有网络身份和协议类别，但尚未带有 AdGuardHome 的 ClientID 和客户过滤设置。

### 2.2 Go context 与 dnsContext 的二次封装

每个入口都会调用 `p.reqCtx.New(ctx)` 创建请求级 context。随后日志中间件把带请求 ID、QTYPE、查询名的 logger 放入 context。

`Server.Wrap` 在进入 `Server.ServeDNS` 前提取 ClientID：

- DoH 路径 `/dns-query/{ClientID}` 命中时，直接从 `r.PathValue` 读取。
- DoT/DoQ 从 TLS connection state 的 SNI 读取。
- DoH 没有路径 ID 时，还会从 TLS SNI 或明文 Host 的主机名读取。
- UDP/TCP 直接得到空 ID。

提取成功后，ClientID 通过 `contextWithClientID` 放入 Go context；进入 `Server.ServeDNS` 后再复制到业务本地的 `dnsContext.clientID`。这使中间件只负责身份提取，后续模块只面对 `dnsContext`，不直接理解 HTTP 路径或 TLS SNI。

### 2.3 协议信息如何影响查询结果

协议信息不会让过滤规则分叉，但会影响传输适配和少量可达性判断：

1. `Proto` 决定响应编码。`scrub` 对 UDP 按请求 EDNS UDP size 截断，并在需要时设置 TC；非 UDP 使用 65535 字节上限，见 [proxy/dnscontext.go:160](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/dnscontext.go:160)。因此同样的上游大响应在 UDP 上可能触发截断并提示客户端改用 TCP，在 TCP/DoT/DoH/DoQ 上则完整返回。
2. `DoQVersion` 只影响 DoQ 响应帧：RFC v1 添加 2 字节前缀，旧 draft 不添加，见 [proxy/serverquic.go:403](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:403)。
3. `Proto` 决定查询日志中的客户端协议：DoH、DoQ、DoT、DNSCrypt 分别记录，明文 UDP/TCP 留空，见 [internal/dnsforward/stats.go:114](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/stats.go:114)。
4. 访问控制对 UDP/DNSCrypt 使用静默丢弃，对面向连接或请求-响应式加密协议返回 DNS `REFUSED`。这是防放大的传输策略，不是过滤策略差异。
5. UDP 独占 socket 速率限制。限流中间件只检查 `ProtoUDP`，见 [ratelimit.go:36](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/ratelimit/ratelimit.go:36)；TCP/DoT/DoH/DoQ 不受该 IP 限流中间件影响。

除这些必要差异外，协议不参与过滤决策。`CheckHost` 使用同一个 host、QTYPE 和 `filtering.Settings`，过滤响应也由同一个 `genDNSFilterMessage` 生成。

### 2.4 客户端信息如何影响查询结果

`processInitial` 先把 `pctx.Addr.Addr()` 交给地址处理器做 rDNS/WHOIS 等后台更新，再从 context 读取 ClientID，并用 IP 和 ClientID 生成客户过滤设置，见 [internal/dnsforward/process.go:104](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/process.go:104)。

客户信息的影响包括：

- 访问控制：IP/CIDR 与 ClientID 同时参与。黑名单模式任一命中即拒绝；白名单模式要求 IP 或 ClientID 至少一个允许。
- 个性化过滤：`ApplyAdditionalFiltering(addr, clientID, setts)` 先按 ClientID 查持久客户端，找不到再按 IP/子网查找，再可通过 DHCP MAC 查找；客户可拥有独立过滤开关、安全搜索、安全浏览、家长控制和拦截服务。
- 自定义上游：`setCustomUpstream` 同样先按 ClientID 后按 IP 查找持久客户端，并写入 `pctx.CustomUpstreamConfig`，见 [internal/dnsforward/process.go:524](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e/internal/dnsforward/process.go:524)。
- 本地网络语义：`IsPrivateClient` 为 false 时，本地 DHCP 域名直接 `NXDOMAIN`；私有 ARPA 的 PTR/SOA/NS 请求也会在统一校验阶段被拒绝。私网客户端则可查 DHCP lease 或私有 RDNS 上游。
- EDNS Client Subnet：启用 ECS 后，请求自带非零 ECS 就透传；否则用配置的自定义 ECS 地址或客户端 `Addr` 生成 ECS，见 [proxy/proxy.go:1007](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:1007)。DoH 经可信代理头改写后的客户端地址也会成为这个来源。
- 日志和统计：有 ClientID 时优先按 ClientID 归档，同时保留 IP；否则按匿名化后的 IP 归档。

上游选择本身由统一的 `selectUpstreams` 完成：私有 RDNS 请求走私有上游；客户自定义上游优先于全局上游；未命中自定义配置再按域名选择全局上游，见 [proxy/proxy.go:741](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:741)。缓存也遵循客户隔离：客户自定义上游未配置缓存时不能使用全局缓存，私有 RDNS 和 CD 请求也不缓存。

## 3. 入口异常、连接中断与一致性保障

### 3.1 UDP

UDP 没有连接生命周期。监听 socket 关闭或读取错误会让该 listener 的 packet loop 退出；单个 datagram 处理失败不会影响后续包。

- 字节流连 DNS header 都无法形成：记录错误并静默返回，不发送不可解释的响应。
- DNS header 可解析但消息其余部分非法：构造 `FORMERR` 并发送到源地址，避免客户端只能等待超时。
- 业务层返回 `ErrDrop`：例如 UDP 限流、访问客户端或访问域名命中，不写任何响应。
- 响应写回失败：若是 socket 已关闭则忽略；其他写错误只记录日志。
- 客户端在响应前离开：UDP 层无感知，响应照常发往原源地址。

### 3.2 TCP 与 DoT

TCP 和 DoT 共用同一个连接处理函数。连接在 goroutine 中循环读取多个请求，并通过 defer 保证关闭。

- Accept 失败且 listener 已关闭：debug 日志并结束该监听循环；其他 Accept 错误记录 error 并结束。
- TLS 握手失败：握手在 `Accept` 返回 TLS 连接前由 `tls.Listener` 处理；失败不会产生 `DNSContext`，连接由 TLS/TCP 层结束。
- 读取 2 字节长度、读满 body、body 超长或 `Unpack` 失败：`readDNSReq` 返回 nil，handler 直接退出并关闭连接，不发送 DNS rcode。
- 单个业务请求失败但连接仍可写：继续进入响应分发；若已有 DNS 响应则写回，若 `Res == nil` 则关闭连接。
- 写响应失败或对端断开：记录非关键错误，defer 关闭连接；后续请求不再处理。

TCP/DoT 对非法分帧采取关闭连接而不是 `FORMERR`，这符合字节流协议的状态要求：长度前缀已经破坏时，服务器无法可靠地定位下一条消息。

### 3.3 DoH

DoH 把错误明确分成 HTTP 层和 DNS 层：

- 明文 HTTP 且未允许 `InsecureEnabled`：返回 `404`。
- 非 GET/POST：`405`。
- POST 媒体类型错误：`415`。
- GET 的 `dns` 参数非法、body 读取失败或 DNS wire message 非法：`400`。
- DNS 已成功解析后，`FORMERR`、`NXDOMAIN`、`REFUSED`、`SERVFAIL` 等仍是 HTTP 200，body 为 `application/dns-message`；这是 DNS 语义，不映射成 HTTP 500。
- 业务结束时没有 `Res` 或响应无法 pack：才返回 HTTP 500。
- 客户端在写响应时断开：Go HTTP server 终止该请求，写错误只在 proxy 层记录。

DoH 还通过 HTTP 路由路径支持 ClientID。非法路径 ID 在 `Server.Wrap` 中变成 DNS `SERVFAIL`，不是 HTTP 404，因为路由已经匹配且请求体中的 DNS 消息已经成功解析。

### 3.4 DoQ

DoQ 同时具有 QUIC connection 和 DNS stream 两级生命周期：

- Accept connection 的普通超时会被忽略并继续循环；严重错误结束监听循环。
- Accept stream 失败或 idle timeout：以 `DOQ_NO_ERROR` 关闭 connection 并结束该连接处理。
- stream 短读、读到的字节不足最小 DNS 包：记录后返回，goroutine 随后关闭当前 stream；不影响同一 QUIC connection 上其他 stream。
- DNS 消息无法 unpack、出现 EDNS TCP keepalive、非法 0-RTT opcode 等协议错误：以 `DOQ_PROTOCOL_ERROR` 关闭整个 connection。
- 共享处理结束但没有 `Res`：以 `DOQ_INTERNAL_ERROR` 关闭 connection。
- 正常响应：按协商/推断出的 DoQ 版本写帧，然后关闭 stream 并发送 FIN。

### 3.5 共同逻辑如何避免过滤和转发不一致

协议差异被限制在入口 adapter 内，业务一致性由以下结构保证：

1. 统一数据模型。所有入口都填充同一个 `proxy.DNSContext`，传输句柄放在独立字段，业务主体只处理 `Req`、`Addr` 和后续设置。
2. 统一前置校验。问题数、ANY、递归检测、私有 ARPA 等判断只在 `validateRequest` 中实现一次。
3. 统一中间件。限流、日志、ClientID、IP/ClientID 访问控制、blocked hosts 都位于所有协议共用的 handler chain 中。
4. 统一过滤设置。客户过滤只由 `Addr` 与 ClientID 决定，不由 `Proto` 决定；命中的拦截响应由同一 blocking mode 生成。
5. 统一上游选择。普通查询、私有 RDNS、客户自定义上游、fallback、DNS64、bogus NXDOMAIN 和缓存都在 `proxy.Resolve` / `selectUpstreams` 内完成。
6. 统一结果回写接口。共享层只设置 `Res`；UDP、TCP、DoT、DoH、DoQ 各自负责 wire format、HTTP status 或 QUIC error code，不反向修改过滤结果。
7. 传输差异只处理协议自身要求。UDP 截断和静默丢弃、TCP 分帧、DoH 状态码、DoQ stream/connection 错误均属于适配层，不改变域名是否过滤或转发到哪个上游。

需要注意的是，上游调用接口当前使用的是 `upstream.Upstream.Exchange(req)`，请求 context 不直接传入上游实现。连接中断会触发请求 context 取消，但已发出的上游查询不一定随之中断；不过响应回到入口时可能因客户端已断开而写失败。这个行为对所有协议一致，不影响过滤判定和上游选择。

## 协议差异与共享语义对照结论

| 维度 | 协议差异 | 共享语义 |
|---|---|---|
| 连接模型 | UDP 无连接；TCP/DoT 字节流复用；DoQ connection 多 stream；DoH 是 HTTP/HTTP2/HTTP3 请求 | 每个请求都归一为一个 `DNSContext` |
| TLS/加密 | DoT、DoQ 在 DNS proxy listener 内握手；DoH 在 AGH Web 层完成；DNSCrypt 自行加解密 | 解密和握手成功后，业务只处理标准 `dns.Msg` |
| 解析失败 | UDP 可回 `FORMERR`；TCP/DoT 关闭连接；DoH 回 HTTP 4xx；DoQ 使用 QUIC/DoQ 错误码 | 只有成功解析成 DNS 消息后，才进入统一 DNS rcode 和过滤链 |
| 客户端身份 | UDP/TCP 只有源 IP；DoT/DoQ 可用 SNI；DoH 可用路径、SNI/Host 和可信代理头 | IP 与可选 ClientID 统一驱动访问控制、客户过滤、自定义上游和日志 |
| 访问拒绝 | UDP/DNSCrypt 静默丢弃；其他协议回 DNS `REFUSED` | 是否拒绝由同一 IP/ClientID/host 规则决定 |
| 响应大小 | UDP 按 EDNS size 截断并可能设置 TC；其他协议可传 64KiB 消息 | 查询结果来自同一过滤和上游路径，仅最终序列化不同 |
| 转发路径 | 无协议分支 | 私有 RDNS、客户自定义上游、全局上游和 fallback 的优先级完全一致 |
| 业务失败 | 入口把无响应映射成关闭、HTTP 500 或 DoQ internal error | 可表达 DNS 语义的业务失败优先生成统一 DNS rcode |

结论：这些入口的本质是协议适配层。监听、握手、分帧、客户端网络地址和协议句柄在进入共享链之前被转换为 `DNSContext`；ClientID、私网属性、客户过滤设置和自定义上游在共享链前段补齐。之后所有协议执行同一套校验、访问控制、过滤、DNS64、缓存、上游选择和统计逻辑。协议造成的差异只存在于消息能否通过、如何取客户端身份、如何截断/封装响应，以及连接或解析失败如何结束；不会让同一客户端对同一域名产生不同的过滤或转发决策。
