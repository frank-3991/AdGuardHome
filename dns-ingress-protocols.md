# DNS 入口协议与共享处理语义分析

本文基于当前仓库的 internal/dnsforward、internal/home，以及依赖 github.com/AdguardTeam/dnsproxy v0.84.2、github.com/AdguardTeam/dnscrypt v0.0.2 的实际实现分析。核心结论是：各入口只负责把不同传输协议还原成统一的 proxy.DNSContext 和 *dns.Msg，过滤、DHCP、重写、上游选择、缓存、DNS64、统计与查询日志由同一条 dnsforward 处理链完成。

## 1. 总体边界

AdGuard Home 在 [internal/dnsforward/config.go:343](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/config.go:343) 创建 dnsproxy 配置，并把请求处理器组装为：

~~~text
ratelimit -> logMiddleware -> dnsforward.Server.Wrap(access/clientID) -> dnsforward.Server.ServeDNS
~~~

对应代码在 [internal/dnsforward/config.go:370](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/config.go:370)。dnsproxy 负责监听、TLS/QUIC/HTTP/DNSCrypt 外层协议、报文拆包和按协议写回；[internal/dnsforward/requesthandler.go:18](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/requesthandler.go:18) 的 ServeDNS 负责统一 DNS 业务处理。

共享处理链顺序固定为：

1. processInitial：客户端地址处理、AAAA 开关、保留域名、ClientID 与客户端过滤设置。
2. processDDRQuery：本机加密解析器发现。
3. processDHCPHosts：本机 DHCP 主机名。
4. processDHCPAddrs：本机 DHCP 反向解析。
5. processFilteringBeforeRequest：请求前过滤、安全服务和重写。
6. processUpstream：按客户端配置选择上游并调用 proxy.Resolve。
7. processFilteringAfterResponse：响应中的 CNAME、IP、HTTPS hint 二次过滤。
8. ipset.process：把解析结果加入 ipset；错误只记录，不改变响应。
9. processQueryLogsAndStats：查询日志和统计；若前面的阶段以 Finish 提前结束，则不会执行这一阶段。

阶段定义见 [internal/dnsforward/requesthandler.go:31](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/requesthandler.go:31)。

## 2. 入口阶段如何分工

### 2.1 监听与连接处理

| 入口 | 监听和接入 | 请求边界 | 共享链入口 |
| --- | --- | --- | --- |
| UDP | Proxy.Start 初始化 UDP socket；udpPacketLoop 循环 UDPRead，每个数据报获取信号量后起 goroutine | 一个 UDP 数据报就是一个 DNS 消息 | udpHandlePacket 解包后构造 ProtoUDP 上下文 |
| TCP | 普通 TCP listener；tcpPacketLoop 对每个连接起 goroutine | 连接上循环读取 2 字节长度前缀和消息体 | handleTCPConnection 构造 ProtoTCP 上下文 |
| DoT | 普通 TCP listener 外包一层 tls.NewListener | 与 TCP 相同，仍使用 2 字节长度前缀；TLS 握手在读连接时完成 | 同一连接循环构造 ProtoTLS 上下文 |
| DoH | 当前主路径不是 dnsproxy 自己监听 HTTPS，而是主 Web 服务监听 HTTP/1.1、HTTP/2，可选 HTTP/3；路由注册到 dnsforward.Server.ServeHTTP | 一个 HTTP GET 或 POST 对应一个 DNS 消息 | Web handler 转发给 Proxy.ServeHTTP，构造 ProtoHTTPS 上下文 |
| DoQ | dnsproxy 在 UDP 上创建 QUIC EarlyListener；每个 QUIC 连接一个处理 goroutine，每个双向流再获取信号量处理 | RFC 9250 模式下一流一请求，v1 使用 2 字节长度前缀；兼容旧 draft 的无前缀格式 | handleQUICStream 构造 ProtoQUIC 上下文 |
| DNSCrypt | dnscrypt 库分别创建独立 UDP/TCP server，证书、provider name 和 resolver cert 来自 TLSConf.DNSCryptConf | UDP 每个加密数据报一个请求；TCP 仍是长度前缀，可复用连接 | dnsCryptHandler.ServeDNS 解密后构造 ProtoDNSCrypt 上下文 |

UDP 与 TCP 的监听代码分别在 [serverudp.go:83](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverudp.go:83) 和 [servertcp.go:83](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:83)。DoT 在 [servertcp.go:65](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:65) 通过 tls.NewListener 包装 TCP listener。

DoH 的路由由主程序注册：[internal/home/dns.go:134](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/home/dns.go:134) 遍历配置的 DoH routes 并绑定 globalContext.dnsServer；[internal/dnsforward/dnsforward.go:891](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/dnsforward.go:891) 再调用 dnsproxy 的 ServeHTTP。HTTPS/HTTP3 服务器使用同一个 TLS manager，分别在 [internal/home/web.go:445](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/home/web.go:445) 和 [internal/home/web.go:492](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/home/web.go:492) 启动。

DoQ listener 和流处理在 [serverquic.go:63](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:63)、[serverquic.go:211](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:211)、[serverquic.go:311](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:311)。DNSCrypt server 由 [serverdnscrypt.go:16](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverdnscrypt.go:16) 创建，handler 适配在 [serverdnscrypt.go:110](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverdnscrypt.go:110)。

### 2.2 TLS 与加密处理

DoT 和 DoQ 的 tls.Config 都来自 AdGuard Home 的 TLS manager。配置注入在 [internal/dnsforward/config.go:721](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/config.go:721)：DoT 使用原始 TLS 配置，DoQ clone 后把 ALPN 设置为 doq 及兼容 draft 值，见 [serverquic.go:84](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:84)。

严格 SNI 检查通过包装 tls.Config.GetCertificate 实现；SNI 与证书名称不匹配时握手阶段失败，请求不会进入 DNS 共享链。代码见 [internal/dnsforward/config.go:765](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/config.go:765)。

DoH 的 TLS 由主 Web 服务器负责，不由 dnsproxy 的 DoT/DoQ listener 处理。DoH handler 仍会检查 r.TLS；除非启用 InsecureEnabled，明文 HTTP 请求返回 404 Not Found，见 [serverhttps.go:208](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverhttps.go:208)。

DNSCrypt 不使用 TLS。它用 resolver certificate、client magic 和非对称密钥协商完成查询解密与响应加密；证书 TXT 查询可在加密握手前由 dnscrypt 库直接回答。

### 2.3 请求解析

| 入口 | 外层解析 | DNS 解析失败的入口层响应 |
| --- | --- | --- |
| UDP | 直接对数据报调用 dns.Msg.Unpack | 连 DNS header 都没有时直接丢弃；header 存在时回 FORMERR，避免可识别请求被静默丢弃 |
| TCP | 先读 2 字节长度，再 io.ReadFull，最后 Unpack | 读前缀、读消息体、超长或 Unpack 失败都关闭连接，不发送 DNS 错误 |
| DoT | 与 TCP 相同，只是连接已经过 TLS | 与 TCP 相同；握手失败也只结束连接 |
| DoH | GET 解码 dns 参数，POST 读取 application/dns-message body，再 Unpack | 返回 HTTP 400、405、415 等；不会进入 DNS 共享链 |
| DoQ | 读到流 FIN，按前 2 字节是否等于剩余长度判断 RFC v1 或旧 draft，再 Unpack | 短于最小 DNS 消息只结束当前流；解包失败或违反 DoQ 校验时用 DOQ_PROTOCOL_ERROR 关闭整个 QUIC 连接 |
| DNSCrypt | 先识别 client magic；证书查询走明文 TXT；加密查询先解密再 Unpack | UDP 解密或解包失败丢弃数据报；TCP 失败关闭连接 |

UDP 的特殊处理在 [serverudp.go:155](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverudp.go:155)。TCP 长度帧解析在 [servertcp.go:170](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:170)。DoH HTTP 解析在 [serverhttps.go:143](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverhttps.go:143)。DoQ 解包和协议错误处理在 [serverquic.go:311](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:311)。

### 2.4 客户端识别

所有入口都会填充 DNSContext.Addr，但地址来源不同：

- UDP、TCP、DoT、DoQ、DNSCrypt：使用传输层 remote address。
- DoH：默认使用 r.RemoteAddr；如果反向代理头发送真实 IP，只有直连对端位于 TrustedProxies 时才采用头中地址，否则回退为代理自身地址。支持 CF-Connecting-IP、True-Client-IP、X-Real-IP、X-Forwarded-For，见 [serverhttps.go:317](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverhttps.go:317)。头中 IP 没有端口，因此地址端口为 0。

共享入口 [server.go:79](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go:79) 先丢弃响应包，再用配置的私有网络集合计算 IsPrivateClient，然后执行统一报文校验。

ClientID 只从加密 HTTP 语义中提取，普通 UDP/TCP 和 DNSCrypt 没有协议内 ClientID：

- DoH：优先从路由 /dns-query/{ClientID} 的 path value 提取；没有路径 ID 时，再根据 SNI 或 HTTP Host 的即时子域名提取。
- DoT：从 TLS connection state 的 SNI 提取。
- DoQ：从 QUIC TLS connection state 的 SNI 提取。
- UDP/TCP/DNSCrypt：ClientID 为空。

提取逻辑见 [internal/dnsforward/middleware.go:99](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/middleware.go:99) 和 [internal/dnsforward/clientid.go:63](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/clientid.go:63)。ClientID 会先通过 access middleware，再写入 Go context.Context，随后在 processInitial 中复制到业务层 dnsContext.clientID。

## 3. 异常如何结束请求

### 3.1 入口层异常

| 异常 | UDP | TCP/DoT | DoH | DoQ | DNSCrypt |
| --- | --- | --- | --- | --- | --- |
| 监听失败 | Proxy.Start 返回错误，并关闭已创建 listener | 同左 | Web HTTPS 启动失败走 Web server 错误处理 | dnsproxy 启动失败并关闭已建 listener | dnscrypt server 启动失败，整体启动失败 |
| 外层连接中断 | 无连接概念；读 socket 致命错误退出 packet loop，单个写错误只记录 | Accept/read/write 错误结束该连接 goroutine 并关闭连接 | HTTP server 结束该请求，写错误只记录 | Accept stream 失败后关闭 QUIC 连接；单个流结束后 FIN | UDP 丢数据报；TCP 关闭连接 |
| 外层帧格式错误 | header 无效则丢弃；有 header 则 FORMERR | 关闭连接，不发 DNS 响应 | HTTP 4xx | 短读结束流；DNS 解包或 DoQ 协议错误关闭连接 | UDP 丢弃；TCP 关闭连接 |
| 握手或加密失败 | 不适用 | TLS 握手失败，连接结束 | TLS 失败由 Web server/TLS 栈处理 | QUIC/TLS 握手失败，连接无法进入流处理 | 查询解密失败：UDP 丢弃，TCP 关闭连接 |
| 客户端在响应前断开 | 后续 UDP 写失败被记录或忽略 | 当前读写返回 EOF、closed、timeout 等，连接关闭；错误降为 debug 日志 | HTTP 写返回错误，只记录 | 流或连接错误，关闭相关资源 | UDP 写失败只记录；TCP 关闭连接 |

这些异常都发生在业务 handler 之前，或者发生在业务结果已经生成后的协议写回阶段，因此不会让某一种协议执行另一套过滤规则。它们只决定“能否把统一 DNS 响应送出”以及“使用 DNS rcode、HTTP status，还是传输层关闭”来表达失败。

TCP 和 DoT 的连接循环带 10 秒 deadline；readDNSReq 返回 nil 后 handleTCPConnection 直接 return，defer 关闭连接，见 [servertcp.go:126](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/servertcp.go:126)。DoQ 一个流处理完后由调用方关闭 stream；AcceptStream 出错则关闭整个 QUIC 连接，见 [serverquic.go:211](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/serverquic.go:211)。

DNSCrypt 的入口行为位于 dnscrypt 依赖中：UDP 解密失败仅 debug 记录后返回；TCP handleTCPMsg 解密失败返回错误，外层关闭连接。若已得到合法 DNS 消息但共享 handler 返回错误，dnscrypt 库会再写一个 SERVFAIL。

### 3.2 共享校验和中间件异常

合法 DNS 消息进入 handleDNSRequest 后，先做与入口无关的校验，代码在 [proxy.go:946](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:946)：

- question 数不等于 1：FORMERR。
- 开启 RefuseAny 且 QTYPE 为 ANY：NOTIMPLEMENTED。
- 检测到服务器递归请求：NXDOMAIN。
- 公网客户端请求私有反向解析域名：NXDOMAIN。

这些响应由 AdGuard Home 的 MessageConstructor 生成，因此 EDNS、SOA 和 rcode 风格在所有协议上保持一致。最后只由 respond 分派成 UDP 数据报、TCP 长度帧、HTTP body、QUIC stream 或 DNSCrypt 加密响应。

access 层位于共享链之前，规则见 [internal/dnsforward/middleware.go:24](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/middleware.go:24)：

- ClientID 提取或校验错误：设置统一 DNS SERVFAIL。
- 客户端 IP/ClientID 被拒绝，或请求主机命中 blocked hosts：UDP 和 DNSCrypt 返回 proxy.ErrDrop，不发送任何响应；TCP、DoT、DoH、DoQ 设置 REFUSED。
- UDP 速率限制也返回 ErrDrop，因此不产生响应；速率限制中间件只对 UDP 生效，见 [ratelimit.go:39](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/ratelimit/ratelimit.go:39)。

UDP/DNSCrypt 被拒绝时主动丢包是防放大措施，代码注释在 [internal/dnsforward/middleware.go:57](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/middleware.go:57)。这不是过滤语义差异：请求没有进入过滤或上游阶段，所有协议都不会查询上游；差异只在访问拒绝的外部表达方式。

### 3.3 共享业务阶段异常

业务阶段使用 resultCode 控制是否继续：

- resultCodeFinish：pctx.Res 已设置，立即结束链并正常写回；例如 AAAA 禁用、Mozilla canary、healthcheck、DDR、部分 DHCP 响应。
- resultCodeSuccess：进入下一阶段；很多阶段即使已经设置 pctx.Res，后续阶段也会跳过重复处理。
- resultCodeError：ServeDNS 返回 dctx.err；调用方继续执行统一 respond，是否已有 pctx.Res 决定最终写回内容。

上游解析阶段最典型。proxy.Resolve 在没有可用上游时先把响应置为 NXDOMAIN，再返回 upstream.ErrNoUpstreams；上游交换完全失败且无响应时，handleExchangeResult 会把响应置为 SERVFAIL，见 [proxy.go:775](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:775) 和 [proxy.go:842](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/proxy.go:842)。因此错误通过共享逻辑被转换成 DNS rcode，而不是由 UDP/TCP/DoH/DoQ 各自决定。

响应打包或写回失败属于出口异常：

- UDP：respondUDP 返回错误，handleDNSRequest 只记录。
- TCP/DoT：respondTCP pack 失败返回错误；若 d.Res 为 nil，会直接关闭连接。
- DoH：d.Res 为 nil 或 pack 失败时返回 HTTP 500。
- DoQ：d.Res 为 nil 时以 DOQ_INTERNAL_ERROR 关闭连接；写 stream 失败只记录。
- DNSCrypt：d.Res 为 nil 时不写并丢弃；加密或写失败由 dnscrypt 层记录，TCP 场景最终关闭连接。

## 4. 上下文进入共享链前后的变化

### 4.1 入口产生的初始上下文

newDNSContext 初始只保证 Proto、Req、Addr、RequestID 四个核心值，结构定义见 [dnscontext.go:15](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/dnscontext.go:15)。随后各入口按协议补充：

| 字段 | UDP | TCP | DoT | DoH | DoQ | DNSCrypt |
| --- | --- | --- | --- | --- | --- | --- |
| Proto | udp | tcp | tls | https | quic | dnscrypt |
| Req | 数据报解包 | 长度帧解包 | 长度帧解包 | HTTP 参数/body 解包 | QUIC stream 解包 | 解密后解包 |
| Addr | UDP remote | TCP remote | TLS TCP remote | remote addr 或受信任代理头 | QUIC remote | ResponseWriter remote |
| Conn | *net.UDPConn | net.Conn | *tls.Conn | nil | nil | nil |
| HTTPRequest/Writer | 无 | 无 | 无 | 有 | 无 | 无 |
| QUICConnection/Stream | 无 | 无 | 无 | 无 | 有 | 无 |
| DNSCryptResponseWriter | 无 | 无 | 无 | 无 | 无 | 有 |
| DoQVersion | 无 | 无 | 无 | 无 | v1 或 draft | 无 |

这些协议特有字段只用于三件事：提取 ClientID、按协议写回响应、按协议执行截断或编码。业务过滤函数本身不读取 Conn、HTTPRequest 或 QUICStream。

### 4.2 进入共享 DNS 流程时新增的信息

handleDNSRequest 在调用 requestHandler 前补充：

- IsPrivateClient：由 Addr.Addr 和 privateNets 计算。
- 校验响应 Res：如果 question、ANY、递归、私有 ARPA 等校验失败，直接设置响应，不进入 handler。
- EDNS 和报文大小：真正到 proxy.Resolve 时，calcFlagsAndSize 从 Req 的 OPT 记录提取 udpSize、hasEDNS0、doBit、adBit。
- RequestedPrivateRDNS：validateRequest 调 isForbiddenARPA 时从 PTR/SOA/NS 的反向域名提取。
- ReqECS：开启 EDNS Client Subnet 后，在 Resolve 开始时优先保留客户端请求自带 ECS；否则用客户端公网 IP 或自定义 ECS IP 构造。

上下文随后被 dnsforward 包装成内部 dnsContext，新增：

- setts：客户端过滤设置。
- result：过滤结果。
- startTime：处理耗时。
- clientID：从 Go context 中取回。
- origQuestion/origResp：CNAME rewrite 和响应过滤时保存原始问题与原响应。
- responseFromUpstream/responseAD：标记响应是否来自上游及 AD 位。
- isDHCPHost：标识本机 DHCP 主机名请求。

### 4.3 协议信息如何影响结果

Proto 不直接参与黑名单匹配，也不改变过滤模块的规则选择。它主要影响：

1. 访问拒绝表达：UDP/DNSCrypt 丢包，其他面向连接协议 REFUSED。
2. 响应尺寸：scrub 使用请求 EDNS UDP size；非 UDP 使用 65535 字节上限，见 [dnscontext.go:160](/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/dnscontext.go:160)。
3. 日志协议名：processQueryLogsAndStats 把 https、quic、tls、dnscrypt 映射为 DoH、DoQ、DoT、DNSCrypt；UDP/TCP 留空。
4. 出口编码：DoQ v1 添加 2 字节前缀，旧 draft 不添加；DoH 写 application/dns-message；DNSCrypt 加密；TCP/DoT 写长度帧；UDP 直接写数据报。
5. ClientID 可用性：只有 DoH、DoT、DoQ 能从 HTTP 路径或 TLS SNI 得到 ClientID。

因此，传输协议本身不会让同一个域名在过滤引擎中得到不同裁决；真正可能改变查询结果的是客户端身份、请求内容和由入口可靠提交的客户端地址。

### 4.4 客户端信息如何影响过滤和转发

processInitial 取出 ClientID 后，通过 clientRequestFilteringSettings 获取过滤设置，见 [internal/dnsforward/filter.go:18](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/filter.go:18)。DNSFilter.ApplyAdditionalFiltering 会：

- 把客户端 IP 写入 setts.ClientIP。
- 应用全局和客户端自定义 blocked services。
- 优先按 ClientID 查持久客户端；未命中再按 IP 查，之后还可通过 DHCP MAC 找到客户端。
- 覆盖该客户端的过滤开关、Safe Search、Safe Browsing、Parental、客户端标签、客户端名称等。

上游选择发生在 processUpstream。setCustomUpstream 同样优先按 ClientID、再按 IP 查自定义上游，见 [internal/dnsforward/process.go:526](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0004-adguardhome-2-ec2d8d6e-b/internal/dnsforward/process.go:526)。命中后设置 pctx.CustomUpstreamConfig，dnsproxy 的 selectUpstreams 会优先使用它；未命中才用域名规则和全局上游。

客户端地址还影响：

- IsPrivateClient：公网客户端不能请求本地 DHCP 主机或私有反向记录。
- 私有 RDNS：私有客户端对私有 ARPA 的 PTR/SOA/NS 可走 PrivateRDNSUpstreamConfig，且不使用普通缓存。
- ECS：私网或特殊用途地址不会被自动加入 ECS；公网客户端可按配置加入 ECS，进而影响上游应答和缓存键。
- 查询日志和统计：有 ClientID 时以 ClientID 优先，否则使用匿名前后的 IP。

这些逻辑均在协议无关的 pctx/dctx 字段上运行。DoH 的代理头如果不被信任，不会伪装客户端身份；DoH 路径中的 ClientID 必须通过校验，且 access 与持久客户端查询都使用同一个规范化值。查询日志和统计位于链尾，普通 DHCP 应答、上游响应和过滤响应会到达该阶段；AAAA 禁用、Mozilla canary、healthcheck、DDR 以及公网客户端访问本地 DHCP 主机这类 Finish 路径会提前结束，不记查询日志。

## 5. 一次请求的完整语义转换

### 5.1 UDP

~~~text
UDP datagram
  -> Unpack
  -> DNSContext(ProtoUDP, Req, Addr, Conn, localIP)
  -> private client / generic validation
  -> rate limit, log, access, ClientID(empty)
  -> dnsforward chain
  -> proxy.Resolve / cache / ECS / upstream
  -> scrub to UDP EDNS size
  -> respondUDP
~~~

UDP 没有连接生命周期。入口可在数据报完全无法识别时直接丢弃；一旦已有响应对象，respondUDP 就 Pack 并写回同一地址。速率限制和访问拒绝使用静默丢包以避免放大。

### 5.2 TCP 与 DoT

~~~text
TCP accept                         TLS accept for DoT
  -> per-connection loop
  -> 2-byte length -> ReadFull -> Unpack
  -> DNSContext(ProtoTCP/ProtoTLS, Req, Addr, Conn)
  -> same validation and dnsforward chain
  -> same Resolve/filter result
  -> write 2-byte prefixed response
  -> keep connection until read/write error, timeout, or shutdown
~~~

TCP 与 DoT 的差别只在 listener 是否包装 TLS。进入 DNSContext 后二者共用相同处理函数；DoT 仅额外允许从 TLS SNI 识别 ClientID。请求解析失败不产生 DNS 错误，因为此时长度帧已经破坏或连接状态不可靠，继续复用连接没有意义。

### 5.3 DoH

~~~text
Web server TLS/HTTP2 or HTTP3
  -> public DoH route
  -> Proxy.ServeHTTP
  -> method/content-type/base64 validation
  -> Unpack
  -> real client IP selection
  -> DNSContext(ProtoHTTPS, Req, Addr, HTTPRequest, HTTPResponseWriter)
  -> same validation and dnsforward chain
  -> Pack response body with content-type application/dns-message
~~~

DoH 把 HTTP 层错误和 DNS 层错误分开：HTTP 方法、媒体类型、base64 或 body 错误在入口返回 4xx；只要 DNS 消息成功解包并进入共享链，过滤阻断、NXDOMAIN、REFUSED、SERVFAIL 等仍是正常 HTTP 200 响应体中的 DNS rcode。只有共享链没有留下响应或响应无法 Pack 时，才退化为 HTTP 500。

### 5.4 DoQ

~~~text
QUIC listener with doq ALPN
  -> accept QUIC connection
  -> accept bidirectional stream
  -> read until FIN
  -> detect RFC v1 length prefix or legacy draft
  -> Unpack / DoQ validation
  -> DNSContext(ProtoQUIC, Req, Addr, QUICConnection, Stream, DoQVersion)
  -> same validation and dnsforward chain
  -> write same stream, add prefix for v1
  -> close stream with FIN
~~~

DoQ 把“流”和“连接”两级生命周期区分开：短读通常只结束当前流；DNS 解包失败、EDNS TCP keepalive、非法 0-RTT opcode 等协议违例是致命错误，使用 DOQ_PROTOCOL_ERROR 关闭连接。普通业务响应仍通过同一个流返回。

### 5.5 DNSCrypt

~~~text
DNSCrypt UDP/TCP server
  -> certificate TXT query or encrypted query
  -> decrypt encrypted query
  -> Unpack plain DNS
  -> DNSContext(ProtoDNSCrypt, Req, Addr, DNSCryptResponseWriter)
  -> same validation and dnsforward chain
  -> DNSCrypt encrypt
  -> UDP datagram or TCP length-prefixed encrypted message
~~~

DNSCrypt 的解密层位于共享链之前，因此解密失败不会形成统一 DNS 响应。解密成功后，它与普通 UDP/TCP 使用相同的业务链。访问控制返回 ErrDrop 时，handleDNSRequest 把它转换为“不调用 respond”并向 dnscrypt handler 返回 nil，因此不会产生错误响应。

需要注意一个适配器层面的细节：如果共享 handler 返回错误且 pctx.Res 已经由 proxy.Resolve 设置为 SERVFAIL，dnsproxy 已先通过 DNSCryptResponseWriter 写出该响应；dnscrypt 库的 serveDNS 看到非 nil error 后还会按自身错误兜底再尝试写一个 SERVFAIL。这属于加密响应适配器的错误包装差异，不改变过滤裁决和上游选择；普通 UDP/TCP/DoH/DoQ 的入口只在 handleDNSRequest 中统一 respond 一次。

## 6. 共享逻辑如何保持过滤与转发一致

第一，协议转换在入口层收敛。所有入口最终都提供同一份 *dns.Msg、客户端 netip.AddrPort、协议枚举和必要的响应 writer。dnsforward 的过滤函数只读取 Req、Addr、ClientID 转换后的客户端设置，不读取底层 HTTP、TLS、QUIC 或 UDP socket。

第二，校验使用同一套 MessageConstructor。question 数、ANY、递归、私有 ARPA、SERVFAIL、FORMERR、NOTIMPLEMENTED、NXDOMAIN 都由 dnsproxy 和 dnsforward 统一生成；各协议 responder 只负责序列化。

第三，客户端身份有确定优先级。过滤设置和自定义上游均先查 ClientID，再查 IP；过滤还能通过 DHCP MAC 找到持久客户端。DoH 的代理头只有在直连代理受信任时生效，避免不可信 X-Forwarded-For 改变访问控制、私有网络判断、ECS 或客户端策略。

第四，请求前过滤和响应后过滤都基于同一份 setts。请求阶段可直接生成阻断、Safe Search、CNAME 或 rewrite 响应；未阻断请求在上游响应返回后，还会检查 CNAME、A、AAAA 和 HTTPS hint。也就是说，即使用不同入口收到同一个解析链，最终响应中新增的违规记录仍会被同一策略处理。

第五，上游选择集中在 proxy.Resolve/selectUpstreams。自定义客户端上游、域名专属上游、DS 查询特殊上游、私有 RDNS 上游、fallback、负载均衡、并行和最快地址模式均在协议无关层决定。Proto 不参与上游选择。

第六，缓存、ECS、DNS64、bogus NXDOMAIN 和 TTL 调整集中在 proxy.Resolve 周围。私有 RDNS 不走普通缓存；ECS 影响转发请求和缓存键；DNS64 和 bogus NXDOMAIN 在上游响应后统一改写。入口无法绕过这些步骤，除非请求在更早的访问控制或入口解析阶段被拒绝。

第七，响应尺寸在出口前统一 scrub。非 UDP 按 64KiB 处理，UDP 按请求 EDNS UDP size truncate，并保证请求有 EDNS 时响应也有 OPT 记录。因此截断差异来自 DNS 传输语义，而不是过滤结果差异。

## 7. 协议差异与共享语义对照结论

| 维度 | 协议差异保留在哪里 | 统一共享语义是什么 |
| --- | --- | --- |
| 监听与连接 | UDP 无连接；TCP/DoT 长连接；DoQ 多流；DoH 是 HTTP 请求；DNSCrypt 有独立加密 server | 每个可处理 DNS 消息都进入同一个 requestHandler |
| 握手与加密 | TLS、QUIC TLS、HTTP TLS、DNSCrypt 非对称加解密彼此不同 | 握手/解密失败不进入业务链；成功后统一为明文 *dns.Msg |
| 请求分帧 | UDP 数据报、TCP 2 字节前缀、DoH HTTP body、DoQ stream 前缀、DNSCrypt 加密帧 | 解包成功后只处理同一 Req 结构 |
| 解析失败 | UDP 可能 FORMERR；TCP/DoT 关连接；DoH 4xx；DoQ 协议错误；DNSCrypt UDP 丢包/TCP 关连接 | 失败发生在入口层，不执行过滤或转发 |
| 客户端地址 | DoH 可从受信任代理头提取；其他协议取 socket/QUIC remote | 统一填入 Addr，并计算 IsPrivateClient、访问控制、ECS、客户端策略 |
| ClientID | 仅 DoH 路径/Host、DoT SNI、DoQ SNI 可提供 | 统一放入 context/dnsContext，并优先影响 access、过滤设置、自定义上游、日志和统计 |
| 访问拒绝 | UDP/DNSCrypt 静默丢包；面向连接协议 REFUSED；ClientID 错误统一 SERVFAIL | 都在共享过滤链之前终止，不查询上游 |
| 过滤与重写 | 不按协议选择规则 | 使用同一 DNSFilter、同一 setts、同一请求前/响应后处理 |
| 上游转发 | 上游连接自身可以是 UDP、TCP、DoT、DoH、DoQ、DNSCrypt，但由配置决定 | 客户端入口 Proto 不影响选择；客户端 ID/IP、域名、私有 RDNS、ECS 才影响 |
| 缓存与 ECS | UDP/非 UDP 影响最终截断大小 | ECS 处理、缓存键、私有地址排除逻辑统一 |
| 响应输出 | UDP 数据报、TCP 前缀、HTTP body、QUIC stream、DNSCrypt 加密消息 | 统一响应对象 pctx.Res 和 DNS rcode；各 responder 只负责编码和写出 |
| 连接中断 | 关闭连接、结束流、HTTP 请求失败或忽略 UDP 写错误 | 不改变已经做出的过滤裁决；未送出的响应只记录出口错误 |

最终结论：这些入口面对的连接状态和安全握手完全不同，但架构把差异压缩在 dnsproxy/dnscrypt 的协议适配层。只要请求被成功还原为 DNS 消息并构造出 DNSContext，后续访问控制、客户端识别、过滤、重写、DHCP、私有 RDNS、上游选择、缓存、ECS、DNS64、统计和查询日志就是同一套语义。入口异常可能表现为丢弃、断连、HTTP 4xx/5xx 或 DoQ 错误码；共享 DNS 异常则被转换成统一 rcode，再由各自 responder 写回。这种分层保证了不同协议不会产生不同的过滤或转发策略，只在传输语义要求的地方保留必要的响应形式差异。
