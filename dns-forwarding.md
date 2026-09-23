# DNS 查询是否转发上游：全链路行为分析与排障反推

本文基于当前仓库代码：AdGuardHome 的 `internal/dnsforward` 包 + 依赖库
`github.com/AdguardTeam/dnsproxy@v0.84.2`。目标：回答“一次 DNS 查询在缓存和
过滤之后，是否、以及如何被转发到上游”，区分**配置策略**、**运行时状态**、**网络异常**
三类因素，并给出按现象反推请求路径的排障表。

## 1. 总体架构：四个执行层

一次查询从网卡到客户端依次穿过四层，决定“转不转发上游”的关键变量在各层之间通过
`proxy.DNSContext`（dnsproxy）和 `dnsContext`（AdGuardHome 包装层）共享：

```
客户端
  |  UDP/TCP/DoT/DoH/DoQ/DNSCrypt
  v
[L1] dnsproxy 服务器循环   server*.go -> (*Proxy).handleDNSRequest
      +- validateRequest（协议级前置校验）
  v
[L2] 中间件链（顺序固定，见 config.go:370 的 RequestHandler）
      ratelimit -> logMiddleware -> Server.Wrap（ClientID / 访问控制）-> 业务 Handler
  v
[L3] AdGuardHome 处理管线   Server.ServeDNS（requesthandler.go:18）
      processInitial
      processDDRQuery
      processDHCPHosts
      processDHCPAddrs
      processFilteringBeforeRequest   <- 请求级过滤（可直接生成响应）
      processUpstream                 <- 在这里调用 proxy.Resolve
      processFilteringAfterResponse   <- 响应级过滤
      ipset.process
      processQueryLogsAndStats
  v
[L4] (*Proxy).Resolve（dnsproxy proxy.go:881）
      ECS/DO -> pendingRequests 单飞 -> replyFromCache -> replyFromUpstream
      -> 缓存写回 -> AD/DO 过滤 -> scrub
  v
(*Proxy).respond 按协议编码回包
```

关键点：**过滤发生在缓存之前**。请求级过滤在 [L3] 就可能设置 `pctx.Res`，此后
`processUpstream` 看到 `pctx.Res != nil` 会直接跳过整个 [L4]（process.go:398
的首个分支），既不查缓存也不发上游；反之，缓存命中的查询也不会再走响应级过滤。

## 2. 贯穿各阶段的共享状态

`dnsContext`（process.go:24）是每个查询独立分配的对象，其字段就是各阶段之间的
“共享状态”：

| 字段 | 写入阶段 | 读取阶段 | 含义 |
|---|---|---|---|
| `setts` | processInitial（按客户端合并设置） | 请求过滤、响应过滤 | 本次查询生效的过滤配置快照 |
| `protectionEnabled` | processInitial 调 `UpdatedProtectionStatus` | filterAfterResponse | 保护总开关的运行时状态（含暂停倒计时恢复） |
| `result` | processFilteringBeforeRequest | 响应后过滤、querylog | 过滤匹配结果（原因、规则、CNAME/IP） |
| `proxyCtx.Res` | 几乎每个阶段 | 后续所有阶段 | 一旦被赋值，processUpstream 等阶段短路 |
| `origQuestion` | filterDNSRequest（CNAME 改写时） | processFilteringAfterResponse | 改写后查询需在回包恢复原问题 |
| `origResp` | filterDNSResponse | querylog（OrigAnswer） | 响应级过滤命中时保留原始应答 |
| `isDHCPHost` | processDHCPHosts | processUpstream | 决定未命中时回 NXDOMAIN 还是继续 |
| `responseFromUpstream` | processUpstream | filterAfterResponse | 只有真正上游应答才做响应级过滤 |
| `responseAD` | processUpstream | querylog | 上游应答的 AD 位 |
| `clientID` | processInitial（由 [L2] 从 SNI/DoH 路径提取） | setCustomUpstream、过滤设置、日志 | 影响客户端专属上游与策略 |
| `err` | 任一处理函数 | ServeDNS | resultCodeError 时作为 Handler 错误返回 |

管线控制语义（requesthandler.go:41-54）：`resultCodeSuccess` 继续下一阶段；
`resultCodeFinish` 立即正常结束（通常已设置 `pctx.Res`，个别路径连 querylog 都不记）；
`resultCodeError` 立即返回 `dctx.err`，后续过滤、ipset、统计日志全部跳过。

## 3. L1/L2：查询在进入业务管线前被拦截的路径

这些路径**都不会触碰缓存或上游**，属于配置策略/运行时治理：

1. `validateRequest`（dnsproxy proxy.go:946）：问题数不为 1 -> FORMERR；
   `RefuseAny=true` 的 ANY 查询 -> NOTIMPLEMENTED；递归检测器命中 -> NXDOMAIN；
   外网客户端查询私网 PTR/SOA/NS（`isForbiddenARPA`）-> NXDOMAIN。
2. 速率限制中间件（config.go:347 构造；dnsproxy `ratelimit` 包）：UDP 超额 ->
   `proxy.ErrDrop`，**不回任何包**（防放大攻击）；TCP/DoT/DoH 不受限。
3. `Server.Wrap`（middleware.go:21）：
   - ClientID 解析失败（DoT/DoQ SNI、DoH 路径、StrictSNI 校验）-> 直接 SERVFAIL，
     业务管线不执行；
   - `IsBlockedClient` 命中客户端封禁，或 `isBlockedHost` 命中域名封禁 ->
     UDP/DNSCrypt 返回 `ErrDrop`（无响应、连接丢弃），TCP/DoT/DoH/DoQ 返回
     REFUSED（middleware.go:46-56）。

## 4. L3 业务管线：逐阶段行为

### 4.1 processInitial（process.go:87）

- `AAAADisabled=true`（配置策略）且 QTYPE=AAAA -> 合成 NODATA，Finish，不上游。
- `use-application-dns.net.`（Firefox DoH canary）-> 合成 NXDOMAIN，Finish。
- `healthcheck.adguardhome.test.` -> 空应答，Finish。
- 记录 clientID；调 `UpdatedProtectionStatus`（config.go:842）取保护状态：这是
  **运行时状态**——保护可被 API 暂停到某时刻，到期后第一次查询通过 CAS 去重触发异步
  恢复 goroutine（避免写锁冻结查询），本次查询即按已恢复处理。
- 调 `clientRequestFilteringSettings`：以全局 `dnsFilter.Settings()` 为底，按
  “客户端 IP + ClientID”叠加客户端级设置，生成每请求独占的 `setts` 快照。

### 4.2 DDR / DHCP（process.go:153、256、302）

- `HandleDDR=true` 时对 `_dns.resolver.arpa.` 的 SVCB 查询本地合成应答。
- DHCP 主机名（本地区域后缀的 A/AAAA）：非内网客户端 -> NXDOMAIN 且 **Finish
  （不进 querylog）**；内网客户端且有租约 -> 本地 A 记录（AAAA 且开 DNS64 时返回映射
  地址）；无租约记录则继续（后续可能被 dnsrewrite 改写或走域名专属上游），此时
  `isDHCPHost=true`。
- 私网 PTR 命中 DHCP 租约 -> 本地合成 PTR。注意 `RequestedPrivateRDNS` 非空时
  processFilteringBeforeRequest 会强制关闭 parental/safebrowsing/safesearch/services
  规则（process.go:338-343）。

### 4.3 processFilteringBeforeRequest / filterDNSRequest（filter.go:31）

若 `pctx.Res` 已被前面阶段设置则直接放行。否则在 `serverLock.RLock` 保护下调
`dnsFilter.CheckHost`：

- 检查器内部错误（如 SafeBrowsing/Parental 查询失败等 `CheckHost` 错误）-> 置
  `dctx.err`，**resultCodeError**。此时通常没有 `pctx.Res`，UDP 表现为客户端收不到
  回包（超时）——这是排障时容易误判为“上游丢包”的一个内部故障点。
- `res.IsFiltered`（黑名单/parental/safebrowsing/服务拦截）-> 由
  `genDNSFilterMessage`（msg.go:58）按**配置的 blocking mode** 合成响应：NullIP ->
  空应答或 0.0.0.0，NXDOMAIN 模式 -> NXDOMAIN，REFUSED -> REFUSED，CustomIP -> 配置 IP；
  非 A/AAAA/HTTPS 类型一般为 NODATA。**短路：不上游、不缓存**（根本没进入 [L4]）。
- Rewrite 且只拿到 CNAME（无 IP）-> 把请求问题名改成 CanonName，保存
  `origQuestion`，继续上游解析新名字（filter.go:42-46）；响应回来后在
  processFilteringAfterResponse 恢复原问题并把 CNAME 拼到应答前面（process.go:442-457）。
- Rewrite 且带 IP（Rewritten/RewrittenAutoHosts/RewrittenRule/FilteredSafeSearch）->
  本地合成 CNAME+IP 或 dnsrewrite 应答，短路。
- 无匹配 -> 继续。

### 4.4 processUpstream（process.go:389）

1. `pctx.Res != nil` -> 直接成功（前面任何阶段合成的应答都从这里穿过）。
2. `isDHCPHost=true` 且没有应答 -> 合成 NXDOMAIN，Finish（代码 TODO 注明将来才可能
   走本地区域专属上游）。
3. `setCustomUpstream`（process.go:443）：按 clientID+IP 在 `ClientsContainer` 查
   **客户端级自定义上游配置**，挂到 `pctx.CustomUpstreamConfig`。这是运行时按客户端
   改变路由目标的机制，并连带影响缓存的选择（见 5.1）。
4. `s.proxy()` 取当前 proxy 指针（读锁）；若为 nil（服务器正在停止/重配置）-> 返回
   `srvClosedErr`，**resultCodeError**。这是“重配置窗口内查询失败”的典型原因
   （Reconfigure 会先 stop 再重建 proxy，dnsforward.go:848）。
5. 调 `prx.Resolve(ctx, pctx)`（见第 5 节）。返回错误 -> resultCodeError，但注意：
   多数网络失败场景下 [L4] 已把 `pctx.Res` 置为 SERVFAIL，所以**客户端仍会收到
   SERVFAIL**；错误同时被各协议 packet loop 记录。
6. 成功后置 `responseFromUpstream=true`，记录 `responseAD`。这两个标记决定后续
   是否做响应级过滤与日志字段。

### 4.5 processFilteringAfterResponse（process.go:466）

- `NotFilteredAllowList`（白名单放行）-> 完全跳过响应检查。
- Rewrite/SafeSearch 类结果 -> 恢复原问题、拼接 CNAME 链。
- 其余走 `filterAfterResponse`（process.go:491）：**只有
  `protectionEnabled && responseFromUpstream` 同时为真**才扫描应答里的
  CNAME/A/AAAA/HTTPS（含 SVCB hint；AAAA 禁用时剥离 v6 hint）。命中规则则用
  `genDNSFilterMessage` 替换应答、原应答存入 `origResp`（querylog 可见
  OrigAnswer）。因此“保护被暂停”或“应答非上游来源”时，应答内容原样返回。
- 过滤应答出错 -> resultCodeError。

随后 `ipset.process` 把匹配的 IP 写入 ipset；`processQueryLogsAndStats` 在
`serverLock.RLock` 下按客户端配置决定是否记 querylog/统计。以 Finish 结束的查询
（访问封禁、外网 DHCP 主机名等）不会进入这里。

## 5. L4：缓存、并发去重与上游交换

`(*Proxy).Resolve`（dnsproxy proxy.go:881）是唯一真正可能发出网络请求的地方。

### 5.1 是否使用缓存：cacheWorks（proxy.go:976）

以下情况缓存完全旁路（不读、不写，也不做单飞）：
- 客户端自定义上游配置存在但其私有 cache 为 nil（防全局缓存污染，dnsproxy
  issue #169）；
- 全局 cache 也为 nil（`CacheEnabled=false`，默认配置见 dnsforward.go:760）；
- `RequestedPrivateRDNS` 非空（本地 PTR 不缓存）；
- 请求带 CD（Checking Disabled）位（防未校验应答污染缓存）。

缓存对象按上下文选择：自定义上游自带 cache 时用它，否则用全局 cache
（proxycache.go:9）。TTL 会再受 `CacheMinTTL/CacheMaxTTL` 钳制（config.go:363）。

### 5.2 单飞：pendingRequests（pending.go）

缓存启用时，每个查询先按“问题 + ECS”算 key 入 pending 表（`LoadOrStore`）：
- 第一个查询成为 leader，继续走缓存/上游；
- 相同 key 的并发查询阻塞在 `finish` channel 上，leader 结束后共享其 `Res`
  （按各自请求重新 SetReply 的拷贝）、`Upstream`、统计与错误（pending.go:80-88）。

这是并发一致性的第一道机制：**同一时刻对同一域名的 N 个查询只向上游发一次**，
等待者看到的是同一份判定，不会出现一部分客户端拿到成功应答、另一部分拿到
SERVFAIL。该机制由 `PendingRequestsEnabled` 控制（config.go:368），关闭后同 key
查询会各自独立访问上游。

### 5.3 缓存命中与乐观缓存（proxycache.go:19）

- 命中（启用 ECS 时先查 subnet cache）-> 复用缓存消息与统计，随后只做 AD/DO 位
  过滤和 scrub，**立即返回，不发上游**。
- 乐观缓存（`CacheOptimistic`）开启且条目已过期：仍立即把旧应答返回客户端
  （TTL 改写为 `CacheOptimisticAnswerTTL`，受 `CacheOptimisticMaxAge` 限制），
  同时 `go p.shortFlighter.resolveOnce(...)` 用缩减克隆上下文异步刷新（含
  CustomUpstreamConfig、ECS 与请求的拷贝，避免数据竞争）。现象：TTL 到期后第一个请求
  秒回旧数据，稍后的请求才拿到新数据；异步刷新失败只在日志留痕，客户端无感知。

### 5.4 选择上游：selectUpstreams（proxy.go:741）

优先级：私网 RDNS（仅私网客户端 + PTR/SOA/NS，走 `privateRDNSUpstreamConfig`，并把
请求加入递归检测器）-> 客户端 CustomUpstreamConfig 的域名规则（命中即用）-> 全局
UpstreamConfig 的域名规则（`[/domain/]` 专属上游，否则默认组）；QTYPE=DS 时改用 DS
专用选择。**配置策略在这里决定“发给谁”**。

选不出任何上游（例如只有 [/特定域名/] 配置而该域名不匹配、自定义配置无此域）->
合成 NXDOMAIN 并返回 `upstream.ErrNoUpstreams`（proxy.go:767-771）。这是一个
“NXDOMAIN + 错误日志（selecting upstream）”的组合现象，不是网络失败。

### 5.5 与上游交换：exchangeUpstreams（dnsproxy exchange.go:16）

由 `UpstreamMode`（config.go setProxyUpstreamMode）决定策略：

- `UpstreamModeParallel`：`upstream.ExchangeParallel`。给**每个**上游复制一份请求
  （`req.Copy()`，注释明确说明 dns.Client 会就地修改请求，防止数据竞争）并发发送，
  带缓冲 channel 收结果；主循环按完成顺序收够 N 个结果，**第一个成功应答立即返回**，
  其余 goroutine 的结果被丢弃（见第 6 节）。全部失败才报错，其中 `ErrNoReply`
  （上游返回 nil 应答）不计入错误列表；若所有上游都是 nil 应答，返回固定错误
  “none of upstream servers responded”，否则 errors.Join 各上游错误
  （upstream/parallel.go:24-66）。
- `UpstreamModeLoadBalance`（默认）：按历史 RTT 计算权重（`calcWeights`，
  rttLock 保护）加权随机挑选顺序，**逐个串行尝试**：成功即返回并更新 RTT；失败按
  `defaultTimeout` 惩罚该上游权重并尝试下一个；全部失败才返回
  “all upstreams failed to exchange request”。只有一个上游时直接交换。
- `UpstreamModeFastestAddr`：仅对 A/AAAA 生效。调 `ExchangeAll` **等所有上游
  应答到齐**（同样全部失败才报错，部分失败保留成功应答），汇总全部 IP 后 TCP ping
  80/443 选出最快 IP，过滤应答只保留最快地址；ping 超时则用第一个应答兜底
  （fastip/fastest.go:94）。其他 QTYPE 退回 LoadBalance。

### 5.6 交换结果的后处理（proxy.go:775-856）

- DNS64（`UseDNS64`）：A 查询无 AAAA 等条件下追加合成查询，改写应答来源上游。
- BogusNXDomain：应答 IP 命中配置的 bogus 网段 -> 改回 NXDOMAIN（配置策略，客户端
  现象是 NXDOMAIN，但上游实际返回了 IP）。
- **Fallback**：仅当交换出错 `err != nil` 且查询不是私网 RDNS 且配置了
  `fallbacks` 时，改为对 fallback 上游组并行交换。即“主上游全挂 -> 自动走备用”，
  成功时客户端无异常，日志中 src=fallback。
- `handleExchangeResult`：resp 为 nil 或问题数不为 1 -> **合成 SERVFAIL**；否则
  设置 `d.Upstream`、去掉 AA 位、施加 min/max TTL。
- 回到 Resolve：只有 `ok`（真从上游拿到应答）且应答不带 CD 位才写缓存
  （proxy.go:927）；SERVFAIL/NXDOMAIN 这类失败合成结果 `ok=false`，**不缓存**。

### 5.7 回到客户端

`handleDNSRequest`（server.go:79）在 Handler 返回后统一调 `respond`：
`pctx.Res==nil` 时 UDP `respondUDP` 直接什么都不发（serverudp.go:190）；各协议
响应时再处理截断/压缩。ServeDNS 末尾会对非 nil 应答置 `Compress=true`
（requesthandler.go:56-58）。

## 6. 并发查询与部分上游失败的一致性

系统用四层机制保证“同一时刻并发查询”结果不发散：

1. **单飞去重（pendingRequests）**：缓存开启时，相同 (QNAME,QTYPE,QCLASS,ECS) 的并发
   查询合并为一次上游交换，等待者复制 leader 的应答与错误（5.2）。
2. **并行模式的“首胜返回”**：`ExchangeParallel` 中每个上游独立 goroutine，请求各拿
   副本，结果写入容量=上游数的 channel；只要有一个上游先回成功应答，本次查询立即
   采用它，其它慢/失败 goroutine 不影响本次结果。部分上游失败时：先成功者胜；若成功
   者晚于失败者返回，失败只被收集进 errs 后继续等；只有全部失败才把合并错误抛出，
   最终由 5.6 转为 SERVFAIL。上游超时/拒绝连接/协议错误等网络异常都在此收敛，单条
   错误以 “exchange failed” 记录并带上游地址与耗时（exchange.go:67-83）。
3. **负载均衡模式的加权重试**：失败的上游被计入惩罚 RTT，本次查询立刻转下一个上游；
   后续查询通过权重自然避开故障上游，形成运行时自适应——这是**网络异常沉淀为运行时
   状态**的例子（`upstreamRTTStats`，仅内存，重启清零）。
4. **共享对象加锁/复制**：全局配置与过滤引擎经 `serverLock`（读写锁）保护，过滤、
   统计、客户端容器读取都在 RLock 下；RTT 有 rttLock；跨 goroutine 传递 DNSContext/消息
   一律 Copy（并行交换、乐观刷新、pending 克隆三处都如此），避免共享 *dns.Msg 被并发
   改写。Reconfigure 走写锁全量重建，临界窗口内查询拿不到 proxy 时收到 srvClosedErr。

注意不一致仍然可能出现的边界：
- 关闭 `PendingRequestsEnabled` 后，并发同 key 查询各自走上游，可能分别命中不同
  上游的不同应答（Parallel 模式尤其明显）；
- FastestAddr 模式下部分上游失败时，参与 ping 的 IP 集合变小，选出的“最快 IP”可能与
  全量时不同；
- 乐观缓存返回的是过期数据，与此刻上游真实结果可能不一致，这是有意的可用性取舍。

## 7. 三类因素对照

| 类别 | 典型项 | 生效位置 | 对“是否上游/回什么”的影响 |
|---|---|---|---|
| 配置策略 | AAAADisabled、RefuseAny、HandleDDR、UsePrivateRDNS、blocking mode、域名专属上游、UpstreamMode、BogusNXDomain、fallback、access 黑白名单、ratelimit | 启动/Reconfigure 时固化到 proxy.Config 与 ServerConfig | 决定短路应答、上游选择、交换模式、应答改写 |
| 运行时状态 | protectionEnabled（含暂停倒计时）、客户端 setts/ClientID/自定义上游、DHCP 租约、RTT 权重、缓存条目（含乐观过期）、pending 表、Reconfigure 窗口、dnsProxy 指针 | 每查询实时计算/内存维护 | 同一配置下不同客户端、不同时刻可走不同路径 |
| 网络异常 | 上游超时/连接拒绝/无应答(ErrNoReply)/报文畸形、bootstrap 失败、客户端写回失败、过滤引擎后端查询失败 | Exchange/ExchangeAll/ExchangeParallel、filterDNSRequest | 全失败->SERVFAIL；部分失败->按模式重试或首胜；无上游->NXDOMAIN；内部错误->无回包 |

## 8. 排障反推表：从现象到实际路径

### 8.1 按客户端收到的响应

| 现象 | 最可能的路径 | 验证方式 |
|---|---|---|
| UDP 查询完全无响应（超时），TCP 正常 | 客户端或域名命中 access 封禁 / 超过 ratelimit（均 ErrDrop，仅 UDP/DNSCrypt 丢包） | 日志 “request is in access blocklist”；ratelimit 仅作用 UDP |
| 任何协议都无响应（连错误包都没有） | filterDNSRequest/checker 返回内部错误（resultCodeError 且 Res 为 nil），或重配置窗口 srvClosedErr | 查 dnsforward 错误日志与保护服务（SafeBrowsing 等）连通性；确认是否刚执行 Reconfigure |
| SERVFAIL | ClientID/SNI 校验失败（L2 直接生成）；或所有上游交换失败、resp=nil 被 handleExchangeResult 合成；单个上游配置时该上游故障 | dnsproxy 日志 “exchange failed”+“resolving err”；querylog 结果为 SERVFAIL |
| NXDOMAIN | 上游真实 NXDOMAIN；无匹配上游（ErrNoUpstreams，日志 “selecting upstream”）；bogus_nxdomain 改写；外网客户端查私网 PTR；DHCP 主机无租约(isDHCPHost)；Firefox canary；拦截模式配置为 NXDOMAIN | 看 querylog 的 Reason/规则；日志 src 与 bogus 提示 |
| REFUSED | access 拦截发生在 TCP/DoT/DoH/DoQ（UDP 同条件是无响应）；或拦截模式 REFUSED | 对照客户端协议与 access 设置 |
| NODATA/空应答 | AAAA 被禁用；healthcheck；NullIP 模式（非 A/AAAA/HTTPS 类型一律 NODATA）；SafeSearch 无该地址族结果；本地 DHCP/DDR 合成 | querylog 中无上游、Reason 为拦截类 |
| A 应答为 0.0.0.0/:: 或自定义 IP | 请求级过滤命中，按 NullIP/CustomIP 模式合成，**未访问上游、未查缓存** | querylog Reason=FilteredBlocked 等 |
| 应答秒回且 TTL 异常固定/与上游不符 | 缓存命中；或乐观缓存返回的过期条目（TTL=CacheOptimisticAnswerTTL） | dnsproxy debug “replying from cache”；随后日志出现 “resolving request for optimistic cache” |
| 应答可用但日志 src=fallback | 主上游全部失败后 fallback 组成功 | “using fallback” 日志；查主上游健康 |
| 应答里 AAAA/HTTPS v6 hint 被剥除 | AAAADisabled 影响 filterHTTPSRecords | 同域名 A 查询不受影响可对照 |
| CNAME 与问题名不一致/被改写 | dnsrewrite/rewrite-only-CNAME 路径：问题名被改写后送上游，回包恢复原问题并前置 CNAME | origQuestion 非空；querylog 显见 CNAME 链 |

### 8.2 按上游与并发行为

| 现象 | 判定 |
|---|---|
| 多个上游中一个持续故障但查询正常 | Parallel：首胜即返回，慢/坏结果被丢弃；或 LoadBalance：串行重试成功，故障上游 RTT 被惩罚降权 |
| 上游恢复后流量缓慢回流 | LoadBalance 权重由历史平均 RTT 决定，需要成功交换逐步更新（updateRTT） |
| 并发突发同一域名只有一条上游请求 | PendingRequests 生效，其余在 finish channel 等同一结果；返回 SERVFAIL 则全部 SERVFAIL，结果一致 |
| 并发同一域名出现两种不同应答 | PendingRequests 被关闭、或 ECS 不同导致 key 不同、或缓存旁路条件成立（CD 位/私网 PTR/自定义上游无 cache） |
| FastestAddr 偶发返回的 IP 集合变化 | 部分上游本次失败，ExchangeAll 仅用成功应答的 IP 参与 ping；pingWaitTimeout 后迟到结果不采用但入 fastip 缓存 |
| 主上游挂时偶发一次慢查询后恢复正常 | fallback 仅在主组全部出错时启用；或乐观缓存先回旧值、后台刷新 |

### 8.3 日志关键字速查

- “not caching” + reason：缓存被旁路的具体原因（自定义上游无 cache / 私网地址 / CD 位）。
- “replying from cache”（general cache/subnet cache）：本次未触达上游。
- “exchange failed”：单个上游网络级失败（含地址与耗时）；只有它而无最终 SERVFAIL 说明
  被并行/重试/fallback 掩盖。
- “all upstreams failed”（LoadBalance）/ errors.Join 多上游错误（Parallel）：客户端将收到
  SERVFAIL。
- “using fallback”：主上游组全部失败，走了备用组。
- “resolving request for optimistic cache”：乐观缓存后台刷新；其失败不影响已返回的应答。
- “request is in access blocklist” / ratelimit 日志：UDP 无响应类问题的首要嫌疑。
- “protection is restarted after pause”：保护暂停到期自动恢复，前后查询路径会变化。

## 9. 一页速记

1. 过滤先于缓存：被拦截/改写的查询根本不进缓存与上游；缓存命中的查询也不再过滤。
2. 是否发上游只看三点：`pctx.Res` 是否已被合成、缓存是否命中、`isDHCPHost` 特例。
3. 发给谁由配置决定（域名规则/客户端自定义/私网 RDNS），怎么发由 UpstreamMode 决定，
   失败怎么办由 fallback + SERVFAIL 兜底。
4. 并发一致性靠 pending 单飞 + 每上游请求副本 + 首胜/重试策略 + 锁与拷贝；关闭单飞
   或缓存旁路条件下结果可能发散。
5. 排障先看客户端拿到什么（无包/SERVFAIL/NXDOMAIN/REFUSED/合成 IP），再对照第 8 节
   反推阶段，最后用 8.3 的日志关键字坐实。
