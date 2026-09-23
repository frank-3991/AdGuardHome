# DNS 查询是否转发到上游：完整路径与排障反推

本文基于当前仓库的 internal/dnsforward，以及 go.mod 固定的 github.com/AdguardTeam/dnsproxy v0.84.2。结论按实际调用顺序整理，重点区分配置策略、每请求运行时状态、共享运行时状态和网络异常。

## 1. 先给结论

一次查询只有在以下条件全部成立时才会进入上游交换：

1. 消息能通过 dnsproxy 的入站校验。
2. 没有被限流、访问控制、保留主机名等中间件直接丢弃或拒绝。
3. 没有被 AdGuard Home 的本地策略提前生成响应，例如禁用 AAAA、DDR、健康检查、Firefox DoH 关闭域名、DHCP 本地记录、请求前过滤或重写。
4. 到达 processUpstream 时 proxy.DNSContext.Res 仍为 nil，且不是未由 DHCP/过滤处理的本地 DHCP 主机名。
5. proxy.Resolve 中没有命中缓存，也没有作为 pending_requests 的重复请求等待首个请求完成。
6. selectUpstreams 能为当前域名、客户端和私有 RDNS 场景选出至少一个上游。

即使已经走到上游交换，结果也不一定来自主上游：

- 主上游全部发生传输或协议交换错误时，公有查询可能改走 fallback。
- 主上游返回合法 DNS rcode，包括 NXDOMAIN、NODATA、SERVFAIL，不属于 Go 交换错误，不会触发 fallback。
- 并行模式只要任一上游返回非 nil 响应，当前请求立即采用该响应；其余 goroutine 不阻塞当前请求，也不会把答案混合进来。
- 最快地址模式会等待所有 DNS 交换结束并合并 IP，再通过 TCP ping 选择一个地址；个别 DNS 上游失败但至少一个成功时仍可成功。
- 上游响应先写入 dnsproxy 缓存，随后 AdGuard Home 才做响应过滤。因此后续缓存命中也可能在 AdGuard 阶段被改写成拦截响应。

## 2. 入站到响应的实际时序

### 2.1 监听器和外层 dnsproxy

UDP、TCP、DoT、DoH、DoQ、DNSCrypt 都先构造独立的 proxy.DNSContext，再进入 /Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go 第 79 行的 Proxy.handleDNSRequest：

1. 标记客户端是否属于私有网络。
2. validateRequest 提前处理：question 数量不为 1 返回 FORMERR；refuse_any=true 且 qtype 为 ANY 返回 NOTIMPLEMENTED；递归检测命中返回 NXDOMAIN；公网客户端请求私有 ARPA 返回 NXDOMAIN。
3. 通过后执行处理器链 ratelimit -> log -> Server.Wrap -> Server.ServeDNS，装配位置见 internal/dnsforward/config.go 第 359 行。
4. handleDNSRequest 最后调用 respond 写回客户端；处理器返回 proxy.ErrDrop 时不响应。

这一层产生的响应不会进入 AdGuard Home 模块链，因此通常没有 AdGuard 查询日志和统计。

### 2.2 中间件：限流、ClientID 和访问控制

internal/dnsforward/middleware.go 第 24 行的 Server.Wrap 在 AdGuard 业务模块前执行：

- 解析 DoH path、DoT/DoQ SNI 中的 ClientID。解析失败时设置 SERVFAIL 并返回 nil，外层会把该 DNS 响应写回。
- 客户端 IP、CIDR 或 ClientID 命中访问控制时调用 serveBlockedResponse：UDP 和 DNSCrypt 返回 ErrDrop，客户端表现为超时或无响应；TCP、DoT、DoH、DoQ 返回 REFUSED。
- BlockedHosts 中的查询名按同样策略阻断。
- 限流中间件也返回 ErrDrop，因此 UDP 被限流时同样是无响应，而不是 DNS rcode。

### 2.3 AdGuard Home 的每请求上下文

internal/dnsforward/requesthandler.go 第 18 行的 Server.ServeDNS 为每个请求新建独立的 dnsContext：

- proxyCtx：当前请求的 proxy.DNSContext。
- setts：本请求使用的过滤设置快照。
- result：请求前/响应后过滤结果。
- origResp：响应过滤前的原始答案，用于查询日志。
- origQuestion：CNAME 重写前的原始 question。
- protectionEnabled：本请求开始时看到的保护开关。
- responseFromUpstream：proxy.Resolve 成功返回后置 true。
- responseAD：记录所选响应的 AD 位。
- clientID、startTime、isDHCPHost。

模块顺序固定：

```text
processInitial
processDDRQuery
processDHCPHosts
processDHCPAddrs
processFilteringBeforeRequest
processUpstream
processFilteringAfterResponse
ipset.process
processQueryLogsAndStats
```

resultCodeSuccess 进入下一模块；resultCodeFinish 停止后续模块但当前 Res 仍写回；resultCodeError 停止后续模块并返回错误。

### 2.4 本地策略提前响应

internal/dnsforward/process.go 第 104 行的 processInitial 处理：

- aaaa_disabled=true 的 AAAA：本地 NODATA，不查缓存、不查上游。
- use-application-dns.net. 的 A/AAAA：本地 NXDOMAIN。
- healthcheck.adguardhome.test.：本地空成功响应。
- 读取保护状态和客户端过滤设置。

handle_ddr=true 时，processDDRQuery 对 _dns.resolver.arpa. 生成本地 SVCB。

DHCP 阶段有三类结果：公网客户端查询本地 DHCP 主机名直接 NXDOMAIN，且代码明确不入查询日志；私网客户端命中 DHCP A/AAAA 租约直接构造 A 或 DNS64 AAAA；私有 ARPA 命中 DHCP PTR 租约直接构造 PTR。

若识别为本地 DHCP 主机名但没有租约，也没有被过滤规则处理，processUpstream 第 465 行会直接返回 NXDOMAIN 并 Finish，不会转到普通公共上游。

### 2.5 请求前过滤和重写

internal/dnsforward/filter.go 第 28 行的 filterDNSRequest 调用 dnsFilter.CheckHost。它可能：

- 命中黑名单、安全浏览、家长控制、安全搜索、阻断服务：生成拦截响应，后续不再查缓存或上游。
- 命中 legacy rewrite、/etc/hosts 或 $dnsrewrite，且规则直接提供记录：生成本地响应。
- 命中只给 CNAME、不直接给 IP 的重写：把当前发往 proxy.Resolve 的 question 改成 CNAME 目标，同时保存原 question，上游响应回来后再恢复原 question 并在答案前插入 CNAME。
- 命中 allowlist：本请求继续转发，且响应后过滤直接跳过。

AdGuard 的请求前过滤发生在 dnsproxy 缓存查找之前。所以一个域名即使已有缓存，仍可能先被请求前规则拦截。

### 2.6 proxy.Resolve：ECS、pending、缓存和上游

只有 pctx.Res == nil 时才进入 processUpstream。它先按客户端 ClientID/IP 注入自定义上游，再调用同一个 dnsproxy 实例的 Resolve。

Resolve 的顺序是：

```text
processECS
calcFlagsAndSize
判断 cacheWorks
  addDO
  pending.queue
  replyFromCache
replyFromUpstream
cacheResp
filterMsg/scrub
```

关键点：

- 缓存在这里才查，不在 AdGuard 请求前过滤之前。
- pending_requests.enabled=true 时，重复请求在缓存查找前等待首个请求；它复制首个请求的 Res、Upstream 和统计，不再自行访问上游。
- 缓存命中时 Resolve 返回 nil，因此 AdGuard 的 responseFromUpstream 也会是 true。AdGuard 不用这个字段区分缓存；真正的缓存证据是 pctx.Upstream == nil 且 QueryStatistics 中 IsCached=true。
- 缓存保存的是上游原始响应，发生在 AdGuard 响应过滤之前。缓存命中后 AdGuard 仍会重新执行响应过滤。

### 2.7 上游选择

dnsproxy 的 selectUpstreams 优先级是：

1. 私有 RDNS 或 DNS64 反查场景：仅私有客户端且启用 use_private_ptr_resolvers 时使用私有 RDNS 上游；私有查询不使用 fallback。
2. 当前客户端的自定义上游配置。
3. 全局上游配置。

全局和自定义配置内部再按域名规则选择：精确域名和最长后缀匹配优先；[/example.com/] 可保留域名及其子域；[/*.example.com/] 只匹配子域；[/example.com/]# 可把某域排除回默认上游；DS 查询会去掉最左标签后选择父域策略。

如果选不出上游，replyFromUpstream 生成 NXDOMAIN 并返回 upstream.ErrNoUpstreams。该请求会带错误返回，AdGuard 后续模块停止。

### 2.8 上游交换和 fallback

replyFromUpstream 调用 exchangeUpstreams，随后依次做：

1. DNS64 补充合成。
2. bogus_nxdomain 命中时把答案改写成 NXDOMAIN。
3. 主上游交换失败且不是私有查询、且配置了 fallback 时，并行查询 fallback。
4. handleExchangeResult：响应为 nil 或 question 数不为 1 时生成 SERVFAIL；合法响应清 AA、应用最小/最大 TTL，并写回 d.Res 和 d.Upstream。

网络或协议错误包括拨号失败、超时、连接关闭、TLS/QUIC/HTTP 传输失败、响应 question 与请求不一致等。普通 DNS rcode 不视为错误：

- 上游 SERVFAIL：只要消息格式合法就直接返回，可按 TTL 缓存，不触发 fallback。
- 上游 NXDOMAIN 或 NODATA：直接返回，符合负缓存条件时缓存。
- 所有主上游都超时或断连：才查询 fallback。
- fallback 也全部失败：得到本地生成的 SERVFAIL 和非 nil 错误。

明文 UDP 上游收到截断响应或 question 不匹配响应时，上游客户端会先自行重试 TCP；这仍失败才计入交换错误。

### 2.9 响应后过滤、ipset、日志和最终发送

AdGuard 在 filterDNSResponse 中检查答案里的 CNAME、A、AAAA 和 HTTPS/SVCB hint。命中阻断时：

- dctx.result 改成阻断原因。
- dctx.origResp 保存原始响应。
- pctx.Res 替换成拦截消息。

响应后过滤只在本请求保护开启并且 Resolve 成功返回时执行。缓存命中也满足后者，所以缓存响应仍会被当前过滤规则复查。

之后 ipset 只处理 responseFromUpstream=true 的 A/AAAA/ANY 答案。最后查询日志和统计读取同一个 pctx.Res、dctx.result、dctx.origResp、pctx.Upstream 和 QueryStatistics，因此正常完成链路上的客户端响应、日志和统计使用同一份选定结果。

最终由外层 respond 按协议发送：UDP 无响应可静默，写失败只记录日志；TCP/DoT 在 Res=nil 时关闭连接；DoH 在 Res=nil 时返回 HTTP 500；DoQ 在 Res=nil 时以内部错误关闭 QUIC。因此“服务端处理完成”和“客户端实际收到 DNS 响应”还隔着一次协议写入。

## 3. 配置策略、运行时状态和共享对象

| 类型 | 状态/策略 | 作用范围 | 对路径和结果的影响 |
| --- | --- | --- | --- |
| 配置策略 | upstream_dns、域名专属上游、fallback_dns、upstream_mode | 全局 Proxy 或客户端自定义配置 | 决定候选上游、顺序/并发方式、失败后是否 fallback |
| 配置策略 | cache_enabled、cache_size、min/max TTL、optimistic TTL/max_age | 一个全局 cache 或一个自定义客户端 cache | 决定是否查缓存、缓存多久、过期后是否先返回旧答案 |
| 配置策略 | enable_dnssec、edns_client_subnet | Proxy 和 cache key | 决定是否给上游加 DO，ECS 还会改变缓存/pending key |
| 配置策略 | 过滤总开关、保护开关、客户端过滤、规则列表 | dnsFilter 和每请求 setts | 决定请求前是否拦截/重写，以及上游答案是否再被过滤 |
| 配置策略 | aaaa_disabled、refuse_any、handle_ddr、bogus_nxdomain、DNS64、私有 RDNS、访问控制 | 不同层级 | 可在本地终止、改写响应或改选上游集合 |
| 共享运行时 | proxy.cache、custom cache、LRU、读写锁 | 多请求共享 | 影响后续请求是否还访问上游；自定义上游默认不写全局缓存 |
| 共享运行时 | pendingRequests | 多请求共享 | 合并同一时刻相同 key 的上游查询，等待者不访问上游 |
| 共享运行时 | 已构造 upstream 对象、连接池、bootstrap cache | 多请求共享 | 拨号、TLS 会话、DoH/DoQ 连接和 bootstrap 结果会影响延迟与瞬时失败 |
| 共享运行时 | load balance RTT 表和锁、fastip IP 可达性 cache | 多请求共享 | 历史失败改变后续权重；最快地址模式会记住 10 分钟 ping 成败 |
| 共享运行时 | dnsFilter 规则引擎、客户端容器、access、serverLock | 多请求共享 | 热更新会影响新读入的请求；处理中的请求使用自己的 setts 和 DNSContext |
| 每请求状态 | dnsContext 和 proxy.DNSContext | 单请求 | Res、Req、Upstream、ReqECS、CustomUpstreamConfig、result、origResp 不跨请求混用 |

### 3.1 缓存 key 和不缓存条件

普通缓存 key 包含 DO 位、qtype、qclass、小写 qname；启用 ECS 时还包含掩码和 ECS 地址。DNS message ID、客户端源 IP、上游地址不属于普通 key。

以下情况不使用缓存：

- cache_enabled=false，或全局/自定义 cache 均不存在。
- 客户端使用自定义上游，但该客户端的 upstreams_cache_enabled=false。代码会因此完全绕过缓存，避免把自定义结果写入全局缓存。
- 私有 RDNS 查询。
- 请求带 CD 位。

以下响应即使访问了上游也不会写入：

- 截断响应、question 数不为 1、计算 TTL 为 0。
- NOERROR 的 A/AAAA 没有 IP，且不满足负缓存条件。
- NXDOMAIN/NODATA 没有符合 RFC 2308 的 SOA。
- 非 NOERROR、NXDOMAIN、SERVFAIL 的其他 rcode。
- CD 请求不查也不写。

SERVFAIL 只有在响应自身给出可缓存 TTL 时才缓存，且最长 30 秒。

### 3.2 保护开关和过滤引擎不是同一个开关

- DNSFilter.SetEnabled 对应 setts.FilteringEnabled。关闭后规则匹配和 rewrite 子系统不工作。
- ProtectionEnabled 是保护开关。即使过滤总功能开启，保护关闭时普通黑名单、安全浏览、家长控制、阻断服务不生效；$dnsrewrite 仍可能由规则子系统返回。
- UpdatedProtectionStatus 会处理“暂停到某时刻”的状态。暂停到期的第一个请求先按保护已启用处理，同时只有一个 goroutine 负责落盘和更新状态。
- 每个请求在 processInitial 取一次 setts，之后沿 dnsContext 传递；请求中途热更新不会让该请求在前后阶段混用两套过滤设置。

### 3.3 并发安全和重配置边界

上游接口契约要求并发安全；并行模式还给每个上游复制请求，避免 dns.Client 修改消息造成数据竞争。全局 cache、pending map、RTT 表、fastip cache、过滤引擎和客户端容器都有各自锁或原子状态。

Reconfigure 持有 serverLock 停止并重建 Proxy。已经持有旧 Proxy 或旧 upstream 引用的在途请求可继续完成；新请求通过 proxy() 获取当前实例。若 Proxy 已被关闭置 nil，processUpstream 返回 server is closed。不要根据单个异常请求推断全局配置已经生效或完全停止，应区分新连接和在途请求。

## 4. 并发查询和部分上游失败

### 4.1 请求级并发

每个入站数据包或连接请求都有自己的 DNSContext。UDP 每个包放入 goroutine，TCP/DoT 每个连接一个 goroutine 并可在连接内连续处理查询；MaxGoroutines 通过信号量限制全局同时处理的查询数。达到上限时，新 UDP 包不再启动处理 goroutine，监听循环可能退出；TCP 在 Accept 后获取信号量时可能失败。

同一批请求之间不共享 dnsContext，因此一个请求改写 Req、Res、result 不会直接污染另一个请求。共享的是配置、cache、pending 表、过滤引擎、上游连接对象和运行指标。

### 4.2 load_balance（默认）

默认模式使用 RTT 计算权重并加权抽样上游，顺序由共享 RTT 状态和随机源决定：

- 选中一个上游后只查询它。
- 成功时立即返回，并更新该上游 RTT。
- 失败时记录错误并把该上游 RTT 更新为内部默认惩罚时间，然后按抽样顺序尝试下一个。
- 只要后续任一上游成功，当前请求就是成功，不会再走 fallback。
- 所有候选都失败才进入 fallback。

因此，load_balance 下“部分上游失败但当前请求成功”表现为：dnsproxy 日志中能看到前面的 exchange failed，最后有一条 exchange successfully finished 和 resolved；客户端只收到成功上游的答案。共享 RTT 会影响后续查询，但当前响应不会混合多个上游。

### 4.3 parallel

parallel 对每个上游复制一份请求并启动 goroutine，结果通道带缓冲，容量等于上游数：

- 按完成顺序接收结果。
- 先到的错误被收集，调用继续等待其他上游。
- 收到第一个非 nil 响应就立即把它作为当前请求响应返回。
- 不会取消仍在进行的慢上游；它们可能在客户端已经收到响应后才完成或超时，并继续写 dnsproxy 错误日志。
- 这些迟到结果不会回改当前 d.Res，也不会写入当前请求的 cache。
- 全部失败才 join 所有错误并进入 fallback。

一致性来自“只选择一个响应对象写入当前 DNSContext”。任何晚到响应没有入口修改该对象。观测上要注意，parallel 成功时 QueryStatistics 主要记录获胜者；失败上游的详细错误在 dnsproxy 日志中，而不一定完整进入 AdGuard 查询日志。

### 4.4 fastest_addr

fastest_addr 只对 A/AAAA 生效，其他 qtype 自动回到 load_balance。

A/AAAA 的处理分两层并发：

1. ExchangeAll 并发查询所有 DNS 上游，但会等待所有 goroutine 返回。只要不是全部失败，就保留所有成功响应，合并其中去重后的 A/AAAA IP。
2. pingAll 对每个 IP 的 80 和 443 端口并发 TCP connect，在 FastestTimeout 内取第一个成功的 IP。

输出规则：找到最快 IP 时，选择包含该 IP 的某一个上游响应，然后从答案中删除其他 A/AAAA，只保留最快 IP，CNAME 等非地址记录保留；超时内没有 ping 成功时，使用最先收到的 DNS 响应。ping 成功和失败结果进入独立 fastip cache，默认记录 10 分钟。某些 DNS 上游失败但至少一个成功时，请求仍可能成功。

### 4.5 fallback 的边界

fallback 只在主上游 exchangeUpstreams 返回错误时使用，并且始终以并行方式查询 fallback。

会触发 fallback 的典型现象：

- 所有主上游拨号、TCP/TLS/QUIC/HTTP 传输失败。
- 所有主上游超时。
- 所有主上游连接被关闭或协议握手失败。
- 所有主上游返回 nil 响应，或响应 question 与请求不匹配。
- bootstrap 无法解析 DoH/DoT/DoQ 上游主机名，导致所有相关主上游不可用。

不会触发 fallback 的典型现象：

- 任一主上游返回合法 DNS 响应，即使 rcode 是 NXDOMAIN 或 SERVFAIL。
- 私有 RDNS 查询失败。
- 请求已被本地策略或请求前过滤处理。
- 缓存命中或 pending 等待命中。

fallback 成功时，主上游错误仍保留在 QueryStatistics.Main，获胜 fallback 记录在 QueryStatistics.Fallback；AdGuard 查询日志的 Upstream 是 fallback 地址。主上游和 fallback 全部失败时，handleExchangeResult 生成 SERVFAIL，Resolve 返回非 nil 错误。

### 4.6 pending requests 与 optimistic cache

pending_requests 默认开启，但只有 cacheWorks=true 时才参与：

- 第一个相同 key 请求成为 leader，继续查缓存和上游。
- 同时到达的 follower 在缓存查找前等待 leader 完成，然后复制 leader 的响应、Upstream 和统计。
- follower 不再访问上游，因此能把并发同题查询压缩成一次外部查询。
- leader 失败时 follower 收到同一个错误和可能已生成的 SERVFAIL；leader 成功时所有 follower 使用同一响应的拷贝。
- 带 CD 位、私有 RDNS、缓存禁用的请求不参与 pending。

pending key 只包含消息和 ECS 维度，代码没有额外把 CustomUpstreamConfig 身份放入 key。正常情况下相同 key 也使用同一个全局或同一个持久客户端缓存；但两个不同持久客户端如果都启用了自定义上游缓存，同时查询相同 qname/qtype/ECS，也可能等待到另一个自定义上下文的 leader。自定义缓存被关闭的请求不参与 pending，会直接访问自己的上游。排障遇到“客户端自定义上游看似未发起连接”时，应同时检查该请求是否为 pending follower，而不是只看自定义上游访问日志。

optimistic cache 的行为不同：过期缓存命中会立刻把旧响应返回客户端，同时启动 short-flighter 异步刷新。刷新直接走 replyFromUpstream 和 cacheResp，不经过 AdGuard 业务模块；刷新成功只更新缓存，失败则保留旧缓存直到 optimistic max age。客户端这次看到的仍是旧 TTL 被改写的缓存响应。

## 5. 按客户端现象反推路径

| 客户端/日志现象 | 最可能路径 | 关键证据 | 排查点 |
| --- | --- | --- | --- |
| UDP 完全无响应，TCP/DoT 却是 REFUSED | 访问控制或 BlockedHosts 阻断 | UDP 返回 ErrDrop；TCP 返回 REFUSED | allowed/disallowed clients、ClientID、blocked_hosts |
| 突发流量后 UDP 无响应，没有 AdGuard 查询日志 | ratelimit 中间件丢弃 | 限流日志在 dnsproxy/ratelimit，AdGuard 模块未执行 | ratelimit、子网掩码长度、白名单 |
| AAAA 总是空答案，A 正常 | aaaa_disabled 在 processInitial 本地响应 | 不访问上游，querylog 无 upstream，qtype=AAAA | aaaa_disabled 配置 |
| use-application-dns.net 返回 NXDOMAIN | Firefox DoH canary 本地策略 | processInitial 直接 Finish | 这是预期策略，不是上游 NXDOMAIN |
| _dns.resolver.arpa. SVCB 有答案 | DDR 本地响应 | handle_ddr=true，无上游 | TLS/DoH/DoT/DoQ 监听配置 |
| 公网客户端查 .lan 或 DHCP 本地名为 NXDOMAIN，且无查询日志 | DHCP 防泄露策略 | processDHCPHosts 对非私有客户端直接 Finish | 客户端来源网段、private_networks、local domain |
| 私有客户端能查到 DHCP 租约名/PTR | DHCP 本地答案 | dctx.isDHCPHost 或 RequestedPrivateRDNS，Upstream 为空 | DHCP 是否启用、租约是否存在、DNS64 |
| 查询被拦截，答案为 null IP、自定义 IP、NXDOMAIN 或 CNAME | 请求前过滤命中 | 查询日志有 Filtered reason 和规则；没有 Upstream | 过滤规则、安全浏览、家长控制、安全搜索、阻断服务、客户端策略 |
| 原始查询名变成另一个 CNAME 目标后才访问上游 | 只含 CNAME 的 rewrite | origQuestion 非空，响应后问题名恢复且答案前插入 CNAME | DNS rewrite 和 safesearch 规则 |
| 查询日志 Cached=true，Upstream 为空或是缓存记录地址 | dnsproxy 缓存命中 | pctx.Upstream=nil，QueryStatistics.IsCached=true | TTL、缓存大小、ECS key、CD 位 |
| 缓存命中但仍因新规则被拦截 | 缓存先返回原始响应，AdGuard 响应过滤后改写 | OrigAnswer 有原始上游答案，result 为阻断，Cached=true | 规则热更新；缓存保存的是过滤前答案 |
| 过期 TTL 仍快速返回，稍后上游才出现刷新流量 | optimistic cache | 本次 Cached=true，后台 short-flighter 刷新 | cache_optimistic、answer_ttl、max_age |
| 相同并发查询只有一条上游连接 | pending follower | follower 无独立 Upstream，复制 leader 响应和统计 | pending_requests.enabled、ECS/CD/qname/qtype |
| 并行模式下客户端已收到答案，日志里慢上游稍后才报超时 | parallel 的 goroutine 未被取消 | 第一个成功响应之后仍有迟到 exchange failed | 这是当前实现；客户端响应不会被迟到结果修改 |
| 多个上游中部分报错但答案正常 | parallel 有其他成功者，或 load_balance 后续重试成功，或 fastest_addr 聚合到成功响应 | resolved 指向成功上游；错误只在交换日志 | upstream_mode、RTT 表、网络可达性 |
| fastest_addr 只返回众多 IP 中的一个 | pingAll 选中最快 IP | 答案仅保留一个 A/AAAA，fastip 有 ping 日志 | fastest_timeout、80/443 可达性、fastip cache |
| 所有主上游失败后答案来自 fallback | fallback 并行成功 | QueryStatistics.Main 有错误，Fallback 有成功地址，querylog Upstream 为 fallback | fallback_dns、主上游网络/证书/bootstrap |
| 主上游明确返回 SERVFAIL 但没有走 fallback | 合法 DNS 响应，不是交换异常 | dnsproxy 无 using fallback，Upstream 为主上游 | 上游解析服务本身；不要只按超时排查 |
| 返回 NXDOMAIN 并伴随 selecting upstream: no upstream specified | 域名/客户端上游配置选空 | replyFromUpstream 本地生成 NXDOMAIN 且返回错误 | 默认上游是否缺失、域名排除规则、私有 RDNS 条件 |
| bogus NXDOMAIN 配置网段中的 IP 变成 NXDOMAIN | 上游成功后被 dnsproxy 改写 | Upstream 非空，原始交换成功，最终 rcode=NXDOMAIN | bogus_nxdomain 网段 |
| 私有 PTR 不走 fallback | selectUpstreams 标记 isPrivate | 即使失败也跳过 fallback 分支 | use_private_ptr_resolvers、local_ptr_upstreams、系统 resolver |
| 不同客户端得到不同缓存结果 | ECS、自定义上游或客户端过滤导致 | 比较 ReqECS、CustomUpstreamConfig、client setts、cache 实例 | ECS 开关/自定义 IP、客户端配置、私有源地址 |
| DoH 看到 HTTP 4xx/415/405/400 而不是 DNS rcode | HTTP 入口请求格式错误 | ServeHTTP 未进入 DNSContext | GET dns 参数、POST Content-Type、方法、加密 DoH 设置 |
| DoH 返回 HTTP 500，TCP/DoT 断连，UDP 无响应 | 处理器报错时 Res 为 nil | 查 filtering check、server closed、打包前错误 | AdGuard 错误日志、Reconfigure 时间点、过滤器存储状态 |
| 已有上游 Res 但后处理报错，客户端仍收到上游原始答案 | processFilteringAfterResponse 返回错误时未清空 pctx.Res | 外层按协议发送已有 Res；查询日志/统计被跳过 | filterDNSResponse、HTTPS hint 规则和过滤引擎错误 |

## 6. 建议的排障顺序

1. 先看客户端协议。UDP 的 ErrDrop 本来就无响应；TCP/DoT 会 REFUSED；DoH 的 Res=nil 会变成 HTTP 500。
2. 判断是否有 AdGuard 查询日志。没有日志时优先查 dnsproxy 校验、限流、访问控制、公网 DHCP/ARPA 策略；有日志时再看 reason、rules、Upstream 和 Cached。
3. 根据 qname/qtype 判断是否被本地策略提前终止：AAAA、DDR、healthcheck、Firefox canary、DHCP、私有 RDNS、请求前 rewrite。
4. 若 Cached=true，沿缓存路径排查：TTL、ECS key、CD、自定义客户端 cache、optimistic 后台刷新。不要把缓存命中后的响应过滤误判成上游实时拦截。
5. 若未命中缓存，检查实际候选上游：全局默认、域名专属规则、客户端自定义上游、私有 RDNS、DS 父域规则。
6. 区分“网络异常”和“DNS 错误 rcode”。只有所有主上游 Exchange 返回错误才走 fallback；合法 SERVFAIL/NXDOMAIN 不走 fallback。
7. 对照 upstream_mode：parallel 看第一个成功响应和迟到日志；load_balance 看尝试顺序和 RTT；fastest_addr 看所有 DNS 响应后的 ping 结果。
8. 若发生在配置热更新前后，记录请求开始时间和 Reconfigure 时间。在途请求可能继续使用旧 Proxy/upstream，新请求使用新配置。
9. 最后检查客户端写入阶段。处理链已经生成响应不代表 UDP 发包、TCP 写入、HTTP response writer 或 QUIC stream 一定成功。

## 7. 关键代码索引

- AdGuard 处理器顺序：internal/dnsforward/requesthandler.go 第 18-61 行。
- 每请求共享状态：internal/dnsforward/process.go 第 21-60 行。
- 初始本地策略：internal/dnsforward/process.go 第 104-147 行。
- DHCP 主机和 PTR：internal/dnsforward/process.go 第 285-400 行。
- 请求前过滤：internal/dnsforward/process.go 第 403-437 行；internal/dnsforward/filter.go 第 28-77 行。
- 自定义上游和 Resolve：internal/dnsforward/process.go 第 451-499 行、第 524-547 行。
- 响应后过滤：internal/dnsforward/process.go 第 552-609 行；internal/dnsforward/filter.go 第 116-168 行。
- 查询日志和缓存标记：internal/dnsforward/stats.go 第 98-139 行。
- Proxy 装配和缓存配置：internal/dnsforward/config.go 第 359-417 行。
- 上游模式映射：internal/dnsforward/upstreams.go 第 143-163 行。
- dnsproxy 入站和最终发送：/Users/dengquan/go/pkg/mod/github.com/!adguard!team/dnsproxy@v0.84.2/proxy/server.go 第 79-168 行。
- 缓存命中/写入和条件：同模块 proxy.go 第 881-1005 行；proxycache.go 第 17-133 行；cache.go 第 386-433 行。
- 上游选择、fallback 和结果归一：proxy.go 第 738-855 行。
- 三种交换策略：exchange.go 第 17-70 行；upstream/parallel.go 第 22-66 行；fastip/fastest.go 第 94-121 行。
- pending 和 optimistic：pending.go 第 63-130 行；optimisticresolver.go 第 45-67 行。
