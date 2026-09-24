# AdGuard Home 客户端身份识别与策略隔离分析报告

> 分析对象：本仓库（AdGuard Home）中客户端身份识别、运行时状态合并、过滤策略继承与查询处理的实际代码路径。
> 核心问题：当同一台设备的地址变化（DHCP 动态租约）或多个地址归属于同一客户端时，身份识别如何参与状态合并，并最终决定一次 DNS 请求采用哪套策略。

## 1. 两类客户端实体与身份模型

代码中存在两套平行的客户端状态，分别由 internal/client/storage.go 中的 `Storage` 统一管理：

**持久客户端（Persistent）** —— internal/client/persistent.go

- 由管理员显式配置，携带过滤策略（`UseOwnSettings`、`FilteringEnabled`、`SafeBrowsingEnabled`、`ParentalEnabled`、`SafeSearchConf`、`UseOwnBlockedServices`、`BlockedServices`、`Upstreams`、`Tags` 等）。
- 身份由四类标识符共同构成：`IPs`、`Subnets`、`MACs`、`ClientIDs`（至少一个，见 `validate`）。内部主键是 `UID`（UUIDv7）。
- 索引 internal/client/index.go 为每类标识符维护独立映射（`ipToUID`、`subnetToUID`、`macToUID`、`clientIDToUID`、`nameToUID`）。`clashes` 在 Add/Update 时保证任一标识符全局唯一——这是策略隔离的静态基础：一个 IP/MAC/ClientID 不可能同时属于两个持久客户端，因此识别结果至多命中一个策略主体。

**运行时客户端（Runtime）** —— internal/client/client.go、internal/client/runtimeindex.go

- 以 IP 为唯一键（`runtimeIndex.index map[netip.Addr]*Runtime`），只携带"识别信息"（主机名、WHOIS），不携带任何过滤策略。
- 信息按来源分槽存储：`whois` / `arp` / `rdns` / `dhcp` / `hostsFile`，来源优先级在 `Source` 常量中定义，`Runtime.Info()` 按 HostsFile > DHCP > rDNS > ARP > WHOIS 取最高优先级来源的第一个名字。

关键结论：策略只挂在持久客户端上。运行时客户端仅参与日志、统计、UI 展示的名称解析；它再完整也不会改变任何过滤行为。

## 2. 状态合并机制

### 2.1 运行时信息的多来源合并

每个来源的刷新都采用"清空该来源 → 重建 → 清理空记录"的三段式（均在 `Storage.mu` 保护下）：

| 来源 | 入口 | 触发方式 |
| --- | --- | --- |
| DHCP | `Storage.UpdateDHCP` | 仅由 HTTP API `handleGetClients`（internal/home/clientshttp.go:110）拉取客户端列表时触发 |
| ARP | `addFromSystemARP` | `periodicARPUpdate` 定时器周期触发 |
| hosts 文件 | `addFromHostsFile` | 订阅 `HostsContainer.Upd()` 更新通道 |
| rDNS/WHOIS | `UpdateAddress` | 每个请求的客户端 IP 经 `DefaultAddrProc`（internal/client/addrproc.go）异步队列处理后回写 |

由于 `clearSource` 只清单一来源的槽位，合并是按来源正交的：DHCP 租约重建不会冲掉 rDNS 结果。`removeEmpty` 会把所有来源都为空的记录删除——租约过期且没有其他来源信息时，该 IP 的运行时身份整体消失，这是"中间状态"的一种：旧身份已清除、新身份尚未建立。

### 2.2 持久身份与运行时身份的合并

- `setWHOISInfo` 明确让位：若 IP 已命中持久客户端（`index.findByIP`），WHOIS 信息被忽略（"persistent client is already created, ignore whois info"）。
- `ClientRuntime` 中 SourceHostsFile > SourceDHCP：hosts 文件命中则直接返回；否则实时调用 `dhcp.HostByIP(ip)` 补充——即运行时 DHCP 信息在读取时与 DHCP 服务的当前租约表合并，而非依赖 `UpdateDHCP` 的快照。

### 2.3 IP→MAC→持久客户端的桥接（动态租约影响身份的关键路径）

`Storage.findByIP` 与 `ApplyClientFiltering` 中的查找顺序揭示了动态地址如何归入既有身份：

1. 先查 `index.findByIP`：精确 IP 命中，或 `subnetToUID` 的子网包含匹配（比较前剥离 IPv6 zone）。
2. 未命中则 `dhcp.MACByIP(addr)`：用 DHCP 服务当前的租约表把 IP 翻译成 MAC。
3. 再 `index.findByMAC(foundMAC)`：用 MAC 命中持久客户端。

也就是说，一个只以 MAC 标识的持久客户端，其"当前地址"完全由 DHCP 租约表动态决定；租约建立即获得身份，租约过期/易主即失去身份。这条桥接路径不经过 runtimeIndex，直接读 DHCP 服务的实时状态，因此过滤路径不受 2.1 节快照中间态影响。

## 3. 查询处理中的身份解析与策略继承

### 3.1 ClientID 提取与访问控制

internal/dnsforward/middleware.go 的 `Wrap` 在进入处理链之前：

1. `clientIDFromDNSContext` 提取 ClientID：DoH 从 URL 路径参数（`clientIDFromDNSContextHTTPS`），DoT/DoQ 从 TLS SNI 的子域名（`clientIDFromClientServerName`），均校验并转小写；普通 UDP/TCP 无 ClientID。
2. `IsBlockedClient(ip, clientID)`（internal/dnsforward/dnsforward.go:903）执行访问列表：allowlist 模式下 IP 与 ClientID 都不在白名单才拒绝；blocklist 模式下任一命中即拒绝。ClientID 解析失败直接回 SERVFAIL。

### 3.2 过滤设置的构造（策略继承点）

`processInitial` → `clientRequestFilteringSettings`（internal/dnsforward/filter.go:18）：

    setts = dnsFilter.Settings()            // 全局开关快照
    setts.ProtectionEnabled = ...           // 全局保护开关
    dnsFilter.ApplyAdditionalFiltering(ip, clientID, setts)

`ApplyAdditionalFiltering`（internal/filtering/filter.go:712）的顺序：

1. 写入 `ClientIP`，应用全局 BlockedServices（含时间表判断）。
2. 调用 `applyClientFiltering`，即 `Storage.ApplyClientFiltering`（internal/home/clients.go:142 接线）。
3. 若客户端覆盖了 BlockedServices，则清空全局 `ServicesRules` 并按客户端的时间表重建。

`Storage.ApplyClientFiltering` 的身份查找顺序为 ClientID → IP（含子网）→ DHCP MAC 桥接 → MAC，与 2.3 节一致但 ClientID 最优先。找到持久客户端后：

- `UseOwnBlockedServices` 为真 → 用客户端的 `BlockedServices` 整体替换；
- 无条件写入 `ClientName`、`ClientTags`；
- `UseOwnSettings` 为真 → 覆盖 `FilteringEnabled`、`SafeSearchEnabled`/`ClientSafeSearch`、`SafeBrowsingEnabled`、`ParentalEnabled`；
- 找不到则原样返回——设置保持全局值，即策略继承自全局配置。

注意：`ApplyClientFiltering` 直接读 `index` 而未持有 `Storage.mu`（同文件的 `Find`/`CustomUpstreamConfig` 均持锁），在客户端增删与查询并发时存在弱一致窗口，属于代码现状的一个观察点。

### 3.3 标签策略如何进入规则匹配

`matchHost`（internal/filtering/filtering.go:891 附近）把身份注入 urlfilter 请求：

    ufReq := &urlfilter.DNSRequest{
        ClientTags:        setts.ClientTags,    // 匹配规则中的 $ctag 修饰符
        ClientIP:          setts.ClientIP,
        ClientIdentifiers: setts.ClientName,    // 匹配规则中的 $client 修饰符
    }

因此"标签策略"并非独立机制，而是身份的派生物：只有识别到持久客户端，`ClientTags`/`ClientName` 才非空，带 `$ctag`/`$client` 修饰符的规则才可能命中。识别失败时这类规则对该请求透明失效。

### 3.4 过滤执行链

`CheckHost`（internal/filtering/filtering.go:507）按序执行：legacy rewrites → 系统 hosts → `matchHost`（过滤规则）→ blocked services → safe browsing → parental → safe search。除 hosts/规则匹配外，各环节都由 `setts` 中对应开关门控（如 `checkParental` 要求 `ProtectionEnabled && ParentalEnabled`），而这些开关正是 3.2 节中被身份覆盖的字段。私有 rDNS 请求（`RequestedPrivateRDNS`）在 `processFilteringBeforeRequest` 中被强制关闭 safebrowsing/parental/safesearch 与服务规则。

### 3.5 自定义上游与日志统计

- `setCustomUpstream` → `CustomUpstreamConfig(clientID, addr)`：同样 ClientID 优先、IP 次之（含 MAC 桥接），命中则按客户端 `UID` 取独立上游配置与缓存。
- 日志/统计侧用 `FindLoose`（额外尝试剥离 zone 的 IP 匹配，结果不确定）和 `clientOrArtificial`（internal/home/clients.go:340 附近）：持久客户端 → 运行时客户端（`Info()` 最高优先级来源名）→ 人工占位记录。`IgnoreQueryLog`/`IgnoreStatistics` 仅对持久客户端生效。

## 4. 动态租约变化与识别不完整时的最终策略

**场景 A：设备获得新 IP（租约变化），客户端仅以 MAC 标识。**
新 IP 未在任何 `ipToUID` 中，但 `dhcp.MACByIP` 实时桥接到 MAC，身份与策略无缝跟随。在 DHCP 服务器已登记租约的瞬间即生效；若租约尚未登记（如静态地址、租约表未刷新），桥接断裂，回退全局策略。

**场景 B：新设备拿到旧设备释放的 IP。**
若旧持久客户端以该 IP 为标识符，新设备的请求会被误识别为旧客户端并继承其全部策略（IP 精确匹配优先于 MAC 桥接）。这是 IP 标识符在动态地址环境下的固有风险，代码用 `clashes` 保证唯一性但无法感知地址易主。

**场景 C：识别信息不完整（无 ClientID、IP 未配置、无 DHCP 租约、MAC 不在索引）。**
`ApplyClientFiltering` 静默返回，请求采用：全局 `Settings()` 开关 + 全局 BlockedServices；`ClientTags`/`ClientName` 为空，`$ctag`/`$client` 规则不匹配；无自定义上游；日志中显示为运行时客户端的主机名（若 rDNS/DHCP/hosts 有任何来源）或空名的人工记录。访问控制层面，allowlist 模式下该请求会因 IP 不在白名单而被拒。

**场景 D：DoH/DoT/DoQ 请求携带 ClientID，但源 IP 属于另一个持久客户端。**
ClientID 严格优先于 IP（`ApplyClientFiltering`、`CustomUpstreamConfig` 均先查 `clientIDToUID`），采用 ClientID 对应客户端的策略，IP 归属被忽略。同一台物理设备可以通过切换/省略 ClientID 在不同策略间切换。

**场景 E：运行时索引的中间状态。**
`UpdateDHCP`/ARP/hosts 刷新期间的"清空—重建"窗口只影响 UI 客户端列表与日志名称展示；过滤路径的身份判断（ClientID、IP 索引、DHCP MAC 桥接）全部实时进行，不读 runtimeIndex，因此过滤策略不存在因运行时状态合并而产生的中间态。

## 5. 身份切换后的策略判断依据

综合上述代码路径，一次请求最终采用哪套策略，由以下判定链决定（按优先级）：

1. **ClientID 命中**：请求携带合法 ClientID（DoH 路径 / DoT、DoQ SNI）且命中 `clientIDToUID` → 采用该持久客户端的策略；`UseOwnSettings` 决定覆盖还是仅补充名称/标签/服务封锁。
2. **IP/子网命中**：源 IP 精确命中 `ipToUID` 或被已配置子网包含 → 采用对应持久客户端策略。
3. **DHCP MAC 桥接命中**：以上均未命中时，以 DHCP 当前租约将 IP 译为 MAC 并命中 `macToUID` → 采用该持久客户端策略。租约缺失或过期时此级失效。
4. **全部未命中 → 全局默认策略**：全局过滤开关、全局 BlockedServices、无客户端标签与名称、无自定义上游；`$ctag`/`$client` 规则不生效；allowlist 访问模式下直接拒绝。

即：身份切换后策略的判断依据是 "ClientID > IP/子网 > DHCP 实时租约桥接的 MAC > 全局默认" 这条固定优先级链；运行时客户端信息（rDNS/ARP/hosts/WHOIS）只决定日志与界面中的身份展示，永不参与过滤策略的选择。
