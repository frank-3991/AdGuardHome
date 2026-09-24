# AdGuard Home 客户端身份与策略隔离分析报告

本文沿实际代码路径分析：当同一台设备的地址发生变化、或多个地址归属于同一客户端时，客户端身份识别如何参与运行时状态合并，如何影响过滤策略的继承与查询处理，以及在动态租约变化或识别信息不完整时，最终请求实际采用哪套策略。

代码基线：仓库根目录 `internal/client`、`internal/dnsforward`、`internal/filtering`、`internal/home`、`internal/dhcpd` / `internal/dhcpsvc`。

## 1. 两层身份模型：持久客户端与运行时客户端

AdGuard Home 把"客户端身份"拆成两个相互独立的索引，由 `client.Storage`（internal/client/storage.go）统一持有，二者共用一把 `sync.Mutex`（`s.mu`）保护所有读写：

- **持久客户端索引（`index`，internal/client/index.go）**：来自配置文件 / 管理 API 的 `Persistent` 客户端。每个客户端有唯一 `UID`，并通过多张映射表登记标识符：`nameToUID`、`clientIDToUID`、`ipToUID`、`subnetToUID`（有序映射）、`macToUID`。**策略（Tags、UseOwnSettings、BlockedServices、自定义上游等）只挂在持久客户端上**。
- **运行时客户端索引（`runtimeIndex`，internal/client/runtimeindex.go）**：以 IP 为键聚合来自 WHOIS、ARP、rDNS、DHCP、系统 hosts 文件五种来源的主机名 / WHOIS 信息（`Runtime`，internal/client/client.go）。运行时信息**只用于展示与日志 enrichment，不参与策略决策**。

关键隔离不变量由 `index.clashes` 保证：任何一个 IP、子网、MAC、ClientID、名称在同一时刻只能登记到一个持久客户端（`Storage.Add` / `Storage.Update` 都会先校验冲突）。因此"多个地址归属于同一客户端"只能通过**同一客户端登记多个标识符**（`Persistent.IPs` / `MACs` / `Subnets` / `ClientIDs`）来表达，而不可能出现两个持久客户端共享同一标识符的歧义状态。

## 2. 身份识别如何参与状态合并

### 2.1 运行时信息的来源合并语义

`Runtime` 按来源分槽存储信息，`Runtime.Info()` 以固定优先级取一个代表主机名：

```
SourceHostsFile > SourceDHCP > SourceRDNS > SourceARP > SourceWHOIS
```

各来源的写入都采用"全量替换 + 清理空槽"的合并协议，且在 `s.mu` 临界区内原子完成：

- `addFromSystemARP`（ARP 周期刷新）：`clearSource(SourceARP)` → 逐条 `setInfo` → `removeEmpty()`；
- `addFromHostsFile`（hosts 文件变更通知）：同样先 `clearSource(SourceHostsFile)`；
- `UpdateDHCP`：`clearSource(SourceDHCP)` → 按当前全部租约 `setInfo` → `removeEmpty()`。注意它只在 `GET /control/clients`（internal/home/clientshttp.go:110）时被触发，并非租约变化时自动推送——`dhcpd` 的 `onLeaseChanged` 回调链在当前代码中没有任何注册方；
- `UpdateAddress`（rDNS/WHOIS 异步结果，来自 `DefaultAddrProc` 的处理队列，internal/client/addrproc.go）：按 IP 增量写入 `SourceRDNS` 槽或 WHOIS 槽。

由于每次合并都是"清源 → 重写 → 删空"，租约或邻居表变化后，旧 IP 的运行时条目会被 `removeEmpty` 回收，新 IP 建立新条目——**运行时身份跟随 IP，不跟随设备**。

### 2.2 持久身份与运行时身份的合流点

两条身份线在三个地方合流：

1. `Storage.setWHOISInfo`：若该 IP 已命中持久客户端（`index.findByIP`），WHOIS 信息被直接忽略——持久身份压制运行时 enrichment。
2. `Storage.findByIP`（持久客户端查找）：先查 `ipToUID`，再查子网包含关系，最后**实时**调用 `dhcp.MACByIP(addr)` 把 IP 翻译成 MAC，再查 `macToUID`。这是"地址变化但设备不变"时身份得以延续的关键一跳：DHCP 租约是查询时惰性解析的，不经过运行时索引缓存。
3. `Storage.ClientRuntime`：读取运行时条目时，若来源不是 hosts 文件且启用了 `RuntimeSourceDHCP`，会惰性调用 `dhcp.HostByIP(ip)` 把 DHCP 主机名补进 `SourceDHCP` 槽再返回。

## 3. 查询处理路径上的身份解析与策略继承

一个 DNS 请求的身份解析按以下顺序发生：

### 3.1 ClientID 提取（中间件层）

`Server.Wrap`（internal/dnsforward/middleware.go）在任何过滤之前调用 `clientIDFromDNSContext`：

- DoH：从 URL 模式 `/dns-query/{ClientID}` 提取并校验；
- DoT/DoQ：从 TLS SNI 中提取 `<clientID>.<servername>` 形式的直接子域；
- 提取失败（如 strict 模式下 SNI 不匹配）直接回 SERVFAIL；未提供则为空串。

随后 `IsBlockedClient`（internal/dnsforward/dnsforward.go:905）用 IP 与 ClientID 对照访问控制列表：allowlist 模式下两者都被拒才拦截，blocklist 模式下任一命中即拦截。

### 3.2 每请求的过滤设置合成

`processInitial` → `clientRequestFilteringSettings`（internal/dnsforward/filter.go）→ `DNSFilter.ApplyAdditionalFiltering`（internal/filtering/filter.go:711）：

1. 先以全局配置铺底：`Settings()` 拷贝全局开关，`ApplyBlockedServices` 按全局 `BlockedServices`（含时间表 `Schedule`）生成 `ServicesRules`；
2. 再调用 `applyClientFiltering`，即 `Storage.ApplyClientFiltering`（internal/client/storage.go:757），查找顺序为：`ClientID` → `IP（精确）/子网包含` → `DHCP MACByIP → MAC`；
3. 命中持久客户端后：
   - `UseOwnBlockedServices` 为真时，用客户端自己的 `BlockedServices` **整体替换**全局列表（随后按客户端自己的 Schedule 重新生成 `ServicesRules`）；
   - `ClientName`、`ClientTags` 无条件写入设置；
   - 仅当 `UseOwnSettings` 为真时，才覆盖 `FilteringEnabled`、`SafeSearchEnabled`（含客户端自定义 `ClientSafeSearch`）、`SafeBrowsingEnabled`、`ParentalEnabled`；
4. 未命中时函数直接返回，**请求完整继承全局策略**。

### 3.3 标签与名称进入规则匹配

`matchHost`（internal/filtering/filtering.go，构造 `urlfilter.DNSRequest` 处）把 `setts.ClientTags` 放进 `ClientTags`，把 `ClientName` 放进 `ClientIdentifiers`。因此 `$ctag` 修饰符规则只对带对应标签的已识别客户端生效，`$client` 修饰符规则按客户端名匹配。未识别客户端这两个集合为空，带 `$ctag`/`$client` 限定的规则不会命中。

### 3.4 自定义上游

`setCustomUpstream`（internal/dnsforward/process.go:526）调用 `ClientsContainer.CustomUpstreamConfig(clientID, ip)`，同样是 **ClientID 优先、IP（含子网、MAC 回退）其次**（internal/client/storage.go:695）。身份未命中则使用公共上游配置。

### 3.5 查询日志与统计

`clientOrArtificial`（internal/home/clients.go:340）用 `FindLoose` 再查一次身份：先按字符串标识（ClientID/IP/MAC），再 `dhcp.MACByIP` 回退，最后 `findByIPWithoutZone`（剥掉 IPv6 zone 的线性扫描，注释明确说明多客户端同 IP 不同 zone 时结果不确定）。都找不到则用运行时客户端的主机名，再不行记为 artificial 条目。`IgnoreQueryLog` / `IgnoreStatistics` 也只在命中持久客户端时生效。

## 4. 动态租约变化与识别信息不完整时的最终策略

### 4.1 场景：设备换了 IP（DHCP 租约变化）

- **客户端以 MAC（或 ClientID、子网）登记**：新 IP 虽未登记，但 `findByIP` 经 `dhcp.MACByIP` 实时翻译后命中 `macToUID`，**策略完整跟随设备**，无中间态。前提：DHCP 服务器已持有新租约，且 `Storage` 构造时传入了真实的 `DHCP` 接口。
- **客户端仅以旧 IP 登记**：`ipToUID` 失配，`MACByIP` 查到的 MAC 不在任何客户端的 `MACs` 中（或 DHCP 未启用 / 无租约），查找失败。此时：
  - 过滤设置：全局 `FilteringEnabled` / SafeSearch / SafeBrowsing / Parental；
  - 拦截服务：全局 `BlockedServices` 及其 Schedule；
  - 标签：空，`$ctag` 规则不生效；
  - 上游：公共上游；
  - 日志：显示运行时主机名（DHCP/hosts/rDNS 优先级）或记为 artificial，`IgnoreQueryLog` / `IgnoreStatistics` 不再生效。
- **中间态窗口**：租约已发但 `UpdateDHCP` 未刷新（它只在 Web API 拉取时触发）时，运行时索引里可能还留着旧 IP 的 DHCP 主机名；但这只影响展示名。策略判定走的是 `MACByIP` 实时查询，不受该缓存 staleness 影响。

### 4.2 场景：识别信息不完整或尚在途中

- **rDNS/WHOIS 是异步的**：`processInitial` 把客户端 IP 投入 `addrProc` 队列后立即继续处理请求（internal/dnsforward/process.go:113）。识别结果写回前，该 IP 的请求已经按"无运行时信息"处理；且 rDNS/WHOIS 只进运行时索引，**永远不会改变策略**。
- **DoH/DoT/DoQ 提供了 ClientID**：ClientID 在三个查找点（访问控制、过滤设置、自定义上游）都优先于 IP，设备换网络、换 IP 都不影响身份，策略最稳定。
- **ClientID 无效或 SNI 不匹配（strict 模式）**：请求直接 SERVFAIL，不进入过滤。
- **完全未识别**（无 ClientID、IP/子网/MAC 均未登记、DHCP 无租约）：`ApplyClientFiltering` 空跑，请求自始至终使用全局策略，访问控制按未匹配 ClientID/IP 的默认规则裁决。

### 4.3 状态合并的原子性边界

所有索引读写都在 `Storage.mu` 下完成，单请求的 `ApplyClientFiltering` 看到的是某一时刻的一致快照；但"身份切换"本身不是事务：`Storage.Update` 先 `remove` 旧客户端再 `add` 新标识，期间并发的 DNS 请求可能观察到旧身份或短暂查无此人，从而在该窗口内回落到全局策略。同样，`FindLoose` 的 `findByIPWithoutZone` 在多个持久客户端共享同 IP（不同 zone）时结果不确定，日志归属可能与过滤时的身份不一致。

## 5. 结论：身份切换后的策略判断依据

身份切换（换 IP、换网络、识别信息补齐或缺失）后，单个请求最终采用哪套策略，由以下判定链决定，且**每个请求独立重算，不存在粘性缓存**：

1. **ClientID 优先**：DoH 路径参数 / DoT、DoQ SNI 中的 ClientID 命中 `clientIDToUID` 时，无论源 IP 如何变化，一律采用该持久客户端的策略（自定义开关、标签、拦截服务、上游、日志开关）。
2. **IP → 子网 → DHCP MAC 回退**：无 ClientID 时按 `ipToUID` 精确匹配，再按 `subnetToUID` 包含匹配，最后经 `dhcp.MACByIP` 把当前 IP 实时翻译成 MAC 查 `macToUID`。设备换 IP 但 MAC 已登记时，策略仍跟随设备。
3. **全部未命中即全局策略**：以上均失败时，请求继承全局过滤开关、全局拦截服务（含时间表）、公共上游；标签与 `$ctag`/`$client` 规则不参与匹配；运行时信息（DHCP/hosts/rDNS/ARP/WHOIS 主机名）只决定日志中的显示名，不构成任何策略依据。
4. **访问控制独立裁决**：`IsBlockedClient` 用 IP 与 ClientID 对照 ACL，allowlist 模式"两者皆拒才拦"，blocklist 模式"任一命中即拦"，与过滤设置的身份解析互不影响。

简言之：**策略身份 = ClientID > IP/子网 > DHCP 租约翻译出的 MAC > 全局默认**；运行时识别信息只负责"这台设备叫什么"，不负责"这台设备用什么策略"。
