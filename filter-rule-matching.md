# AdGuard Home 过滤规则匹配机制分析

> 代码基线：仓库 `0007-adguardhome-3-1fa2964b`（commit `2b5be1f`），依赖 `github.com/AdguardTeam/urlfilter v0.23.4`。
> 结论先行：一条过滤规则只有在「下载/读取 → 解析校验 → 编译进 urlfilter 引擎 → 引擎整体原子替换」全部 完成之后，才会影响 DNS 查询；查询阶段的最终判断由一套固定的优先级链决定，任何一环失败都回退到「上一次已知良好」的状态，而不是半新半旧。

## 1. 规则进入运行时的完整链路

一条规则（来自本地自定义规则、本地文件或 HTTP 订阅）到达运行时引擎的路径如下：

```
AdGuardHome.yaml (filters / whitelist_filters / user_rules)
        │
        ▼  启动: filtering.New() → loadFilters()        internal/filtering/filtering.go:1054
        ▼  周期: updatesLoop() → periodicallyRefreshFilters()
        ▼       → tryRefreshFilters()                   internal/filtering/filtering.go:1089-1135
        ▼  手动: HTTP API → filterSetProperties()/filterAdd()
        ▼                                               internal/filtering/filter.go:94
   DNSFilter.update() → updateIntl()                    internal/filtering/filter.go:480,501
        │  下载到 aghrenameio.PendingFile（临时文件，不落正式名）
        ▼
   rulelist.Parser.Parse()                              internal/filtering/rulelist/parser.go:42
        │  去注释/空行、拒绝 HTML 与二进制字符、统计规则数、累加 CRC32
        ▼
   finalizeUpdate()                                     internal/filtering/filter.go:585
        │  checksum 变化才 CloseReplace() 原子替换 data/filters/<id>.txt；
        │  否则仅 os.Chtimes 更新时间戳，临时文件 Cleanup() 丢弃
        ▼
   refreshFiltersIntl() → EnableFilters(false)          internal/filtering/filter.go:416,664
        │  汇总启用的列表：自定义规则(ID 0, 内存 Data) + 拦截列表 + 放行列表
        ▼
   setFilters() → initFiltering()                       internal/filtering/filtering.go:361,748
        │  newRuleStorage() → filterlist.NewFile/NewBytes（编译）
        │  urlfilter.NewDNSEngine() 构建 block 引擎与 allow 引擎
        ▼
   engineLock 保护下整体替换 d.filteringEngine / d.filteringEngineAllow
        │  旧 RuleStorage 在换入新引擎后关闭（reset）
        ▼
   查询时 matchHost() 持 engineLock.RLock 做匹配         internal/filtering/filtering.go:886
```

要点：

- **解析先于生效**。`rulelist.Parser`（`internal/filtering/rulelist/parser.go`）在下载过程中逐行流式处理：剥离注释与空行、检测 HTML 错误页（`ErrHTML`）、检测疑似二进制字符并按「行号:列号」报错、对净内容累加 CRC32。任何一行出错都会让整个 `Parse` 返回错误，本次更新作废。
- **编译先于切换**。`initFiltering` 先在锁外用新数据构建好两个 `urlfilter.DNSEngine`，再在 `engineLock` 写锁内一次性替换（`internal/filtering/filtering.go:766-777`）。正在执行的查询持有读锁，要么看到完整的旧引擎，要么看到完整的新引擎，永远不会看到「换到一半」的引擎。
- **自定义规则也是一张列表**。用户自定义规则被包装成 `Filter{ID: rulelist.IDCustom(=0), Data: ...}` 放在拦截引擎的第一张列表（`enableFiltersLocked`，`internal/filtering/filter.go:672-684`），与订阅列表共用同一个引擎和同一套优先级规则。

> 注：仓库中还存在正在重构的新一代实现 `internal/filtering/rulelist`（`Engine`/`Storage`/`TextEngine`），目前只被自身测试使用，尚未接入 `dnsforward` 主流程。下文以现行路径为主，并在差异处单独说明。

## 2. 规则与查询结果发生冲突/例外时的处理

### 2.1 同一引擎内：urlfilter 的优先级仲裁

多个规则同时命中一个主机名时，`DNSEngine.MatchRequest` 先收集所有命中的网络规则，再由 `rules.GetDNSBasicRule`（urlfilter `rules/match.go:173`）选出唯一「基本规则」：

1. 先剔除被 `$badfilter` 抵消的规则（`removeBadfilterRules`），再剔除 `$dnsrewrite` 规则（它们走独立通道，见 2.3）。
2. 剩余规则两两比较 `IsHigherPriority`（urlfilter `rules/network.go:436`），优先级序列为：
   **`@@`白名单+`$important` > `$important` > `@@`白名单 > 普通拦截规则**。
3. 同级别时再比「具体度」：`$redirect` 优先；非通用规则（限定域名）优先于通用规则；最后按修饰符数量（`calcRuleSpecs`，统计启用的选项、域名限制、DNS 类型限制、客户端标签/客户端限制、denyallow、GeoIP 等）多者胜。

因此「放行与拦截结论不一致」在引擎内的裁决依据是：**例外（`@@`）天然压过普通拦截；`$important` 可以反转一次例外；再往后由规则具体度决定，与规则来自哪张订阅列表、在文件中的先后顺序无关**。

### 2.2 引擎之间：allow 引擎先于 block 引擎

`matchHost`（`internal/filtering/filtering.go:886`）的顺序是硬编码的：

```go
if setts.ProtectionEnabled && d.filteringEngineAllow != nil {
    dnsres, ok := d.filteringEngineAllow.MatchRequest(ufReq)
    if ok {
        return d.matchHostProcessAllowList(ctx, host, dnsres)   // :914
    }
}
```

放行引擎（`WhitelistFilters` 编译而成）一旦命中，直接返回 `NotFilteredAllowList`，**不再查询拦截引擎**。即「放行列表命中」在引擎间层面无条件压倒「拦截列表命中」。用户自定义规则因为在拦截引擎内部，所以用户写的 `@@||x^` 例外靠 2.1 的白名单优先级生效，效果等价。

### 2.3 $dnsrewrite 的例外通道

`matchHost` 中 `$dnsrewrite` 结果先于基本判定被检查（`internal/filtering/filtering.go:927`）：只要 `processDNSResultRewrites` 返回了重写结果（Reason 为 `RewrittenRule`），就直接返回，不再走拦截/放行结论。这与 urlfilter 把 dnsrewrite 规则从基本规则竞争中剔除（`removeDNSRewriteRules`）相配合，保证重写不被普通拦截规则「抢走」。

### 2.4 子系统之间：固定顺序、先命中先赢

`CheckHost`（`internal/filtering/filtering.go:507`）先跑 legacy DNS 重写（`processRewrites`，CNAME 链带环路检测），然后按 `New()` 中注册的固定顺序遍历 `hostCheckers`（`internal/filtering/filtering.go:996`）：

```
/etc/hosts 容器 → 过滤规则(matchHost) → 拦截服务 → 安全浏览 → 家长控制 → 安全搜索
```

第一个 `Reason.Matched()` 的检查器直接返回，后续子系统不再执行。所以「过滤规则放行、安全浏览拦截」这类跨子系统冲突，实际由这个注册顺序裁决，而不是由某种全局优先级配置裁决。

### 2.5 请求阶段与应答阶段的两道闸门

- 请求阶段：`processFilteringBeforeRequest → filterDNSRequest`（`internal/dnsforward/filter.go:28`）对 `Question[0]` 的主机名调用 `CheckHost`；`IsFiltered` 为真时直接生成拦截响应，不再询问上游。
- 应答阶段：`filterDNSResponse`（`internal/dnsforward/filter.go:117`）对上游应答中的每条 CNAME 目标、A/AAAA 记录 IP、HTTPS/SVCB hint 再次调用 `CheckHostRules` 匹配规则。也就是说，即使请求的主机名本身没命中，只要应答里解析出的别名或 IP 命中规则，整个应答仍会被替换为拦截响应——规则对一次查询的影响可以发生在解析完成之后。

### 2.6 拦截结论如何变成响应

`IsFiltered` 为真后，`genDNSFilterMessage`（`internal/dnsforward/msg.go:58`）按 `Reason` 与 `BlockingMode` 生成最终报文：安全浏览/家长控制返回专用拦截页 IP；其余按 `genForBlockingMode` 返回 0.0.0.0（NullIP）、NXDOMAIN、REFUSED、自定义 IP，或（Default 模式且规则自带 IP，如 hosts 语法）直接返回规则中的 IP。非 A/AAAA/HTTPS 类型的查询在 NullIP 模式下退化为空应答/NODATA。

## 3. 规则更新不完整时系统依据什么判断

更新路径上每一环的失败都有明确的回退语义，核心原则是「**宁用旧数据，不用坏数据；引擎要么不换，要么整体换**」：

| 失败点 | 行为 | 代码位置 |
| --- | --- | --- |
| 下载中 HTTP 非 200 / 网络错误 / 解析出错 | 临时文件 `Cleanup()` 丢弃，`data/filters/<id>.txt` 保持旧内容，该列表继续用旧数据 | `filter.go:501` `updateIntl`、`filter.go:585` `finalizeUpdate` |
| 内容未变（CRC32 相同） | 不替换文件，仅 `os.Chtimes` 刷新时间戳，不触发引擎重建 | `filter.go:480` `update` |
| 本轮所有列表全部失败 | 判定为网络错误（`isNetErr`），完全不重建引擎；周期任务间隔翻倍退避（上限 1 小时） | `filter.go:313` `refreshFiltersArray`、`filtering.go:1117` `periodicallyRefreshFilters` |
| 部分列表失败、部分有更新 | 仅对有变化的列表替换文件，随后 `EnableFilters(false)` 用磁盘上「新文件+旧的失败列表文件」整体重建引擎 | `filter.go:416` `refreshFiltersIntl` |
| 启动时缓存文件不存在 | 该列表静默跳过（`os.ErrNotExist` → 返回 nil），等首次下载成功才参与过滤 | `filter.go:626` `load`、`filtering.go:702` `ruleListFromFilter` |
| 引擎重建过程中 | 查询持 `engineLock.RLock`，新引擎在写锁内整体换入，旧存储换入后关闭；查询永远看到完整引擎 | `filtering.go:748` `initFiltering`、`filtering.go:905-912` |
| 配置层更新（改 URL/启停）出错 | `filterSetProperties` 用 defer 把 URL/Name/Enabled/时间戳全部回滚到旧值 | `filter.go:94` |

需要注意的一个细节：「部分失败」时失败列表并不是被剔除，而是**沿用其磁盘上的旧缓存文件**参与新引擎——这是 fail-static 而非 fail-open。

新一代 `rulelist.Engine`（尚未接线）语义略有不同，报告如实记录：`engineRefresh.process` 中单个列表刷新失败时，该列表**不会**被加入新的 `RuleStorage`（`internal/filtering/rulelist/engine.go:225-244`），即该列表在新引擎中缺席；而若唯一的错误是 context 超时/取消，则整个刷新放弃、保留旧引擎（`isOneTimeoutError`，`engine.go:173`）。这与现行路径的「沿用旧文件」策略不同，后续接线时值得关注。

## 4. 多个规则同时命中时的最终判断

分四种情形：

1. **多条网络规则命中同一主机**：由 `GetDNSBasicRule` 按 2.1 的优先级序列选出唯一基本规则，`Result.Rules` 只含这一条。列表之间没有「列表优先级」，只有规则级优先级。
2. **多条 hosts 语法规则命中**：urlfilter 返回 `HostRulesV4`/`HostRulesV6` 两个集合。`resultFromHostRules`（`filtering.go:848`）按查询类型选择：A 查询取全部 v4 规则（可多条同时生效，IP 都进应答），AAAA 查询取全部 v6 规则；其他类型由 `hostResultForOtherQType` 取 v4 的第一条（v4 优先于 v6）。
3. **放行与拦截同时命中**：先看是否同一引擎——引擎内 `@@` > 普通规则、`$important` 可反转；跨引擎则 allow 引擎整体优先（2.2）。最终 `Reason` 只会是 `FilteredBlockList` 或 `NotFilteredAllowList` 之一，`IsFiltered` 仅当 `Reason == FilteredBlockList` 时为真（`makeResult`，`filtering.go:954`）。
4. **过滤结论与其他子系统冲突**：按 2.4 的 `hostCheckers` 注册顺序，先命中者胜；请求阶段未拦截的，还可能在应答阶段被 2.5 的第二道闸门拦截。

## 5. 可验证的规则生效路径（实测还原）

以下路径已在本仓库中用 Go 测试实际跑通。测试文件：[internal/filtering/rulepath_verify_test.go](internal/filtering/rulepath_verify_test.go)。

路径：自定义规则 `||blocked-by-custom.example^` 写入配置 `user_rules`
→ `filtering.New(conf, nil)` 创建 DNSFilter
→ `EnableFilters(false)` 把用户规则包装成 `Filter{ID: 0, Data: ...}`（`filter.go:672`）
→ `initFiltering` 编译进 block 引擎（`filtering.go:748`）
→ `CheckHost("blocked-by-custom.example", TypeA, setts)`
→ `matchHost` → `filteringEngine.MatchRequest` 命中
→ `matchHostProcessDNSResult` 判定 `FilteredBlockList`、`IsFiltered=true`
→ 结果规则携带 `FilterListID=0`（即自定义列表）。

运行命令与实测输出：

```console
$ go test ./internal/filtering/ -run 'TestVerifyRulePath|TestVerifyCustomUserRule' -v
=== RUN   TestVerifyRulePath
    blocked.example   -> reason=FilteredBlackList rule="||blocked.example^"
    important.example -> reason=FilteredBlackList rule="||important.example^$important"
    allowed.example   -> reason=NotFilteredWhiteList rule="@@||allowed.example^"
    hosts.example     -> reason=FilteredBlackList ip=192.0.2.1
--- PASS: TestVerifyRulePath (0.00s)
=== RUN   TestVerifyCustomUserRule
    blocked-by-custom.example -> reason=FilteredBlackList list=0 rule="||blocked-by-custom.example^"
--- PASS: TestVerifyCustomUserRule (0.00s)
PASS
ok  github.com/AdguardTeam/AdGuardHome/internal/filtering
```

测试同时实证了第 4 节的三条裁决规则：

- `||blocked.example^` 单规则命中 → `FilteredBlockList`，`Result.Rules[0].Text` 原样返回规则文本；
- `||important.example^$important` 与 `@@||important.example^` 同时命中 → `$important` 拦截规则胜出（优先级序列第 2 级压过第 3 级）；
- `||allowed.example^` 与 `@@||allowed.example^` 同时命中 → 白名单例外胜出，`IsFiltered=false`，`Reason=NotFiltered`，查询继续走上游；
- `192.0.2.1 hosts.example`（hosts 语法）→ 判定为 `FilteredBlockList` 且规则自带 IP，Default 拦截模式下该 IP 直接作为应答返回。

（注：本仓库 `go.mod` 要求 Go 1.26.8，需使用支持 toolchain 自动切换的 Go 版本运行测试。）
