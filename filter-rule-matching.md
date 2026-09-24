# AdGuard Home 过滤规则匹配机制分析

> 代码基线：commit `2b5be1f`（`AGDNS-4443 Add-gh-release-workflow`）。
> 核心结论：一条规则只有在「下载/读取 → 解析 → 编译进 `urlfilter.DNSEngine` → 引擎整体替换」
> 全部完成后才会影响查询；在此之前的任何中间态对查询不可见。所有冲突的最终判断都收敛到
> `filtering.Result.IsFiltered` 这一个布尔值上。

## 1. 一条规则进入运行时的完整路径

### 1.1 来源与解析

规则有两个来源，最终殊途同归：

- **订阅/本地文件**（`FilterYAML`，`internal/filtering/filter.go`）：
  HTTP API（`handleFilteringAddURL` / `handleFilteringRefresh` 等，`internal/filtering/http.go`）
  或定时器（`updatesLoop` → `periodicallyRefreshFilters`，`internal/filtering/filtering.go`）触发
  `refreshFiltersIntl` → `update` → `updateIntl`。下载（`readFromHTTP`）或读取本地文件
  （`readFromFile`，受 `safe_fs_patterns` 白名单校验）后，内容经过
  `rulelist.Parser.Parse`（`internal/filtering/rulelist/parser.go`）：
  - 剔除空行、`#`/`!` 注释，提取 `! Title:`，检测 HTML/二进制内容并拒绝；
  - 对剩余规则行计算 **CRC32 checksum** 并计数（`RulesCount`）；
  - 清洗后的文本写入 `aghrenameio.PendingFile`（临时文件）。
- **自定义规则**（`UserRules`）：不落地为文件，在 `enableFiltersLocked`
  （`internal/filtering/filter.go`）中被拼成 `ID = rulelist.IDCustom (0)` 的内存列表，
  固定作为 block 引擎的第一个列表。

### 1.2 原子落盘与变更判定

`finalizeUpdate`（`internal/filtering/filter.go`）根据 checksum 决定走向：

- `res.Checksum == flt.checksum`：内容未变，`PendingFile.Cleanup()` 丢弃临时文件，只刷新
  `LastUpdated` 和文件 mtime；
- 不同：`CloseReplace()` 把临时文件**原子改名**为 `data/filters/<id>.txt`，更新内存中的
  checksum/RulesCount/Name。

### 1.3 编译进引擎

任何变更（增删列表、启停、规则变化）最终调用 `EnableFilters(async)` → `setFilters` →
`initFiltering`（`internal/filtering/filtering.go`）：

1. `newRuleStorage` 把每个启用的列表包装成 `filterlist.Interface`（Unix 用
   `filterlist.NewFile` 惰性映射文件，Windows 读入内存用 `NewBytes`），聚合成
   `filterlist.RuleStorage`；
2. `urlfilter.NewDNSEngine(storage)` 扫描全部规则，把 host 规则（`/etc/hosts` 语法）建索引、
   把网络规则（Adblock 语法）装入 `NetworkEngine`——**这一步才完成"解析和匹配"的准备工作**；
3. 在 `engineLock` 写锁内整体替换 `d.filteringEngine`（block）和 `d.filteringEngineAllow`
   （allow），旧 storage 随后关闭。

异步模式（HTTP 修改配置时 `async=true`）下，新引擎在后台 goroutine 构建，**旧引擎继续应答**，
构建完成后才切换——查询永远不会看到"半个引擎"。

## 2. 一次查询如何被规则影响

入口在 `dnsforward.filterDNSRequest`（`internal/dnsforward/filter.go`）→
`DNSFilter.CheckHost`（`internal/filtering/filtering.go`），顺序如下：

1. **Legacy DNS rewrite**（`processRewrites`）：先匹配，命中 `Rewritten` 直接返回；
   CNAME 自指、通配回环等被识别为**例外**并放弃该 rewrite（`handleRewriteLoop`）。
2. **hostCheckers 流水线**（`New()` 中固定注册顺序），第一个返回 `Reason.Matched()` 的
   检查器胜出，后续不再执行：
   `hosts 容器` → `过滤规则(matchHost)` → `blocked services` → `safe browsing` →
   `parental` → `safe search`。
3. `matchHost` 内部（持有 `engineLock` 读锁）：
   - **先查 allow 引擎**：`filteringEngineAllow.MatchRequest` 命中即返回
     `NotFilteredAllowList`，block 引擎根本不会被查询（短路）；
   - 再查 block 引擎，命中结果中的 **`$dnsrewrite` 规则优先**于普通拦截
     （`processDNSResultRewrites`，`internal/filtering/dnsrewrite.go`）；
   - `ProtectionEnabled == false` 时，非 rewrite 的匹配结果被丢弃，视为未命中。
4. 引擎内部（`urlfilter` v0.23.4，`dnsengine.go` / `rules/match.go`）：
   `GetDNSBasicRule` 从所有命中的网络规则中选一条，优先级为
   **白名单+$important > $important > 白名单 > 普通拦截规则**（同级时修饰符更多、更具体的
   规则优先，见 `NetworkRule.IsHigherPriority`）；`$badfilter` 规则先被移除；
   host 规则在没有网络规则命中时才生效，且 A/AAAA 各自可以返回**多条**。
5. **响应阶段二次过滤**（`filterDNSResponse`）：上游应答里的 CNAME 目标、A/AAAA 记录、
   HTTPS RR 的 IP hint 会再用 `CheckHostRules`（只查规则引擎）检查一遍，命中即把应答替换为
   拦截响应。

最终，`dnsforward` 只看 `res.IsFiltered`：为 true 时调用 `genDNSFilterMessage` 按
`blocking_mode`（`null_ip`/`custom_ip`/`nxdomain`/`refused`/`default`）生成拦截应答；
否则按正常流程转发/放行。`Reason` 只决定查询日志里记录的原因，不影响动作。

## 3. 三类冲突场景的最终判断依据

### 3.1 规则更新不完整

依据：**以最后一次完整成功解析并落盘的列表内容为准，失败的列表保留旧版本，引擎要么不重建、
要么整体重建。**

- 下载/解析任一环节出错：`PendingFile` 被 `Cleanup`，`data/filters/<id>.txt` 原封不动
  （`updateIntl` + `finalizeUpdate`）；
- 多个列表各自独立更新（`updateFilterList`），单个失败只记日志，不影响其他列表；
- 全部失败视为网络错误（`isNetErr`），`refreshFiltersIntl` 直接返回，**不触发引擎重建**；
- 只要有 ≥1 个列表内容变化（`updNum > 0`），才调用 `EnableFilters(false)` 同步重建引擎，
  且重建是在 `engineLock` 写锁下整体替换（`initFiltering`）；
- `refreshLock.TryLock`（`tryRefreshFilters`）保证同一时间只有一个更新流程，
  更新中到来的更新请求直接放弃。

因此查询侧看到的状态空间只有两种：旧的完整引擎、新的完整引擎，不存在"部分规则生效"的中间态。

### 3.2 多个规则同时命中

依据：**引擎内按 `IsHigherPriority` 选唯一基本规则；跨引擎/跨模块按固定检查顺序，先命中先赢。**

- 同一引擎内多条网络规则命中：`GetDNSBasicRule` 按
  「白名单+$important > $important > 白名单 > 普通规则（更具体者优先）」选出一条，
  `Result.Rules` 里只放这一条；
- host 规则（`0.0.0.0 host` 语法）是例外：A/AAAA 查询可返回多条，`Result.Rules` 全部保留；
- `$dnsrewrite` 命中时绕过上述基本规则逻辑，且 CNAME 类 rewrite 优先于记录类 rewrite，
  非 SUCCESS 的 RCODE（如 REFUSED）优先级最高（`processDNSRewrites`）；
- 跨引擎：allow 引擎先于 block 引擎（`matchHost` 的短路逻辑）；
- 跨模块：`hostCheckers` 数组顺序即优先级（hosts > 过滤规则 > 服务拦截 > 安全浏览 >
  家长控制 > 安全搜索）。

### 3.3 放行与拦截结论不一致

依据：**白名单语义在两个层级上都压过拦截，最终以 `Result.IsFiltered` 为唯一裁决。**

- 同一引擎内：`@@` 白名单规则通过 `IsHigherPriority` 天然高于普通拦截规则，命中后
  `matchHostProcessDNSResult` 把 `Reason` 置为 `NotFilteredAllowList`；
- 独立 allowlist（用户白名单列表）：在 block 引擎之前短路返回 `NotFilteredAllowList`；
- `makeResult` 中 `IsFiltered = (reason == FilteredBlockList)`，所以任何"放行"结论
  （`NotFilteredAllowList`/`NotFilteredNotFound`）都会让 `IsFiltered=false`，
  `dnsforward.filterDNSRequest` 据此不生成拦截应答，查询被正常放行；
- 例外中的例外：`$important` 修饰的拦截规则可以压过普通白名单规则（但仍压不过
  「白名单+$important」），这是 urlfilter 优先级表决定的，AdGuard Home 本身不再干预。

## 4. 可验证的规则生效路径（实测还原）

验证测试：[internal/filtering/zz_verify_internal_test.go](internal/filtering/zz_verify_internal_test.go)，
覆盖「列表数据 → 引擎 → `CheckHost` 结果」全链路及上述三类冲突判断。

复现命令（需要 Go ≥ 1.26，本机 go.mod 要求 1.26.8）：

```sh
go test ./internal/filtering/ -run TestVerifyRuleEffectivePath -v -count=1
```

实测输出（2026-09-23，go1.26.8 darwin/amd64）：

```text
=== RUN   TestVerifyRuleEffectivePath
=== RUN   TestVerifyRuleEffectivePath/block_rule_matches
=== RUN   TestVerifyRuleEffectivePath/multiple_rules_hit,_important_wins
=== RUN   TestVerifyRuleEffectivePath/custom_whitelist_rule_beats_block_rule_in_same_engine
=== RUN   TestVerifyRuleEffectivePath/allowlist_engine_short-circuits_block_engine
=== RUN   TestVerifyRuleEffectivePath/protection_disabled_ignores_block_match
--- PASS: TestVerifyRuleEffectivePath (0.00s)
    --- PASS: TestVerifyRuleEffectivePath/block_rule_matches (0.00s)
    --- PASS: TestVerifyRuleEffectivePath/multiple_rules_hit,_important_wins (0.00s)
    --- PASS: TestVerifyRuleEffectivePath/custom_whitelist_rule_beats_block_rule_in_same_engine (0.00s)
    --- PASS: TestVerifyRuleEffectivePath/allowlist_engine_short-circuits_block_engine (0.00s)
    --- PASS: TestVerifyRuleEffectivePath/protection_disabled_ignores_block_match (0.00s)
PASS
ok  	github.com/AdguardTeam/AdGuardHome/internal/filtering	0.498s
```

以 `block_rule_matches` 为例，规则 `||ads.example.com^` 的生效路径逐步对应：

1. 规则文本作为 `Filter{ID: 1, Data: ...}` 进入 `New()` → `initFiltering`
   （生产环境等价路径：订阅下载 → `rulelist.Parser` 清洗 → `data/filters/1.txt` →
   `filterlist.NewFile`）；
2. `urlfilter.NewDNSEngine` 把它编译进 `NetworkEngine`；
3. `CheckHost("ads.example.com", A, setts)` → `matchHost`：allow 引擎为 nil 跳过，
   block 引擎 `MatchRequest` 命中该规则；
4. `matchHostProcessDNSResult` 生成 `Result{IsFiltered: true, Reason: FilteredBlockList,
   Rules: [{Text: "||ads.example.com^", FilterListID: 1}]}`——测试断言的正是这四个字段；
5. 生产环境中 `dnsforward.filterDNSRequest` 看到 `IsFiltered=true` 后调用
   `genDNSFilterMessage`，按 `blocking_mode` 返回拦截应答（默认 `0.0.0.0`）。

其余四个子测试分别实证：多条规则命中时 `$important` 规则成为唯一入档规则；
自定义 `@@` 白名单规则在同一引擎内压过拦截规则（`IsFiltered=false`）；
独立 allowlist 引擎短路 block 引擎（`FilterListID` 为 allow 列表的 2 而非 block 列表的 1）；
`ProtectionEnabled=false` 时拦截命中被整体丢弃（`NotFilteredNotFound`）。
