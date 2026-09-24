# AdGuard Home 统计数据时间桶分析报告

本文沿实际代码追踪管理后台统计数据的写入、聚合、读取与展示链路，分析时区、
边界时间与迟到事件的影响，并给出查询日志与统计接口结果不一致时的定位方法。
以下行号基于当前工作区代码（commit 2b5be1f）。

## 1. 数据链路：事件如何进入小时/天/长期桶，聚合结果如何被读取

### 1.1 写入路径：DNS 事件 → 当前小时桶（内存）

1. DNS 请求处理完成后，`dnsforward.Server.processQueryLogsAndStats`
   （`internal/dnsforward/stats.go:19`）在同一把 `serverLock` 读锁下依次调用
   `logQuery`（写查询日志）和 `updateStats`（写统计）。两者各自有独立的
   开关判断：`shouldLog` 走 `queryLog.ShouldLog`，`shouldCountStat` 走
   `stats.ShouldCount`（`internal/dnsforward/stats.go:76-93`），
   **忽略列表和客户端计数开关是两套配置**，这是不一致的第一个来源。
2. `updateStats`（`internal/dnsforward/stats.go:140`）构造 `stats.Entry`
   （Domain、Client、Result、ProcessingTime、UpstreamStats），调用
   `s.stats.Update(e)`。**Entry 里没有任何时间戳字段**
   （见 `internal/stats/unit.go:56-82` 的 Entry 定义）。
3. `StatsCtx.Update`（`internal/stats/stats.go:271`）检查
   `enabled`/`limit`、校验 Entry，然后直接 `s.curr.add(e)`，把事件累加进
   **当前内存 unit**。`unit.add`（`internal/stats/unit.go:321`）按 Result
   分别累加 `domains`/`blockedDomains`、`clients`、`nResult`、
   `nTotal`、`timeSum` 以及上游响应计数。

关键结论：**事件进入哪个桶，完全由 `Update` 被调用的墙钟时刻决定，而不是
事件本身携带的任何时间**。事件一旦落入某个 unit，就永远不会再迁移。

### 1.2 桶的划分：只有"小时桶"，没有独立的天桶/长期桶

- 桶 ID 由 `newUnitID`（`internal/stats/unit.go:183`）生成：
  `uint32(time.Now().Unix() / 3600)`，即 **Unix 纪元以来的绝对小时数（UTC）**。
  天、周、90 天等"长期桶"在存储层不存在，全部是读取时对小时桶的二次聚合。
- `periodicFlush`（`internal/stats/stats.go:497`）循环调用 `flush()`：
  重新生成当前 ID，若与 `s.curr.id` 不同（小时已切换），则在 `flushDB`
  （`internal/stats/stats.go:446`）中：
  1. 把 `s.curr` 换成新的空 unit（此后事件进入新小时桶）；
  2. 把旧 unit 序列化（`unit.serialize`）后以 gob 编码写入 bbolt，
     bucket 名为 8 字节大端 ID（`idToUnitName`）；
  3. 删除 ID 为 `id - limit` 的过期 bucket（保留窗口 = `limit` 小时，
     `limit` 即配置的天数换算成小时）。
- 序列化时 `convertMapToSlice` 会把 domains/blockedDomains/clients/upstreams
  **各自截断到 Top 100**（`maxDomains`/`maxClients`/`maxUpstreams`，
  `internal/stats/unit.go:21-28, 267-277`）。落盘即有损。
- 未跨小时时 `flush()` 返回 `sleepFor = time.Second`，即每秒轮询一次；
  进程正常退出时 `Close()`（`internal/stats/stats.go:239`）会把当前 unit
  落盘。

### 1.3 重启与"历史补算"

`New()`（`internal/stats/stats.go:156`）启动时：

- `deleteOldUnits(tx, id - limit - 1)` 清理保留窗口之外的旧 bucket；
- `loadUnitFromDB(tx, id)` 把**当前小时**已落盘的部分加载回来，
  `s.curr.deserialize(udb)` 后继续累加——同一小时内重启不会丢已落盘数据，
  这相当于对当前小时桶的"补算/续写"；
- 停机跨越的整小时**没有任何补算机制**：`loadUnits` 读到缺失的 bucket 时
  只填一个全零的空 `unitDB`（`internal/stats/stats.go:575-580`），
  图表上表现为 0 值的洞，而不是数据丢失报错。

### 1.4 读取路径：GET /control/stats

1. `handleStats`（`internal/stats/http.go:60`）解析可选的 `?recent=`
   毫秒参数（`parseRecent`，必须是 1 小时的整数倍且 ≤ 配置的 limit），
   换算成小时后调用 `getData(limitHours)`。
2. `loadUnits`（`internal/stats/stats.go:552`）在写事务中读取
   `[curID-limit+1, curID)` 的历史小时桶，**再追加当前内存 unit 的即时
   序列化结果**，凑满 `limit` 个 unit。因此统计接口是准实时的，
   当前小时的数据立即可见。
3. `dataFromUnits`（`internal/stats/unit.go:441`）分三类输出：
   - **Top 列表**：`topsCollector` 把各小时桶的（已截断到 100 的）Top 列表
     按名称累加，再取全局 Top 100；top_queried/top_blocked 在读取时还会再过
     一遍 `s.ignored` 忽略引擎，top_clients 在读取时再过一遍
     `shouldCountClient`（`topClientPairs`）——**忽略配置是读时生效的，
     改配置会"追溯性"改变展示结果而不改存储**。
   - **总计数**：`NumDNSQueries` 等是**全部 `limit` 个小时桶**的直接求和。
   - **时间序列**：`fillCollectedStats`（`internal/stats/unit.go:487`）。
     `daysCount = limit/24`，当 `daysCount > 7`（即 30/90 天档）切换为
     `time_units=days`，由 `fillCollectedStatsDaily` 把小时桶按
     `i / 24` 归并成天；否则按小时输出。

### 1.5 前端展示

- `client/src/actions/stats.ts` 的 `getStats()` 调 `GET /control/stats`
  （不带 `recent`，即整个配置区间），把 top 列表规范化后存入 redux。
- 图表 `client/src/components/ui/Line.tsx` 用 `buildChartData`
  （`client/src/components/ui/lineUtils.ts:32`）把数组下标映射为时间标签：
  小时档用 `subHours(now, hoursAgo)`、天档用 `subDays(now, ...)`，
  **全部按浏览器本地时区、以"距现在的相对偏移"生成标签**，而不是后端桶的
  真实 UTC 边界。
- 副标题（`client/src/components/Dashboard/index.tsx:57`）根据
  `time_units` 显示"最近 N 小时/天"。

## 2. 时区、边界时间与迟到事件的影响

### 2.1 时区

- 存储与聚合**全程 UTC**：桶 ID 是 UTC 小时，天档归并用
  `countHours(curHour, days)`（`internal/stats/unit.go:545`）以
  `curHour % 24` 对齐，即**按 UTC 零点切天**。
- 前端标签是**浏览器本地时区**。对 UTC+8 的用户，"天"桶实际是
  本地 08:00–次日 08:00 的数据，却贴着本地日期的标签；跨天边界附近
  会出现"今天的数据被记到昨天"的观感。小时档标签用 `subHours(now, N)`
  按取数时刻反推，与桶的真实 UTC 边界最多可错位近 1 小时（见 2.2）。
- 代码中没有可配置的统计时区；这是设计使然而非 bug，但排查时必须把
  后台图表的"天"理解为 UTC 天。

### 2.2 边界时间（小时切换）

- 切换由每秒轮询驱动，整点后**最多约 1 秒内**事件仍写入旧小时桶
  （`flush()` 的 `sleepFor = time.Second`）。所以小时桶边界不是严格的
  墙钟整点，而是"整点后第一次轮询"。
- 前端小时档标签以"距 now 几小时"计算，而后端桶按 UTC 整点对齐：
  在 10:00:30 取数时，当前桶（10:00–11:00）的标签是"10:00"，但若在
  10:59 取数，上一桶（09:00–10:00）标签会被算成"10:00"附近，标签与桶
  边界的对应关系随取数时刻漂移。
- 天档归并时 `fillCollectedStatsDaily` 会**丢弃窗口开头不足一天的零头
  小时**（`units = units[len(units)-hours:]`，注释 `align_ceil(24)`），
  使序列恰好是若干个完整 UTC 天（最后一天是不完整的当天）。但总计数
  `NumDNSQueries` 等是对**全部 `limit` 个小时**求和的——代码里
  `fillCollectedStatsDaily` 上方的 TODO 也承认了这一点。因此 30/90 天档下
  **图表每天柱子之和 ≠ 顶部卡片总数**，差值就是被裁掉的头部零头小时，
  属于读取语义差异，不是数据丢失。

### 2.3 迟到事件与异常重启

统计事件是同步计数的，真正的"迟到"来自三处：

1. **崩溃丢失**：当前小时桶只在整点切换或 `Close()` 时落盘。进程被
   kill 时，自上次整点以来最多 1 小时的统计**永久丢失**；而查询日志按
   `MemSize` 条数刷盘（`internal/querylog/qlog.go` 的 `Add` 与
   `flushLogBuffer`），持久化粒度细得多。崩溃后对照两边，统计会明显
   少于日志。
2. **切换窗口**：整点后约 1 秒内处理完的事件计入上一小时（见 2.2），
   而查询日志条目时间戳是 `newLogEntry` 里的 `time.Now()`
   （`internal/querylog/qlog.go:189`），按本地时间看会落在"新一小时"。
   逐条对账时这部分事件像"被记错桶"。
3. **Top 100 截断**：`serialize` 每小时只保留各类 Top 100。某域名若
   每小时都排在 100 名之外，即使 24 小时累计量能进全天 Top，也已在
   落盘时被丢弃——**Top hosts 是"每小时 Top 100 的累加"，不是全量计数
   的排序**，小时分布越扁平，与查询日志现算结果的偏差越大。同理，
   某域名只在个别小时进前 100，其它小时的量被截掉，总计会被低估。

## 3. 查询日志 vs 统计接口：不一致的归因判断

两套系统的差异对照：

| 维度 | 查询日志 | 统计 |
| --- | --- | --- |
| 时间基准 | 条目自带 `Time: time.Now()` | 无时间戳，按 `Update` 时刻归入当前小时桶 |
| 内存形态 | 环形缓冲（`MemSize` 条） | 当前小时 unit |
| 持久化粒度 | 缓冲区满即异步刷文件 | 整点切换 / 正常退出，最粗 1 小时 |
| 保留策略 | 按文件轮转间隔 | 按 `limit` 小时删 bucket |
| 忽略/计数开关 | `queryLog.ShouldLog` | `stats.ShouldCount`（独立配置） |
| 读取 | 内存缓冲 + 文件搜索，按时间过滤 | 历史桶 + 当前 unit，读时再套忽略规则 |

按现象归因：

1. **数据丢失**
   - 特征：统计总数系统性少于查询日志条数，且差值集中在最近一次
     非正常退出前的一小时内 → 当前桶未落盘（2.3-1）。
   - 特征：Top hosts 中某些域名缺失或偏低，但总数基本吻合 →
     每小时 Top 100 落盘截断（2.3-3），属于设计性有损。
   - 特征：某客户端/域名两边都没有 → 检查两边各自的忽略列表与
     `ShouldCountClient` 配置，是配置差异而非丢失。

2. **延迟**
   - 统计接口本身包含当前内存桶，几乎无延迟；若刚刷新仍差几条，
     多为整点切换的约 1 秒轮询窗口（2.2），下一秒即自愈。
   - 查询日志文件搜索可能略滞后于内存缓冲（异步刷盘），日志页
     "少最后几条"属于此类，与统计无关。

3. **桶归属**
   - 特征：总量一致，但某小时/某天柱子此消彼长 → 边界事件被计入
     相邻桶（切换窗口），或本地时区与 UTC 天边界错位（2.1、2.2）。
   - 特征：30/90 天档图表首日的量明显偏少 → 头部零头小时被
     `fillCollectedStatsDaily` 裁掉，是聚合对齐行为。

4. **读取语义**
   - 特征：图表柱子之和 < 顶部卡片总数 → 天档下载掉了零头小时但
     总计包含它们（`dataFromUnits` 对全量 unit 求和），语义如此。
   - 特征：把域名加进统计忽略列表后，历史 Top 立刻变化但总数不变 →
     忽略是读时过滤（`topsCollector`），存储未改。
   - 特征：`?recent=` 查询结果与预期区间差一点 → 该参数被强制
     取整到小时（`parseRecent`），且窗口终点是当前正在累积的小时桶。

## 4. 结论

- 统计存储层只有 UTC 小时桶；天与长期视图是读时聚合，天边界按 UTC 零点，
  前端标签按浏览器本地时区，两者在跨时区场景下必然存在观感错位。
- 事件不带时间戳，桶归属由处理时刻决定；整点切换有约 1 秒的归属模糊窗口，
  崩溃会丢失当前小时未落盘的计数，这是与查询日志对账时最主要的真实丢失源。
- Top hosts 是"每小时 Top 100 累加"的近似值，且忽略规则读时生效；
  与查询日志现算结果存在偏差是预期行为。
- 遇到不一致时，按"总量是否吻合 → 是否集中在边界/首末日 → 是否只影响
  Top 列表 → 是否随忽略配置变化"的顺序，即可分别定位到丢失、桶归属、
  截断或读取语义。

