# AdGuard Home 统计时间桶分析报告

本文沿实际代码追踪管理后台统计数据的写入、聚合与展示路径，分析时区、边界时间与迟到事件的影响，并对照查询日志给出结果不一致时的归因方法。涉及的代码版本以当前工作区为准。

## 1. 数据流：事件如何进入小时/天/长期桶并被读取展示

### 1.1 写入路径（事件 → 当前小时桶）

DNS 请求处理完成后，由 [internal/dnsforward/stats.go](internal/dnsforward/stats.go) 中的 \`processQueryLogsAndStats\` 统一驱动两条链路：

- 查询日志：\`shouldLog\` 通过后调用 \`s.queryLog.Add(p)\`（[internal/querylog 的 qlog.go](internal/querylog/qlog.go)）。
- 统计：\`shouldCountStat\`（即 \`stats.ShouldCount\`，检查启用状态、忽略域名引擎、客户端忽略设置）通过后调用 \`updateStats\`，构造 \`stats.Entry{Client, Domain, Result, ProcessingTime, UpstreamStats}\` 并调用 \`StatsCtx.Update(e)\`。

关键点：**Entry 不携带任何时间戳**。\`StatsCtx.Update\`（[internal/stats/stats.go](internal/stats/stats.go)）只做三件事：检查 \`enabled/limit\`、\`e.validate()\`、然后 \`s.curr.add(e)\`。也就是说事件落入哪个桶，完全取决于**它到达 \`Update\` 时的墙钟时间**，而不是查询实际发生的时间。

\`curr\` 是一个内存中的 \`unit\`（[internal/stats/unit.go](internal/stats/unit.go)），其 \`id\` 由 \`newUnitID()\` 生成：

\`\`\`go
id = uint32(time.Now().Unix() / 3600)   // 自 UNIX 纪元起的绝对小时数
\`\`\`

这就是"小时桶"：一个以 UTC 整点对齐的小时编号。\`unit.add\` 在内存中累加 \`domains/blockedDomains/clients/upstreams*\` 等 map 以及 \`nResult/nTotal/timeSum\`。

### 1.2 桶切换与落盘（小时桶 → bbolt）

\`Start\` 启动 \`periodicFlush\` 协程。\`flush()\` 每秒检查一次 \`s.unitIDGen()\` 是否与 \`curr.id\` 相同；不同（即跨过了 UTC 整点）则 \`flushDB\`：

1. \`s.curr = newUnit(id)\` —— 先把当前桶换成新的空桶（之后到达的事件进入新小时）；
2. 把旧桶 \`serialize()\` 成 \`unitDB\` 写入 bbolt，bucket 名即 \`idToUnitName(id)\`（8 字节大端小时编号）；
3. \`tx.DeleteBucket(idToUnitName(id - limit))\` —— 删除超出保留期（\`limit\`，默认 90 天，见 [internal/home/config.go](internal/home/config.go) 的 \`90 * timeutil.Day\`）的最旧桶。

锁顺序固定为先 \`confMu\` 后 \`currMu\`，\`Update\` 与 \`flush\` 一致，避免切换瞬间死锁或写错桶。\`Close\` 时也会把 \`curr\` 落盘一次。

### 1.3 历史补算（重启后的续算）

\`New\` 打开数据库后执行 \`s.loadUnitFromDB(tx, id)\`，把**当前小时**已落盘的部分反序列化进新的 \`curr\`（\`deserialize\`），同时 \`deleteOldUnits\` 清理过期桶。因此进程重启不会丢失当前小时已统计的数据，而是**在同一个 UTC 小时桶上继续累加**——这就是"历史补算"的实际机制：补的是当前小时桶，停机期间的小时不会回填，读取时以空桶（全零）补齐。

### 1.4 天桶与"长期桶"：不存在独立存储

存储层只有小时桶。"天"和长期视图是**读取时现算的**：

- \`loadUnits(limit)\` 从 DB 读出最近 \`limit\` 个小时桶（缺失的补空 \`unitDB\`），并**把内存中的 \`curr\` 序列化后追加到末尾**，所以接口返回包含当前未落盘的小时。注意它用可写事务读，以保证看到正在进行的 flush。
- \`fillCollectedStats\`：若 \`limit/24 > 7\`（即保留期超过 7 天），\`TimeUnits\` 置为 \`"days"\`，由 \`fillCollectedStatsDaily\` 把小时桶按 24 个一组累加成天；否则按小时返回。
- 天对齐方式：\`countHours(curHour, days)\` 取 \`curHour % 24\` 得出当前 UTC 日内已过小时数，从**末尾**截取整天数的小时，**丢弃序列开头不足一天的部分**（720 小时可能跨 31 个 UTC 日，只保留 30 个整天 + 当天已过小时）。
- Top hosts / Top clients / Top upstreams：\`topsCollector\` 把所有小时桶的 \`countPair\` 累加进一个 map 后排序截断（各 100 条）。总数类指标（\`NumDNSQueries\` 等）是所有桶的直接求和。

### 1.5 展示

\`GET /control/stats\`（[internal/stats/http.go](internal/stats/http.go) 的 \`handleStats\`）支持 \`?recent=<毫秒>\` 参数缩短回看窗口，但必须是整小时倍数且不超过配置的 \`limit\`。前端 [client/src/reducers/stats.ts](client/src/reducers/stats.ts) 把 \`dns_queries\` 等数组原样存入 store，[client/src/components/ui/lineUtils.ts](client/src/components/ui/lineUtils.ts) 的 \`formatHistoryLabel\` 用**浏览器本地时间**从 \`Date.now()\` 倒推为每个桶生成 x 轴标签（小时模式 \`subHours\`，天模式 \`subDays\`）。

## 2. 时区、边界时间与迟到事件的影响

### 2.1 时区错位（服务端 UTC vs 前端本地）

- 桶边界由 \`time.Now().Unix()/3600\` 决定，恒为 **UTC 整点**；天聚合按 \`curHour % 24\` 对齐，恒为 **UTC 日界**。服务端完全不感知本地时区。
- 前端标签却用浏览器本地时间标注。对 UTC+8 的用户，一个"天"桶实际覆盖的是本地时间 08:00–次日 08:00，但图表标签把它显示为自然日；小时模式下"HH:00"标签同样是本地整点，而桶切分发生在 UTC 整点（UTC+8 下恰好也是本地整点，所以小时模式标签巧合对齐；在 UTC+5:30、UTC+9:30 这类半小时间时区，小时标签会与桶边界错开 30 分钟）。
- 结论：**天粒度图表在非 UTC 时区下，标签所示日期与桶实际覆盖范围存在系统性偏移**，这不是数据错误，而是展示层的时区语义不一致。

### 2.2 边界时间（整点切换瞬间）

- 切换由 \`periodicFlush\` 每秒轮询驱动，因此新桶的启用最多比真实整点**滞后约 1 秒**：整点后的第一秒内到达的事件仍计入旧小时桶。
- 切换是"先换 \`curr\` 再落盘"，切换后到达的事件只进新桶，**不会回补旧桶**。
- \`Close\` 与 \`flush\` 竞争由 \`currMu\` 保护；\`Close\` 把 \`db\` 置 nil 后，\`flushDB\` 直接放弃落盘（返回 \`cont=true, sleepFor=0\` 使循环退出）。

### 2.3 迟到事件

由于 Entry 无时间戳，"迟到"只可能表现为**到达 \`Update\` 的时刻晚于查询发生时刻**：

- 慢查询（上游超时、重试，\`processingTime\` 可达数秒）若在整点前发起、整点后完成，会计入**完成时**的小时桶，而非发起时的桶。边界附近的计数因此在相邻两小时间"漂移"，但总量守恒。
- 进程停机期间的查询根本不存在（服务不可用），不会补算；重启后只有当前小时桶会被续算（见 1.3）。
- 对 Top hosts 的影响：每个小时桶在 \`serialize\` 时就被截断为**该小时的前 100 个域名/客户端/上游**（\`maxDomains/maxClients/maxUpstreams = 100\`），超出部分**永久丢失**。迟到事件挤进新小时桶后会改变该小时的排名，可能把别的域名挤出前 100；长期 Top 是各小时"已截断"榜单的求和，因此长尾域名在多天视图中被系统性低估甚至消失，而 \`NumDNSQueries\` 不受影响（\`nTotal\` 不截断）。这会造成"总数对、Top 少"的典型现象。

### 2.4 读取时的二次过滤

\`topsCollector\` 在读取时对 TopQueried/TopBlocked 再应用一次当前的忽略域名引擎，\`topClientPairs\` 对 TopClients 再应用一次 \`shouldCountClient\`。因此**修改忽略列表会追溯性地改变 Top 展示，但总数不变**——这是读取语义，不是数据变化。

## 3. 查询日志 vs 统计接口：不一致归因

两条链路在 \`processQueryLogsAndStats\` 中同源，但存储、保留期、过滤规则完全独立：

| 维度 | 查询日志 | 统计 |
| --- | --- | --- |
| 时间戳 | \`newLogEntry\` 里 \`time.Now()\`，逐条记录 | 无时间戳，按到达时刻归入当前 UTC 小时桶 |
| 缓冲 | 内存 ring buffer（\`MemSize\` 条），满或 Shutdown 时 flush 到 \`querylog.json\` | 内存 \`curr\` 桶，每小时落 bbolt |
| 保留 | 按文件首条记录时间 + \`RotationIvl\` 轮转，\`querylog.json\` 改名为 \`.1\`，旧 \`.1\` 被覆盖（实际保留约为轮转间隔的 1–2 倍） | \`limit\` 个小时桶，超时整桶删除 |
| 读取 | 内存 buffer + 两个文件倒序读，\`older_than\` 二分定位 | 最近 \`limit\` 个小时桶 + 当前内存桶 |
| 默认配置 | 轮转 1 天 | 保留 90 天 |

判断不一致原因时按以下顺序排查：

**数据丢失（真的没了）**
- 统计侧：小时桶超过 \`limit\` 被 \`flushDB\`/\`deleteOldUnits\` 删除；每小时 Top-100 截断丢弃长尾；\`Entry.validate\` 失败（空 domain/client、非法 result）被丢弃；写入时 \`ShouldCount\` 因忽略列表/客户端设置/统计被禁用而拒绝。
- 日志侧：\`querylog.json.1\` 被下一次轮转覆盖；\`querylog_clear\`；\`ShouldLog\` 因忽略列表/客户端 \`IgnoreQueryLog\` 拒绝；日志被禁用。

**延迟（稍后会一致）**
- 查询日志的内存 buffer 未满 \`MemSize\` 时未写文件——但搜索接口同时读内存，所以 API 层面不受影响；只有直接翻文件才会觉得"少"。
- 统计的当前小时在内存中，但 \`loadUnits\` 会附上 \`curr.serialize()\`，API 同样立即可见。
- 真正可见的延迟只有：请求仍在处理中（\`processQueryLogsAndStats\` 尚未执行），以及整点切换最多 1 秒的轮询滞后。

**桶归属（总量对、分布不对）**
- 跨整点完成的慢查询落入下一小时桶。
- 天视图按 UTC 日界对齐，且 \`fillCollectedStatsDaily\` 丢弃序列开头不足一天的小时——天数组首元素不是"第一个有数据的小时"，而是对齐后的第一个 UTC 日。
- 前端用本地时间标注 UTC 桶，非 UTC 时区下日期/小时标签错位（见 2.1）。
- 停机跨小时产生全零空桶，图表上出现"空洞"，不是丢数据。

**读取语义（数据没变，口径不同）**
- \`RefuseAny\` 开启时 ANY 查询**不进查询日志但仍计入统计**（\`shouldLog\` 有该判断，\`shouldCountStat\` 没有），导致统计总数 > 日志条数。
- 缓存命中的响应不计入 upstream 统计（\`unit.add\` 跳过 \`IsCached\`），但日志照常记录，且日志把缓存伪造成 upstream 地址。
- 统计的客户端标识优先用 ClientID，日志同时记录 IP 与 ClientID；按 IP 对账时会对不上。
- 忽略列表/客户端忽略在统计侧是**写入时 + 读取时（仅 Top）双重过滤**，修改配置后 Top 榜单会追溯变化而总数不变。
- \`recent\` 参数只接受整小时倍数；\`limit=0\`（统计禁用）时 \`getData\` 返回全空结构而非错误。
- 统计保留期（默认 90 天）通常远长于日志保留（默认 1–2 天），历史总量只能看统计、明细只能看近期日志，二者覆盖窗口天然不同。

**实用对账方法**：比较 \`num_dns_queries\` 与查询日志条数时，先对齐窗口（统计是 UTC 小时桶、日志是绝对时间戳），再扣除 ANY 查询、被忽略域名/客户端、被禁用项；若总数一致而某天/某小时分布不一致，优先怀疑桶归属（UTC 对齐、迟到事件、前端时区标签）；若 Top 榜单与明细不符，优先怀疑 Top-100 截断与读取时忽略过滤，而非数据丢失。

