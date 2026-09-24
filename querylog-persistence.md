# AdGuard Home 查询日志的持久化生命周期与一致性分析

本文基于当前代码库（`internal/querylog`、`internal/dnsforward`、`internal/home`）的实际实现，
梳理一条 DNS 查询事件从产生、内存缓冲、落盘、轮转归档到检索的完整生命周期，
并重点分析**并发写入**与**磁盘空间不足**两种场景下，用户在前端看到的历史结果与真实发生的查询之间可能出现的偏差。

## 1. 生命周期总览

```
DNS 请求 → dnsforward.processQueryLogsAndStats → queryLog.Add
        → 内存环形缓冲区 (RingBuffer, 默认 1000 条)
        → 达到阈值后异步 goroutine flush → 追加写入 querylog.json
        → 每小时检查一次，按时间轮转: querylog.json → querylog.json.1 (覆盖旧归档)
        → GET /control/querylog: 内存缓冲 + 两个文件 合并检索 (倒序)
```

### 1.1 事件产生与入缓冲

- 每个 DNS 请求处理完毕后，由 `dnsforward.Server.processQueryLogsAndStats`
  （[internal/dnsforward/stats.go](internal/dnsforward/stats.go)）调用 `logQuery`，
  最终调用 `queryLog.Add(params)`（[internal/querylog/qlog.go](internal/querylog/qlog.go)）。
- `Add` 先读配置（`confMu` 读锁），未启用则直接丢弃；随后构造 `logEntry`
  （时间戳在 `newLogEntry` 里取 `time.Now()`），在 `bufferLock` 写锁下
  `buffer.Push(entry)`。
- 缓冲区是 `container.RingBuffer[*logEntry]`，容量为 `MemSize`（默认 1000，
  见 `internal/home/config.go` 中 `MemSize: 1000`）。**环形缓冲写满后新条目会静默覆盖最老的未 flush 条目**，
  这是后续数据丢失场景的根源之一。
- 当 `buffer.Len() >= memSize` 且 `FileEnabled` 时，置 `flushPending = true` 并
  **启动一个异步 goroutine** 执行 `flushLogBuffer`。注意源码中此处有
  `TODO(s.chzhen): Fix occasional rewrite of entires.`（qlog.go:258），
  作者自己已标注该路径存在偶发问题。

### 1.2 持久化（flush）

`flushLogBuffer`（[internal/querylog/querylogfile.go](internal/querylog/querylogfile.go)）分两步：

1. `encodeEntries`：持有 `fileFlushLock` + `bufferLock`，把缓冲里所有条目
   JSON 序列化到内存 `bytes.Buffer`，然后**立即 `buffer.Clear()` 并复位
   `flushPending = false`**。
2. `flushToFile`：在 `fileWriteLock` 下以 `O_WRONLY|O_CREATE|O_APPEND`
   打开 `querylog.json`，一次性 `Write` 后 `Close`（**没有 fsync**）。

关键事实：**条目先从内存清除，再写文件**。这两步之间不是原子的，
中间任何失败（磁盘满、权限、进程崩溃）都会永久丢失这批条目。

### 1.3 轮转与归档

- `Start` 时启动 `periodicRotate` goroutine：启动时先检查一次，之后**每小时**检查一次
  （`rotationCheckIvl = 1 * time.Hour`，与配置的轮转间隔无关）。
- `checkAndRotate` 读取 `querylog.json` **第一条记录**的时间戳
  （`readFileFirstTimeValue`，只读文件头 512 字节），若
  `第一条时间 + RotationIvl < now` 则执行 `rotate`。
- `rotate` 只是 `os.Rename(querylog.json, querylog.json.1)`，**直接覆盖旧归档**。
  本版本没有 gzip 压缩（qlog.go 顶部 ".gz extension is added later during compression"
  的注释是过时的，仓库中没有任何 querylog 压缩代码）。
- 因此磁盘上最多同时存在两代文件，实际保留时长在 **1～2 倍轮转间隔**之间
  （Config 注释也明确说明 "the actual log retention time is twice the interval"）。
  默认 `Interval = 90 天`，即历史最多约 180 天，超出部分**不可恢复**。
- 归档"恢复"并不存在主动流程：检索时 `setQLogReader` 固定按
  `[querylog.json.1, querylog.json]`（从旧到新）打开两个文件，
  不存在的文件直接跳过（`os.ErrNotExist` → `continue`）。

### 1.4 检索

`GET /control/querylog` → `handleQueryLog` → `search`（[internal/querylog/search.go](internal/querylog/search.go)）：

1. `searchMemory`：在 `bufferLock` 下对内存缓冲 `ReverseRange`（新→旧）匹配。
2. `searchFiles`：构造 `qLogReader`，**从文件末尾倒序逐行读**；
   若带 `older_than` 参数，先在文件内做**二分查找**（`seekTS`，最多 100 次探测）
   定位到该时间戳的记录。文件读取假设**记录按时间严格升序**。
3. 默认每次最多扫描 50000 条文件记录（`maxFileScanEntries`），
   显式传 `offset` 时不限。
4. 内存结果与文件结果合并后按时间**稳定排序**（新→旧），再应用 offset/limit，
   返回 `oldest` 供前端翻页。
5. 解码端（`decodeLogEntry`）对未知字段、旧字段名（如 `"Time"` vs `"T"`）宽容，
   单行解码失败只记 debug 日志，不会中断整个搜索。

## 2. 并发写入：用户可能看到什么偏差

### 2.1 两次 flush 乱序落盘 → 文件不再严格按时间排序

`encodeEntries` 与 `flushToFile` 分别持有不同的锁（`bufferLock` 已释放后才竞争
`fileWriteLock`）。虽然 `fileFlushLock` 让两次 flush 串行进入，但考虑如下时序：

- flush A 序列化条目 1..1000 并清空缓冲；
- flush B 序列化条目 1001..1500 并清空缓冲；
- A、B 竞争 `fileWriteLock` 的顺序不保证与序列化顺序一致——
  实际上 `fileFlushLock` 保证了 A 先进入 `flushLogBuffer`，
  但 A 在 `encodeEntries` 阶段持有锁的时间很长（JSON 序列化），
  真正的写入顺序依赖同一锁的传递，**顺序在常规路径下能保持**；
  然而源码 qlog.go:258 的 TODO（"Fix occasional rewrite of entires"）表明
  作者已观察到缓冲条目被偶发重写/覆盖的现象。

更现实的风险来自**环形缓冲覆盖**：flush goroutine 是异步的，
若它被调度延迟（或前一次 flush 还持有 `fileFlushLock`），
而查询洪峰继续到达，`Push` 会在缓冲写满后**覆盖尚未序列化的最老条目**。
这些查询真实发生过，但永远不会出现在文件里——
用户看到的历史在该时间段出现**无规律的空洞**，且无任何界面提示。

### 2.2 文件乱序对检索的放大效应

一旦文件内记录不再严格按时间升序（2.1 的乱序落盘、或轮转瞬间的写入，见 2.3），
依赖有序假设的 `seekTS` 二分查找会失效：

- 可能返回 `errTSNotFound`，`setQLogReader` 此时**静默返回 nil reader**，
  搜索结果只剩内存缓冲里的条目——用户翻页时历史"突然消失"，没有任何错误提示；
- 也可能定位到错误的记录，导致以 `older_than` 翻页时**跳过一批记录或重复返回一批记录**。

`finalizeSearchResults` 最后的排序只能修正**单页内**的顺序，
无法修复跨页的分页错位。

### 2.3 flush 与 rotate 并发

`rotate`（`os.Rename`）**不持有 `fileFlushLock` / `fileWriteLock`**：

- Linux/macOS 上 rename 进行中的 flush 会继续写入已改名为 `querylog.json.1` 的 inode，
  于是**最新的条目混进了归档文件**，两个文件的时间边界不再单调；
  后续检索跨文件倒序读时会出现时间回跳。
- Windows 上 rename 一个被打开的文件会失败，`checkAndRotate` 只记错误日志，
  本轮轮转被跳过（一小时后重试），期间文件持续增长。

### 2.4 检索与写入并发

- `searchMemory` 与 `searchFiles` 之间不持有同一把锁。若两次调用之间发生一次 flush，
  同一批条目既在内存快照里、又已写入文件，**同一页结果出现重复条目**；
  反之若 flush 恰好在 `searchMemory` 之前完成，则无影响。
- 检索读文件时，并发的 `flushToFile` 可能正在追加。读者以打开时刻的文件大小倒序读，
  可能读到**写了一半的最后一行**（JSON 被截断）。解码端对此宽容：
  该行要么被 `quickMatch` 丢弃，要么解码出字段残缺的条目——
  用户可能看到一条缺少 answer/rules 的记录，下一次刷新又恢复正常。
- 轮转发生在 `newQLogReader` 打开两个文件**之间**时，
  可能把同一个 inode 打开两次（重复结果）或漏掉刚 rename 的文件（结果缺口）。

### 2.5 与统计模块的口径差异

`processQueryLogsAndStats` 中 querylog 与 stats 是**独立**更新的，
且 stats 有自己的缓冲与落盘节奏。查询日志因上述任何原因丢条目时，
统计数字（总查询数）仍然计入——用户在"仪表盘总数"与"查询日志列表"
之间会看到对不上的差额，这正是缓冲覆盖/写盘失败在 UI 上最直观的可观测信号。

## 3. 磁盘空间不足：用户可能看到什么偏差

### 3.1 写失败后条目被静默丢弃（无重试）

`flushLogBuffer` 的顺序是"先清缓冲、后写文件"。磁盘满时：

- `os.OpenFile` 或 `f.Write` 返回 `ENOSPC`，错误仅被
  `Add` 里的 goroutine 记为 error 日志（"flushing after adding"）；
- 但 `encodeEntries` **已经清空了缓冲并复位 `flushPending`**，
  这批已序列化的条目就此蒸发，**没有任何重试机制**；
- 用户侧表现：历史记录出现一段与磁盘写满时段吻合的空白，
  而期间 DNS 解析实际完全正常。

### 3.2 部分写入 → 文件尾部出现损坏行

`f.Write` 在磁盘满时可能返回 `n < len(b)` 的短写：文件里留下半行 JSON。
之后磁盘恢复、后续 flush 继续追加，**损坏行永久留在文件中间**。
检索到该行时解码失败被跳过（或产生残缺条目），
用户看到的历史在该位置少一条/多一条畸形记录。

### 3.3 无容量管理，轮转只看时间不看大小

- 轮转完全由时间驱动（且每小时才检查一次），**没有文件大小上限**。
  高 QPS 下 `querylog.json` 在一个间隔内可无限增长直至写满磁盘；
  磁盘满之后又反过来触发 3.1 的静默丢失。
- 没有 fsync：`flushToFile` 仅 `Close`。即使写入"成功"，
  掉电/崩溃仍可能丢失最近一批已对用户可见（在文件搜索结果中出现过）的条目。
- `clear`（`POST /control/querylog_clear`）删除两个文件并清缓冲，
  与并发 flush 通过 `fileFlushLock` 互斥，不会死锁；
  但 clear 之后 `readFileFirstTimeValue` 读不到文件会按"无需轮转"处理，逻辑自洽。

## 4. 结论：用户可见偏差的清单

| 场景 | 用户看到的历史 vs 真实查询 |
| --- | --- |
| 缓冲被洪峰覆盖（flush 异步延迟） | 历史出现无提示的时间空洞，条目永久丢失 |
| flush 写盘失败（磁盘满/权限） | 整批条目静默丢失，无重试；仅服务端日志有记录 |
| 短写/掉电 | 文件尾部或中间出现损坏行，检索时该条缺失或字段残缺 |
| 检索与 flush 并发 | 单页内出现重复条目，或最后一行截断导致的临时残缺条目 |
| 检索与 rotate 并发 | 重复或缺失一段记录；文件时间边界被最新写入污染 |
| 文件乱序 + `older_than` 翻页 | 二分查找失效：翻页跳过/重复记录，甚至只剩内存条目（历史"消失"） |
| 轮转覆盖归档 | 超过 1～2 倍轮转间隔的历史被永久删除，不可恢复 |
| querylog 与 stats 独立记账 | 日志列表条数与仪表盘总数对不上 |

总体而言，这套实现选择了"简单、低开销"的取舍：单文件追加、时间驱动轮转、
无事务、无重试、无 fsync。在正常运行时它足够可靠；但在**写入洪峰、磁盘紧张、
轮转/检索与写入交错**这些边界条件下，历史结果与真实查询之间会出现
丢失、重复、乱序和残缺四类偏差，且除服务端日志外，用户界面上没有任何信号。
```
