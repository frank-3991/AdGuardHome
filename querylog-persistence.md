# AdGuard Home 查询日志的持久化生命周期与一致性分析

本文基于代码实际实现（`internal/querylog/`、`internal/dnsforward/stats.go`、`internal/home/`），梳理一条 DNS 查询事件从产生、内存缓冲、落盘、轮转归档到被检索的完整生命周期，并重点分析**并发写入**与**磁盘空间不足**两种场景下，用户看到的历史结果与真实查询之间可能出现的差异。

## 1. 生命周期总览

```
DNS 请求处理完成
   |  (dnsforward/stats.go: logQuery -> s.queryLog.Add(p))
   v
内存环形缓冲区 buffer（RingBuffer，容量 = MemSize，默认 1000）
   |  满足条件（Enabled && FileEnabled && Len >= MemSize）后异步触发
   v
flushLogBuffer -> encodeEntries（JSON 序列化并清空 buffer）-> flushToFile（追加写）
   v
数据文件 <BaseDir>/querylog.json（每行一条 JSON）
   |  periodicRotate 每小时检查：文件首条记录时间 + RotationIvl <= now
   v
归档文件 querylog.json.1（os.Rename 覆盖式轮转，仅保留一代）
   v
检索：GET /control/querylog -> search = searchMemory + searchFiles（反向读 + 二分定位）
```

## 2. 各阶段实现细节

### 2.1 产生与内存缓冲（qlog.go）

- `dnsforward.Server.logQuery` 在每次应答后构造 `querylog.AddParams`（问题、应答、上游、过滤结果、耗时、客户端 IP/ID/协议等），调用 `queryLog.Add`。
- `Add` 先做过滤：`Enabled` 为假直接丢弃；`ShouldLog`（ignored 域名、客户端级 `IgnoreQueryLog`）在更上游就决定该查询**根本不进入日志**。这是"真实查询"与"日志"之间的第一类设计性差异。
- 通过校验的条目被 `newLogEntry` 打上 `time.Now()` 时间戳后 `buffer.Push` 进环形缓冲区。注意时间戳在 `Add` 内生成，高并发下进入 buffer 的顺序由 `bufferLock` 的获取顺序决定，与时间戳的先后**不保证严格一致**（检索端用稳定排序缓解，见 2.4）。
- 当 `buffer.Len() >= MemSize` 且 `FileEnabled` 时，置 `flushPending = true` 并**启动一个 goroutine** 执行 `flushLogBuffer`。刷盘是异步的，不阻塞 DNS 应答路径。
- 若 `FileEnabled = false`（纯内存模式），环形缓冲写满后**最老的条目被直接覆盖**，用户只能看到最近 `MemSize`（默认 1000）条，且接口返回的 `total` 只是当前 buffer 长度，并非历史真实总量。

### 2.2 持久化（querylogfile.go）

- `flushLogBuffer` 用 `fileFlushLock` 串行化刷盘；`encodeEntries` 在 `bufferLock` 下把 buffer 中**当时所有**条目 JSON 编码到内存字节流，然后**立即 `buffer.Clear()` 并复位 `flushPending`**；随后 `flushToFile` 在 `fileWriteLock` 下以 `O_WRONLY|O_CREATE|O_APPEND` 打开 `querylog.json` 一次性 `Write`。
- 关键时序：**先清 buffer，后写文件**。编码与写盘之间这批条目处于"既不在内存也不可见于文件"的窗口期（见第 3 节）。
- 写盘**没有 `fsync`**，也没有校验和/长度前缀等自描述 framing，只有"一行一条 JSON"的约定。进程崩溃或掉电时，最后一次 `Write` 之后、内核页缓存刷盘之前的数据会丢失。
- `Shutdown` 时会做最后一次 `flushLogBuffer`，正常退出不丢 buffer 中的数据。

### 2.3 轮转与归档（querylogfile.go: periodicRotate / checkAndRotate / rotate）

- `Start` 启动 `periodicRotate`：启动时先检查一次，之后每 1 小时检查一次（`rotationCheckIvl`，见 issue #3823）。
- 轮转条件：读取 `querylog.json` **文件头 512 字节**中第一条记录的 `"T"` 时间戳，若 `首条时间 + RotationIvl <= now` 则轮转。因此轮转时刻以"文件里最老记录"为基准，实际轮转可能滞后于配置间隔（每小时才检查一次）。
- `rotate` 只是 `os.Rename(querylog.json, querylog.json.1)`：**覆盖式**重命名，上一代 `.1` 被直接销毁。即只保留"当前文件 + 上一代"两代，实际保留时长约为 1~2 倍 `RotationIvl`（`Config.RotationIvl` 注释也明确说明了这一点）。
- **关于"压缩"**：`qlog.go` 中 `queryLogFileName` 的注释写着 `".gz" extension is added later during compression`，但当前代码中**不存在任何 gzip 压缩逻辑**（全仓库的 gzip 只出现在 updater 中）。归档文件就是明文 JSON 的 `querylog.json.1`，该注释是过时/未实现的规划。磁盘占用没有任何压缩缓解。
- `clear`（POST /control/querylog_clear）会清空 buffer 并删除 `querylog.json` 与 `querylog.json.1`。
- **轮转与刷盘之间没有任何锁协调**：`rotate` 不持有 `fileWriteLock` / `fileFlushLock`。

### 2.4 检索（http.go / search.go / qlogreader.go / qlogfile.go / decode.go）

- `GET /control/querylog` -> `search`：先 `searchMemory`（反向遍历内存 buffer，浅拷贝后补 client 信息），再 `searchFiles`，最后合并。
- `searchFiles` 用 `qLogReader` 同时打开 `querylog.json.1` 和 `querylog.json`（从旧到新排列），**从最新文件的末尾反向逐行读取**。
- 分页定位：请求带 `older_than` 时，`seekTS` 在文件内做**二分查找**定位时间戳——该算法**强依赖文件内记录按时间单调递增**这一假设。
- 性能保护：单次请求最多扫描 `maxFileScanEntries = 50000` 条文件记录；响应里的 `oldest` 字段是"本次扫描到的最老记录时间"，前端用它作为下一页的 `older_than` 继续翻页。因此深历史需要多轮请求，单次请求可能"看起来没有更多结果"。
- 合并阶段 `finalizeSearchResults` 对内存+文件结果按时间**倒序稳定排序**（缓解 issue #2293 中 buffer 与文件拼接处的乱序），再应用 offset/limit。
- 过滤分两级：`quickMatch` 在原始 JSON 行上做字符串级预筛，通过后才 `decodeLogEntry` 完整解码并做 `match` 精确匹配；ignored 域名和 `IgnoreQueryLog` 客户端的历史记录在读取侧同样被过滤。
- 匿名化是**展示层**行为：`entryToJSON` 输出时才对 IP 做 `AnonymizeIP`，磁盘文件里保存的是完整客户端 IP。

## 3. 并发写入时用户可能看到的差异

以下按"用户视角的现象"组织，括号内是代码根因。

1. **实时列表短暂缺一批（最多约 MemSize 条）**。`encodeEntries` 在 `bufferLock` 下先 `buffer.Clear()`，`flushToFile` 随后才写盘。在这两步之间发起的查询：内存里已没有这批条目，文件里还没有，两边都搜不到。下一次刷新（写盘完成后）又会"冒出来"。这是实时观察时最常见的瞬态空洞。

2. **轮转瞬间历史重复或丢失**。`rotate` 与刷盘、检索均无锁协调：
   - 若 flush goroutine 已以追加模式打开 `querylog.json`，轮转 `Rename` 发生后，该 fd 会继续写入**已改名为 `.1` 的 inode**：新条目被追加到归档文件末尾，而新的 `querylog.json` 从空开始。结果是 `.1` 尾部出现时间戳比 `querylog.json` 头部还新的记录——文件内时间单调性被破坏。
   - `seekTS` 的二分查找依赖时间有序，上述乱序会使二分定位**收敛到错误位置**，深翻页时表现为某段历史被跳过或重复。
   - 检索恰好在打开两个文件之间发生轮转：`querylog.json` 与 `querylog.json.1` 可能指向**同一个 inode**（读到重复条目），或旧 `.1` 刚被覆盖（丢失一整代历史，最多一个 RotationIvl 的数据）。

3. **条目顺序偶发错乱**。高并发下 `Add` 打时间戳与入 buffer 不是同一临界区，buffer 内顺序与时间戳顺序可能局部颠倒；`finalizeSearchResults` 的稳定排序只是"部分缓解"（注释原文），同毫秒级的相邻条目仍可能前后颠倒。另外 `Add` 里留有 TODO：`"Fix occasional rewrite of entires"`，说明作者已知 flush 触发路径上存在偶发的重复/重写问题（两个 flush goroutine 在 `fileFlushLock` 上排队时，第二个会看到空 buffer 并记录 `"nothing to write to a file"` 错误日志，属无害但会污染日志）。

4. **纯内存模式下老数据静默蒸发**。`FileEnabled = false` 时环形缓冲覆盖最老条目，无任何提示；`total` 字段也不再反映真实查询总量。

5. **clear 与并发写/读的竞态**。`clear` 持有 `fileFlushLock` 但不持有 `fileWriteLock`：与正在进行的 `flushToFile` 并发时，已删除的文件可能被 flush 的 `O_CREATE` 重新创建，用户"清空后"又看到少量旧条目复活；正在读取这些文件的 `qLogReader` 在 Unix 上继续读到已 unlink 的旧数据（结果基于已删除内容），在 Windows 上则删除直接失败。

## 4. 磁盘空间不足时用户可能看到的差异

1. **整批条目静默丢失（历史出现空洞）**。`encodeEntries` 在写盘**之前**就清空了 buffer。若 `flushToFile` 因 ENOSPC 失败，该批（最多 MemSize 条）条目既不在内存也不在磁盘，**彻底丢失**，唯一痕迹是 `"flushing after adding"` 错误日志。用户看到的历史里会出现一段与失败时长对应的空白，且无任何 UI 提示。

2. **文件末尾出现截断的 JSON 行，进而可能让整个文件检索失效**。`f.Write` 在磁盘写满时可能只写入部分字节，`querylog.json` 末尾留下半行 JSON：
   - `seekTS` 二分查找的探针若落在该行，`readQLogTimestamp` 解析失败返回 0，`seekTSStep` 直接报错；`setQLogReader` 对 seek 失败的处理是**返回 nil reader**，`searchFiles` 整体返回空——用户带 `older_than` 翻页时**所有文件历史都消失**，只剩内存 buffer 里的最近条目。
   - 反向逐行扫描（`ReadNext`）遇到截断行时，`decodeLogEntry` 只记 debug 日志并尽力解码，该行可能以缺字段的脏条目形式混入结果，或被 `quickMatch` 静默跳过。
   - 由于 `readFileFirstTimeValue` 只读文件头，轮转判断不受尾部损坏影响，损坏行会一直留到下一次轮转才被"带走"。

3. **没有 fsync，崩溃窗口比想象中大**。即使 `Write` 成功返回，数据也只在内核页缓存。磁盘满常伴随的运维操作（强制重启、容器被杀）会把最近若干次 flush 一起丢掉，用户看到的"最新历史"可能停留在几分钟前。

4. **无压缩、单文件追加，磁盘压力被放大**。归档不做压缩（见 2.3），明文 JSON 逐行追加；磁盘紧张的环境更容易进入上述 ENOSPC 路径，而代码对写失败没有任何重试或降级（比如保留 buffer 等待下次 flush）。

## 5. 结论

- 设计上，查询日志是**尽力而为（best-effort）**的观测设施：异步刷盘、先清 buffer 后写盘、无 fsync、无写失败重试、覆盖式单代归档。它以不阻塞 DNS 数据面为最高优先级，持久性是有意让渡的。
- 并发写入下的差异主要是**瞬态**的：flush 窗口期的短暂缺失、轮转瞬间的重复/乱序，多数会在下一次查询自愈；但轮转与 flush 竞争造成的 `.1` 文件时间乱序会**持续**影响二分定位，直到该文件被覆盖。
- 磁盘不足下的差异是**永久性**的：失败批次直接丢失形成历史空洞，截断行还可能让文件级搜索整体降级为"只剩内存数据"。用户看到的历史与真实查询之间的偏差，在这类场景下既无法从 UI 察觉，也无法事后恢复。

