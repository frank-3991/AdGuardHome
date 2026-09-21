# 远程黑白名单刷新一致性分析

## 结论

当前远程名单刷新采用“先逐名单下载替换文件，再重建整套黑白名单引擎”的方式。下载、解析和重建期间，运行中的 DNS 查询继续使用旧引擎；新的黑名单、白名单存储和引擎都构建完成后，才在同一把 engineLock 写锁内一起替换。正常成功路径中，单次规则匹配不会看到“新白名单 + 旧黑名单”的半切换状态。

但刷新不是端到端事务，存在以下可观察的不一致窗口：

- 文件可能已经替换为新内容，但配置元数据仍旧；随后元数据更新后，运行引擎也可能仍旧。
- 部分失败的名单即使没有替换文件，也可能在同组有其他名单成功时被写回新的 LastUpdated；这会推迟下一次非强制定时刷新。
- 同一次刷新中部分名单失败时，成功名单进入新引擎，失败名单继续保留旧规则，形成同一引擎内的跨订阅版本混合。
- 如果一个刷新组全部失败，流程会跳过引擎重建；另一个组已经落盘的新文件不会在当前进程生效。
- 重建失败时旧引擎继续服务，但新文件和新元数据可能已经落盘；重启后可能直接加载新文件。
- 重复刷新由 refreshLock 的 TryLock 直接拒绝，不排队、不并发执行，也不会清空旧规则。
- 一次 matchHost 匹配是原子代次，但完整 DNS 请求在请求前和上游响应后分两次匹配；刷新若发生在上游往返期间，两个阶段可能使用不同代次。

## 代码范围

运行路径是 internal/filtering 下基于 github.com/AdguardTeam/urlfilter 的实现。internal/filtering/rulelist 中尚未接入主路径的 Storage/Engine 抽象不作为当前运行行为。

关键入口：

- 手动刷新 API：[http.go:366](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/http.go:366)
- 刷新互斥：[filter.go:265](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filter.go:265)
- 定时刷新：[filtering.go:1088](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filtering.go:1088)
- 下载与替换：[filter.go:480](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filter.go:480)
- 元数据同步：[filter.go:359](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filter.go:359)
- 引擎构建与替换：[filtering.go:748](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filtering.go:748)
- 查询匹配：[filtering.go:886](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/filtering/filtering.go:886)
- DNS 请求流水线：[requesthandler.go:33](/Users/dengquan/Downloads/job/code-annotation/fb-workspace/frank-3991/0010-adguardhome-4-8797c37a-b/internal/dnsforward/requesthandler.go:33)

## 状态层次

| 层次 | 内容 | 保护或切换方式 | 查询是否直接使用 |
| --- | --- | --- | --- |
| 远程响应 | HTTP body 或本地绝对路径文件 | 每个名单独立读取到 pending file | 否 |
| 持久文件 | data/filters/<id>.txt | 先写临时文件，成功后 CloseReplace；Unix 为原子 rename，Windows 为 close 后 rename | Unix 旧引擎继续持有旧 inode；Windows 旧引擎构建时已读入字节副本，因此旧查询也不受 rename 影响 |
| 配置元数据 | URL、启用状态、LastUpdated、RulesCount、checksum | conf.filtersMu | 不直接匹配，只影响状态接口和下次重建 |
| 运行引擎 | rulesStorage、rulesStorageAllow、两个 DNSEngine | engineLock | 是 |
| 请求设置 | 保护开关、客户端条件、服务限制等 | 请求开始时复制到 dnsContext.setts | 是；规则引擎本身不是请求开始时的快照 |

refreshLock 串行化刷新流程；filtersMu 只保护配置切片；engineLock 保护运行中的存储和引擎指针。三把锁没有合成一个全局事务。

## 成功刷新时序

| 步骤 | 刷新线程 | 并发查询看到的状态 | 可核对结果 |
| --- | --- | --- | --- |
| 1 | 手动 API 以 force=true 调黑名单或白名单；定时器以 force=true=false 同时刷新两组 | 旧规则 | 手动请求由 whitelist 参数决定刷新哪一组 |
| 2 | tryRefreshFilters 调 refreshLock.TryLock | 不受影响 | 锁竞争失败时手动 API 返回 500 |
| 3 | listsToUpdate 在 filtersMu 读锁下复制启用名单的 ID、URL、checksum | 旧规则 | 禁用名单不刷新；非强制模式按 LastUpdated 和更新间隔过滤 |
| 4 | updateFilterList 逐名单下载、解析、写临时文件 | 旧规则 | 网络耗时不阻塞查询 |
| 5 | checksum 未变化则清理临时文件并 touch 旧文件；变化则 CloseReplace | Unix 旧引擎仍持有旧 inode | 文件新不等于查询已生效 |
| 6 | refreshFiltersArray 拿 filtersMu 写锁并同步元数据 | 仍旧规则 | /filtering/status 可能已显示新规则数和更新时间 |
| 7 | 两组处理完且存在内容变化时，EnableFilters(false) | 旧规则 | false 表示同步重建 |
| 8 | 从当前配置收集自定义规则、黑名单文件路径、白名单文件路径 | 旧规则 | 黑白名单快照在同一 filtersMu 读锁区间收集 |
| 9 | newRuleStorage 和 NewDNSEngine 构建新黑名单、白名单引擎 | 旧规则 | 新引擎构建完成前不修改旧指针 |
| 10 | 获取 engineLock 写锁，关闭旧存储并写入四个新指针 | 已在匹配的查询继续旧代次；新查询等待写锁 | 黑白名单同一临界区切换 |
| 11 | 释放锁并返回 updated=N | 新查询使用新规则 | 手动 HTTP 200 时指针替换已经完成 |

只要 updNum 大于 0，EnableFilters(false) 就会重建黑名单和白名单两组，而不是只重建本次请求的组；它还会重新加入自定义规则。因此，之前一次重建失败后已经落盘但尚未激活的另一组文件，可能在后续任意一组成功刷新时一起被加载。updated=N 只表示本次检测到内容变化的名单数，不代表新引擎中只有这 N 个来源发生代次变化。

单次 matchHost 在进入匹配后持有 engineLock.RLock，先查白名单，命中即返回，未命中再查黑名单。因此白名单和黑名单在这一次调用中属于同一引擎代次。

## 部分失败时旧规则是否有效

### 同组部分失败

updateFilterList 不会因一个名单失败而中断后续名单。失败名单清理临时文件，不替换目标文件，也不写入新 checksum。只要同组至少一个名单成功，syncUpdatedFilters 仍会遍历候选名单；update 无论成功或失败都会设置副本上的 LastUpdated，所以失败项的检查时间也会被写回配置。流程随后继续重建引擎。

结果是：

- 下载成功的名单使用新规则。
- 下载失败的名单继续使用旧文件，旧规则仍有效。
- 下载失败的名单可能显示新的 LastUpdated，但 checksum 和 RulesCount 仍旧；下一次定时刷新会因时间窗口未到而跳过。
- 新引擎因此包含跨名单的新旧混合版本。

这会带来两类误判：

- 漏拦截：失败名单新增的黑名单未加载，或新白名单本应放行但未加载。
- 错误拦截：失败名单仍保留上游已删除的黑名单，或旧白名单继续放行已经不该放行的域名。

### 一个组全部失败

refreshFiltersArray 把“本候选组全部失败”统一标记为 isNetworkErr=true，不管实际是网络、HTTP 状态、本地文件还是解析错误。refreshFiltersIntl 看到该标记后直接返回，不执行 EnableFilters。

因此：

- 黑名单组全失败、白名单组有成功：白名单新文件已落盘，但当前进程继续使用旧白名单和旧黑名单。
- 白名单组全失败、黑名单组有成功：黑名单新文件已落盘，但当前进程继续使用旧黑名单和旧白名单。
- 两组都全失败：文件没有被成功替换，旧规则继续有效。

手动 API 对这种路径返回 200 且 updated=0；逐名单失败原因只在日志中，响应体没有失败明细。由于该组在全部失败时提前返回，配置不会执行该组的元数据同步，这与“同组部分失败”不同。

### 下载成功但无内容变化

CRC32 相同表示规则内容未变化，临时文件会被清理，旧文件保留并更新 mtime。所有名单都无变化时不重建引擎。此时 LastUpdated 表示“最近成功检查”，不表示规则代次发生变化。核对是否切换应看 checksum、规则数或查询命中变化。

### 文件已替换但引擎重建失败

如果 newRuleStorage、存储创建或文件打开在指针替换前失败，initFiltering 直接返回，旧引擎不会被置空，查询继续走旧规则。但此前成功下载的文件和同步过的元数据已经更新。

手动刷新的错误在 enableFiltersLocked 中只记录日志，不向外返回；HTTP 仍可能返回 200 和正数 updated。当前进程可表现为状态显示新规则、查询仍是旧结果。进程重启后会从新文件重建，可能改变结果。

### 下载成功但规则语义为空或部分无效

下载 parser 负责剔除空白、注释、明显二进制字符，并计算 CRC32 和行数；它不保证每行都是 urlfilter 实际加载的 DNS 规则。NewDNSEngine 扫描时会跳过不适用规则，且构造函数不返回扫描错误。

因此状态接口中的 RulesCount 可能大于实际参与 DNS 匹配的规则数。下载显示成功但域名未拦截或未放行时，需要用实际 check_host 或 DNS 查询结果核对。

## 重复刷新

refreshLock.TryLock 保证只有一个刷新流程执行。第二个请求不会等待，也不会与第一个请求并发下载：

- 手动刷新相撞：返回 500，错误信息为 filters update procedure is already running。
- 定时刷新相撞：ok=false，本次不调整退避间隔。
- 第一个刷新结束后再次手动刷新：作为新流程执行。

重复刷新本身不会使旧规则失效。真正需要区分的是刷新与名单增删改并发。新增、删除、修改 URL 的处理不获取 refreshLock，且大多使用 EnableFilters(true) 异步重建；它们与正在执行的刷新可能交错。刷新候选只复制开始时的 ID/URL，后续同步要求当前配置仍匹配相同 ID 和 URL。若中途配置改变，可能出现结果无法同步、文件被删除重命名，或异步重建与同步刷新重建先后覆盖。仅重复点击刷新不属于这种情况。

## 查询线程的交界状态

### 单次规则匹配

重建先完整构建新引擎，再申请 engineLock 写锁；查询在读锁内完成白名单和黑名单匹配。读锁和写锁互斥，所以单次 matchHost 的可见性是：

- 写锁前进入：整次白/黑名单判断使用旧代次。
- 写锁后进入：整次白/黑名单判断使用新代次。
- 不存在同一次 matchHost 中先查新白名单、再查旧黑名单的撕裂。

旧存储在写锁内关闭，仍持有读锁的查询可以安全使用旧文件和旧规则对象。

### 完整 DNS 请求

DNS 处理流水线依次执行请求前过滤、上游解析、响应后过滤：

1. processInitial 在请求开始时复制保护和客户端设置。
2. processFilteringBeforeRequest 对请求域名执行 CheckHost。
3. 未拦截时 processUpstream 向上下游发起解析。
4. processFilteringAfterResponse 对响应中的 CNAME、A、AAAA、HTTPS 记录再次匹配。

请求前和响应后是两次独立获取读锁的匹配，不跨上游网络往返保持同一规则代次。若刷新发生在第 2 步和第 4 步之间，可能出现：

| 边界变化 | 可能的最终误判 |
| --- | --- |
| 请求域名旧规则放行、新规则拦截 | 请求已经发往上游；若响应记录无法被后置规则匹配，可能返回本应拦截的答案；相关 CNAME/IP 命中时才被后置拦截 |
| 请求域名旧规则拦截、新规则放行 | 当前请求已经被旧规则拦截，不会等新规则放行 |
| 新白名单增加放行规则 | 请求前未按白名单短路；响应后若命中新白名单，可能改变最终结果 |
| 新黑名单增加 CNAME/IP 规则 | 请求域名本身未拦，但响应记录可能在后置阶段被拦截 |
| 规则删除 | 已经开始的请求可能按旧规则拦截；下一次请求才按新规则放行 |

这些不是引擎指针半更新造成的，而是同一 DNS 请求跨两个独立规则代次造成的。

## 状态核对清单

要判断一次刷新是否真正影响最终过滤，应按顺序核对：

1. 刷新 API 返回 ok；若返回 500，说明有刷新正在执行，本次没有触发新流程。
2. 日志中每个名单是否下载和解析成功，HTTP updated 只统计内容变化数量，不列失败详情。
3. data/filters/<id>.txt 的 inode、mtime 或内容是否已替换。
4. 配置中对应 ID 的 checksum、RulesCount、LastUpdated 是否同步。
5. 日志是否出现 initialized filtering engine；若只有 enabling filters 错误，运行引擎仍旧。
6. 在切换点前后使用 check_host 或实际 DNS 查询核对 QNAME 与响应记录。
7. 对穿越上游往返的请求，分别核对请求域名和响应中的 CNAME、A、AAAA，因为这两个阶段可能跨代次。

## 最终判断

在没有重建错误、且不与名单增删改并发的正常刷新中，旧规则会一直有效到新引擎完全构建完成，随后黑白名单一起原子切换。刷新不会造成空窗或单次黑白名单匹配撕裂。

会造成实际错误拦截或漏拦截的主要情形是：部分名单失败导致旧规则混合参与新引擎、一个组全失败导致另一组新文件暂不生效、重建失败导致配置和运行代次分离、规则语义未被 urlfilter 实际加载，以及完整 DNS 请求在上游往返前后跨越切换点。
