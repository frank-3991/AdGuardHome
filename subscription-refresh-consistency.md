# 远程黑白名单刷新一致性分析

本文基于当前工作区代码，分析远程黑名单和白名单从刷新事件到 DNS 过滤结果之间的状态关系。生产查询路径使用 internal/filtering/DNSFilter 和 urlfilter；internal/filtering/rulelist.Storage 目前只在包内测试中出现，不是运行时 DNS 过滤路径。

## 结论

1. 单个订阅下载或解析失败时，旧规则继续有效。新内容先写入同目录临时文件，只有成功读取、解析且校验和变化后才替换正式文件；失败会清理临时文件。
2. 远程刷新接口是同步执行：下载、文件替换、引擎重建和指针切换完成后才返回。定时刷新也调用同一条同步重建路径。新增、删除、启停订阅和修改用户规则等管理操作使用异步重建。
3. 单次规则匹配不会读到半套黑白名单。matchHost 在白名单和黑名单两次匹配期间持有 engineLock.RLock()，查询不会看到“白名单是新引擎、黑名单是旧引擎”的组合。
4. 引擎切换对查询呈现为原子快照。新引擎先完整构建，再在写锁下同时替换 block/allow 两组 storage 和 engine。切换前查询使用旧引擎，写锁期间等待，切换后使用新引擎。
5. 多订阅刷新不是分布式事务。同一类别中一个列表成功、另一个失败时，成功列表的文件先变成新内容，失败列表保留旧文件；下一次引擎重建会按这个混合文件集加载。
6. 一个 DNS 请求可能跨规则版本。请求前匹配完成后释放引擎读锁，随后查询上游或 DNS 缓存；响应后过滤再次获取读锁。切换正好发生在两者之间时，前后两阶段可能按不同版本判断。
7. 刷新不清空 DNS 上游缓存。切换前未被旧规则拦截的请求可能命中旧缓存；响应后过滤只检查答复中的 CNAME、A/AAAA 和 HTTPS 提示，不按原始问题名重新匹配。因此新增域名拦截规则可能对边界请求漏拦截，直到缓存 TTL 过期或手动清缓存。
8. 重复刷新不会并发下载。refreshLock.TryLock() 使第二个刷新立即返回 500；第一个刷新结束后，后续请求才重新执行。但异步配置重建不经过 refreshLock，与同步刷新之间缺少统一构建代次控制，存在旧快照后完成并覆盖新引擎的窄窗口。

## 代码锚点

| 环节 | 位置 | 说明 |
| --- | --- | --- |
| HTTP 刷新入口 | internal/filtering/http.go:366 | /control/filtering/refresh，按 whitelist 选择刷新黑名单或白名单 |
| 刷新互斥 | internal/filtering/filter.go:265 | TryLock；已有刷新时 ok=false |
| 选择待刷新列表 | internal/filtering/filter.go:277 | 仅启用列表；普通刷新检查 LastUpdated 和更新间隔 |
| 顺序更新 | internal/filtering/filter.go:339 | 对每个副本调用 update，记录失败数和 changed 标志 |
| 回写元数据 | internal/filtering/filter.go:359 | 回写 LastUpdated、名称、规则数和 checksum |
| 刷新总控 | internal/filtering/filter.go:416 | 分别处理 block 和 allow，最后同步重建 |
| 下载到临时文件 | internal/filtering/filter.go:501 | 创建 pending file，读取 HTTP 或本地文件 |
| 替换或清理 | internal/filtering/filter.go:585 | changed 时 CloseReplace，否则 Cleanup |
| 收集文件路径 | internal/filtering/filter.go:663 | 在 filtersMu 下收集 custom、block、allow |
| 同步/异步重建 | internal/filtering/filtering.go:356 | 同步直接构建；异步投递到容量 1 的 channel |
| 引擎替换 | internal/filtering/filtering.go:748 | 先建新引擎，再在 engineLock 写锁下替换四字段 |
| 查询匹配 | internal/filtering/filtering.go:884 | 白名单和黑名单匹配期间持有读锁 |
| 后台循环 | internal/filtering/filtering.go:1088 | 串行消费异步重建和定时刷新 |
| 请求设置快照 | internal/dnsforward/process.go:143 | 请求开始时获取保护状态和客户端设置 |
| 请求前过滤 | internal/dnsforward/process.go:403 | CheckHost 命中则直接生成拦截响应 |
| 上游/缓存 | internal/dnsforward/process.go:449 | 未拦截时调用 dnsproxy.Resolve |
| 响应后过滤 | internal/dnsforward/process.go:550 | 对答复记录再次匹配 |
| 清缓存 | internal/dnsforward/http.go:763 | 只有 /control/cache_clear 清理 DNS 缓存 |

## 刷新事件到规则生效

### 1. 触发

手动刷新：

1. handleFilteringRefresh 解析 whitelist。false 时刷新黑名单，true 时刷新白名单。
2. 调用 tryRefreshFilters(..., force=true)。
3. 如果 refreshLock 已被占用，接口返回 500 和 “filters update procedure is already running”；该请求不排队、不下载、不等待结果。
4. 获得锁后，在当前 HTTP goroutine 中完成整个刷新，最后返回 updated 数量。

定时刷新：

1. Start 启动 updatesLoop，初始约 5 秒后执行一次。
2. FiltersUpdateIntervalHours 非 0 时，调用 tryRefreshFilters(true, true, false)。
3. 正常完成后间隔变为 1 小时；全部失败时间隔翻倍并钳制到 1 小时；拿不到锁时保持当前间隔。

### 2. 选择列表和远程拉取

1. listsToUpdate 在 filtersMu.RLock() 下复制待更新列表的 ID、URL、Name 和旧 checksum。
2. 强制刷新忽略 LastUpdated；普通刷新只选择到期列表。
3. 读锁释放后顺序更新副本。下载期间不阻塞 DNS 查询旧引擎，也不阻塞状态 API。
4. updateIntl 在正式文件同目录创建 pending file。HTTP 请求必须返回 200，并受 MaxHTTPSize 限制；本地绝对路径必须匹配 safe patterns。
5. Parser 将非空、非注释、不含可疑控制字符的规则行写入临时文件，同时统计规则数和 CRC32。

这里的解析校验主要拒绝 HTML、空内容和二进制字符，并不证明每一行都是有效的 urlfilter DNS 规则。它统计的 rules_count 是“非空、非注释且可打印的行数”，不等于最终进入 DNS 引擎的有效规则数。后续 RuleScanner 对 rules.NewRule 失败的行会静默跳过，cosmetic 规则也会因 IgnoreCosmetic=true 被跳过。因此一次“下载并替换成功”的列表仍可能实际少加载 DNS 规则，造成漏拦截。

### 3. 单列表文件提交

| 拉取结果 | checksum | 文件动作 | 元数据 | 运行引擎 |
| --- | --- | --- | --- | --- |
| 下载、读取或解析失败 | 不提交 | Cleanup 删除临时文件 | 临时副本的 LastUpdated 被设为当前时间；全部失败时不回写，部分失败时才可能回写该时间 | 旧引擎继续运行 |
| 成功但内容相同 | 相同 | Cleanup 临时文件，并 Chtimes 正式文件 | 更新 LastUpdated | 不重建，旧引擎继续运行 |
| 成功且内容变化 | 不同 | Unix 原子 rename；Windows close 后 rename | 更新名称、规则数、checksum、时间 | 文件已新；引擎切换前仍按旧规则查询 |

Unix 上旧引擎持有旧 inode 的打开文件描述符。正式路径被 rename 替换后，旧引擎仍读取旧 inode，直到新引擎切换并关闭旧 storage。Windows 构建时先把正式文件完整读入内存，避免 urlfilter 长期持有正在替换的文件句柄。

跨平台差异仍需区分：Unix 的 CloseAtomicallyReplace 提供原子 rename 语义；Windows 包装是先关闭临时文件再 os.Rename，接口注释也说明该路径不保证原子。由于 Windows 新引擎在构建阶段已经把文件读入 []byte，查询旧引擎又不依赖被替换的路径句柄，这个非原子窗口通常表现为并发管理操作读到文件状态差异，而不是一次 matchHost 读到半份规则。

### 4. 元数据同步

每个类别下载结束后：

1. 如果该类别所有待刷新列表都失败，refreshFiltersArray 返回网络错误标记，不回写该类别的配置项。
2. 只要不是全部失败，就持有 filtersMu.Lock()，按 ID + URL 匹配原配置。
3. syncUpdatedFilters 对所有匹配项无条件写入 LastUpdated。部分失败时，失败列表的规则仍旧，但状态 API 可能显示本次刷新时间。
4. 只有 changed=true 的列表才更新 Name、RulesCount、checksum，并计入 updated。

LastUpdated 的结构体标签是 yaml:"-"，刷新路径也没有调用 ConfModifier.Apply()。因此刷新时间和规则数主要是进程内状态；重启后 load 会从缓存文件 mod time 和重新解析结果恢复。

### 5. 引擎重建

1. 如果 block 或 allow 任一类别的待刷新列表全部失败，refreshFiltersIntl 直接返回，不调用 EnableFilters，旧 block/allow 引擎完整保留。
2. updated 为 0 时不重建。这包括内容无变化，也包括“有失败但没有任何 changed 列表”的情况。
3. 至少一个列表内容变化时，调用 EnableFilters(false)。
4. enableFiltersLocked 在 filtersMu.RLock() 下收集当前自定义规则和启用列表的文件路径。
5. initFiltering 先创建 block RuleStorage、allow RuleStorage，再分别构建 DNSEngine。
6. 两个新引擎都构建完成后，获取 engineLock.Lock()，关闭旧 storage，并一次性写入 block storage/engine 和 allow storage/engine。

构建发生在写锁外，所以下载和建索引期间查询仍使用旧规则。只有最后指针赋值需要等待读锁排空，切换窗口内不会有查询使用半初始化引擎。

需要注意两个构建降级点：

- 正式文件不存在时 ruleListFromFilter 会 skip 该列表而不是报错。新引擎可能成功构建但缺少整个订阅，表现为漏拦截。
- 其他打开、读取或 RuleStorage 创建错误会使 initFiltering 失败，错误只写日志；手动刷新接口仍可能返回 200，旧引擎继续运行，但新文件和元数据已经落盘。

## 部分失败矩阵

| 场景 | 文件和元数据 | 是否重建 | 运行规则 | 主要风险 |
| --- | --- | --- | --- | --- |
| 只刷黑名单，全部失败 | 正式文件不变，该类别不回写 | 否 | 旧黑白名单 | 无切换风险；定时刷新稍后重试 |
| 只刷白名单，全部失败 | 正式文件不变，该类别不回写 | 否 | 旧黑白名单 | 无切换风险；例外规则仍旧 |
| 黑名单部分成功、部分失败 | 成功者新文件和新元数据，失败者旧文件但时间可能更新 | 是，若成功者 changed | 新成功列表、旧失败列表和当前白名单 | 跨列表新旧配套不一致 |
| 白名单部分成功、部分失败 | 成功者新例外规则，失败者旧例外规则 | 是，若成功者 changed | 黑名单当前规则和混合白名单 | 可能误拦截或漏拦截 |
| 黑名单全失败，白名单有 changed | 白名单文件已提交；聚合错误导致不重建 | 否 | 旧黑白名单 | 状态文件与运行引擎暂时不一致 |
| 下载成功但引擎构建失败 | 成功文件已替换，元数据已回写 | 失败 | 旧引擎 | 无即时半切换；重启或下次重建可能延迟暴露新文件问题 |

这里的 isNetworkErr 名称不准确。网络失败、HTTP 非 200、解析错误、本地文件错误、rename 错误都会进入失败计数。HTTP 处理器还丢弃了 isNetworkErr，因此全失败通常也返回 200 和 updated:0，需要查看日志才能确认失败原因。

## 误判来源

### 跨订阅新旧配套

以 B1、B2 两个黑名单为例，B1 成功更新而 B2 失败：

- 如果 B1 新增拦截 example.com，而解除该拦截的配套例外规则本应随 B2 发布但仍停留在 B2.old，刷新后会错误拦截。
- 如果 B1 删除了旧拦截，而本应由 B2 补上的新规则因失败缺失，刷新后会漏拦截。

白名单的部分失败同理。白名单成功扩大例外范围但黑名单配套失败，可能漏拦截；白名单失败而新黑名单需要新例外，可能错误拦截。

### 单次 DNS 请求跨版本

dnsforward 的请求流程是：

1. processInitial 复制本次请求的设置，包括保护开关和客户端设置。
2. processFilteringBeforeRequest 获取 serverLock.RLock()，进入 dnsFilter.CheckHost。
3. matchHost 获取 engineLock.RLock()，完成 allow 匹配后继续 block 匹配，然后释放锁。
4. 若未拦截，processUpstream 调用 dnsproxy.Resolve，可能访问网络或命中缓存。
5. processFilteringAfterResponse 对响应记录再次调用 CheckHostRules，并重新获取 engineLock.RLock()。

因此：

- 请求前用旧规则未拦截，响应后新规则若能匹配响应中的 CNAME 或 IP，可能拦截；这是跨阶段误拦截。
- 请求前用旧规则未拦截，响应后的新规则只按原始域名拦截、答复记录本身没有可匹配的域名或 IP，则缓存答复会放行；这是跨阶段漏拦截。
- 请求前旧白名单命中并返回 NotFilteredAllowList 时，响应阶段会直接跳过，不再用新黑名单检查该响应。
- 请求前已被旧规则拦截的请求不会访问上游或缓存，不会被新规则改成放行。

同一个 matchHost 调用中的 allow 和 block 不会跨版本；跨版本只发生在请求前阶段与响应后阶段之间，或同一域名的两次独立 DNS 查询之间。

### DNS 缓存

刷新逻辑没有调用 dnsProxy.ClearCache()。缓存命中发生在 AdGuard 请求前过滤之后：

1. 旧规则下，请求前没有拦截 example.com。
2. dnsproxy 命中旧缓存，直接返回事先缓存的 A/AAAA 或 CNAME 链。
3. 新规则可能已经把 example.com 加入黑名单，但响应后过滤不会重新检查问题名 example.com，只检查答复记录。
4. 如果答复中没有能被新规则匹配的 CNAME、A/AAAA 字符串或 HTTPS 提示，该请求继续放行。

这会使新黑名单在 TTL 窗口期内对缓存请求表现为漏拦截。新白名单通常不会造成同类问题，因为请求前若被新黑名单拦截就不会读取缓存；但已经被旧规则拦截或旧白名单放行的在途请求仍遵从旧阶段决策。

## 重复刷新与异步重建

### 两个刷新请求

刷新由同一个 refreshLock 串行化：

- 第一个请求执行下载和重建。
- 第二个请求立即收到 500，不合并、不等待、不重试。
- 第一个完成后发起的新刷新会读取当前 checksum；若内容已是最新，通常只更新时间且 updated=0，不会再次重建。

因此不存在两个刷新线程同时写同一正式文件的问题，但客户端不能把 500 当作刷新失败结论；它只表示已有刷新正在运行。

### 刷新与管理配置

新增、删除、启停订阅、修改用户规则等操作走 EnableFilters(true)：

1. 参数放入容量为 1 的 filtersInitializerChan。
2. 投递前会清空所有尚未开始的旧任务，所以队列里只保留最新配置。
3. 已经被 updatesLoop 取出的构建不能取消，也不受 refreshLock 保护。
4. 手动刷新在 HTTP goroutine 中同步构建，可能与一个正在运行的异步构建并发。
5. 两个构建都基于各自开始时收集到的文件路径和配置；后获得 engineLock 写锁者生效。

如果异步旧配置构建耗时较长，期间同步刷新已经把新引擎切换完成，旧构建随后才获得写锁，就可能把引擎短暂覆盖回旧快照。下一次配置变更通常会再次入队并修正，但这个窗口内可能出现旧规则误拦截或漏拦截。正常的远程刷新之间没有这个问题，因为它们共享 refreshLock。

## 状态核对

### 阶段状态表

| 阶段 | 正式文件 | 配置元数据 | 运行引擎 | DNS 结果 |
| --- | --- | --- | --- | --- |
| 下载前 | 旧 | 旧 | 旧 | 旧规则 |
| 下载和解析中 | 旧 | 旧 | 旧 | 旧规则 |
| 某列表 changed 并 CloseReplace 后 | 该列表新，其他旧 | 尚未回写 | 旧 | 旧规则；状态 API 仍显示旧规则数 |
| syncUpdatedFilters 持有写锁时 | 已成功者新，失败者旧 | 正在回写时间和规则数 | 旧 | 查询等待配置读锁，但引擎仍旧 |
| 新引擎构建中 | 已成功者新，失败者旧 | 新 | 旧 | 旧规则 |
| engineLock 写锁切换 | 新 | 新 | 从旧指针切到新指针 | 查询短暂等待 |
| 切换完成 | 新或部分失败时混合 | 新或部分失败时混合 | 新快照 | 新规则；缓存答复可能仍受 TTL 影响 |

### 日志顺序

一次有内容变化且成功的刷新应按顺序出现：

1. starting update
2. downloading update for filter
3. saving contents
4. filter updated，带 bytes_written 和 rules_count
5. updated filter，带 id、rules_count、prev_rules_count
6. initialized filtering engine
7. finished update，updated 大于 0

判断要点：

- 只有 downloading update for filter，随后是 updating filter 错误：正式文件未替换，旧规则有效。
- 有 saving contents 和 filter updated，但没有 initialized filtering engine：文件和元数据可能已更新，运行引擎仍旧或仍是上一次成功引擎。
- 有 initialized filtering engine，但没有 updated filter：通常是内容无变化或管理操作触发的重建，不代表远程列表内容变化。
- finished update 的 updated 是内容变化并成功回写的列表数，不代表下载成功的列表数，也不表示没有失败日志。

### API 核对

1. 刷新前记录 GET /control/filtering/status 中每个列表的 rules_count 和 last_updated。
2. 立即发起 POST /control/filtering/refresh。该接口返回时，正常情况下同步引擎切换已经完成。
3. 并发收到 500 时，不重新推断结果，等待第一个请求结束后再查状态和日志。
4. 刷新后再次读取状态，将 changed 列表的 rules_count 与日志 filter updated 中的 rules_count 对齐。
5. 用 POST /control/filtering/check_host 查询同一域名。该接口调用当前引擎快照；它能验证引擎切换后的规则，但不能复现切换前已经进入上游或缓存阶段的在途请求。
6. 对需要立即消除 TTL 影响的环境，刷新后调用 POST /control/cache_clear，再发送新的 DNS 查询验证拦截或放行。

## 最终判断

刷新设计保证了单文件替换和单次引擎快照的一致性，也保证下载失败时不会把半截规则文件交给运行引擎；因此普通的单订阅失败不会清空规则，旧规则继续有效。

风险集中在三个边界：

- 多个远程列表之间没有事务，部分成功会形成“成功列表新规则 + 失败列表旧规则”的合法混合引擎。
- 请求前和响应后过滤是两个独立加锁区间，单个 DNS 请求跨切换点时可能按新旧两套规则分别决策。
- 上游 DNS 缓存不随刷新清空，新增域名规则可能在 TTL 内继续放行旧缓存答复；异步管理重建与同步刷新并发时，还存在旧构建后完成覆盖新快照的窄窗口。

要严格判断刷新后的实际过滤结果，应同时核对：刷新接口返回、updated filter 和错误日志、initialized filtering engine 日志、刷新后的状态 API、DNS 缓存是否清理，以及实际 DNS 查询发生在引擎切换前、切换中还是切换后。
