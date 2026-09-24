# 首次安装、配置迁移与运行中重载的一致性分析

本文基于本仓库实际代码，梳理三条路径：首次安装向导结束后配置如何进入运行态、
旧配置迁移/校验失败时原配置如何保留、以及运行中重载（HTTP 重绑定、SIGHUP、
next 架构的 configmgr）中断时新旧状态的分歧与后果。

涉及两条实现线：

- 现行架构（默认构建，`main.go` + `internal/home`）：全局变量 `config` +
  安装向导 + SIGHUP 局部重载。
- 下一代架构（`next` build tag，`main_next.go` + `internal/next`）：
  `configmgr.Manager` 统一管理运行态与持久化。

---

## 1. 首次安装：向导结束后配置如何进入运行态

### 1.1 首跑的判定与跳过加载

- `run()` 先调 `detectFirstRun()`（internal/home/home.go:1378）：配置文件不存在
  即视为首跑；stat 出错也按首跑处理（记 error 日志）。
- 首跑时 `setupContext()`（internal/home/home.go:194）**直接返回，不解析配置**。
  此时内存中的 `config` 是包级默认配置（internal/home/config.go:394），其
  `SchemaVersion` 已是最新的 `configmigrate.LastSchemaVersion`（当前为 34，
  internal/configmigrate/configmigrate.go:5），并自带默认过滤器、过滤参数等。
- `run()` 跳过 `runDNSServer()`，以 `firstRun=true` 启动 web（web.go:273 只注册
  install 路由；control.go:345 的 `preInstallHandler` 保证这些路由只在首跑可用）。

### 1.2 finalizeInstall 的应用顺序

向导最后一步 POST `/control/install/configure` → `handleInstallConfigure`
（controlinstall.go:444）先做请求级校验（密码长度、DNS 端口 udp/tcp 可绑定），
然后进入 `finalizeInstall`（controlinstall.go:488），顺序如下：

1. **备份安装相关字段**：`copyInstallSettings(curConfig, config)` 保存
   DNS.BindHosts/Port、HTTPConfig、Language；defer 在出错时回滚这 4 项。
2. **改内存配置**：Language、DNS.BindHosts/Port、Filtering.Logger/SafeFSPatterns、
   HTTPConfig.Address 写入全局 `config`。
3. **建用户**：`web.auth.addUser()`。注意此步**不在回滚范围内**。
4. **启动模块**：`startMods()`（controlinstall.go:628）→ 检查 stats/querylog 目录
   → `initDNS` → `startDNSServer`；若 `startDNSServer` 失败会
   `closeDNSServer` 清理。至此 DNS 服务已进入运行态。
5. **持久化**：`config.write()`（config.go:800）。它不是把请求参数直接落盘，
   而是**从运行中的各模块回读**：依次调用 stats/queryLog/filters/dnsServer/dhcp
   的 `WriteDiskConfig` 以及 clients 的 `forConfig()`，再合并 auth 用户列表和
   TLS 配置，整体加锁后序列化 YAML，用 `maybe.WriteFile`（renameio，原子写且
   内容相同则跳过）写入。这保证落盘内容 = 实际运行态。
6. **切换运行模式**：`firstRun=false`、更新 `BindAddr`、`registerControlHandlers()`
   注册正常控制面路由，返回 200 并 Flush。
7. **HTTP 重绑定（热加载）**：若 web 地址变化（`restartHTTP`，由
   `decodeApplyConfigReq` 对比新旧 `HTTPConfig.Address` 得出），在独立 goroutine
   里 `Shutdown` 旧 HTTP server。web.go:350 的 `start` 循环把
   `http.ErrServerClosed` 当作"换地址重启"信号，回到循环头部用新 `BindAddr`
   重新 `ListenAndServe`——不退出进程即完成监听地址切换。

关键时序：**先运行态（DNS 起来）、再持久化（写盘）、最后热重绑定（HTTP 换地址）**。

---

## 2. 旧配置迁移与校验失败：原配置的保留

非首跑时 `setupContext` 调 `parseConfig`（config.go:604），顺序为：

1. `readConfigFile` 读盘；
2. `migrator.Migrate()`（internal/configmigrate/migrator.go:45）**在内存副本上**
   做链式升级：解析 YAML → 读 `schema_version` → `validateVersion` → 依次执行
   `migrateTo1..migrateTo34`（旧字段映射，如 migrateTo29 把 filters 中的本地路径
   汇集到 `filtering.safe_fs_patterns`）→ 重新编码；
3. 仅当 `upgraded=true` 才用 `maybe.WriteFile` 原子写回磁盘（config.go:637）；
4. `yaml.Unmarshal` 到全局 `config`，再 `validateConfig`（bind_hosts 等校验）。

失败时的行为：

- **迁移失败**（YAML 无法解析、`schema_version` 高于二进制支持的版本
  （"unknown current schema version"，即新配置+旧二进制）、某个 migrateToN 的
  旧字段映射报错如类型不符）：`Migrate` 返回原始 body 和错误，**磁盘文件完全
  未被触碰**；`setupContext` 记日志后 `os.Exit(1)`（home.go:210-215）。进程
  不进入运行态，下次启动重试同一迁移。风险在于：若旧字段映射逻辑本身对某类
  合法旧配置报错，用户会被永久卡在启动失败，只能手工修配置或回退版本。
- **升级成功但写回失败**：同样退出；renameio 的临时文件+rename 语义保证不会
  留下写了一半的配置，原文件保留。
- **校验失败**（Unmarshal/validateConfig）：磁盘未动，进程退出。

即：迁移与校验阶段遵循"全部成功才落盘"，旧配置天然保留；代价是任何一步失败
都是致命的（进程退出），没有"用旧配置继续跑"的降级路径。

---

## 3. 安装中途失败：回滚的边界与新旧状态分裂

`finalizeInstall` 的 defer 只回滚 4 个安装字段，存在三个不一致窗口：

1. **用户不回滚**：`addUser` 成功后若后续步骤失败，用户留在内存 auth 中；
   `firstRun` 仍为 true，install 路由仍开放，重试时 `addUser` 可能因用户已存在
   而报 422。
2. **运行态先于持久化**：`startMods` 成功而 `config.write` 失败时，DNS 服务器
   已在用新设置运行，但磁盘上没有（首装场景）或还是旧配置——内存运行态与
   持久化状态分裂；回滚只改回 4 个字段，并不会停掉已启动的 DNS 服务。
3. **持久化先于重绑定**：写盘成功后才 Shutdown 旧 HTTP server。若新地址
   `ListenAndServe` 失败（返回非 `ErrServerClosed`），web.go:387 的 start 循环
   直接 panic，`RecoverAndExit` 退出进程。此时新配置已完整落盘，进程重启后按
   新配置正常起来——热重绑定中断不丢配置，但表现为一次进程崩溃。

另外，`config.write` 的"从运行态回读"设计意味着：即使请求参数与模块实际生效
值有偏差，落盘的也是模块自报的状态，持久化始终向运行态收敛。

---

## 4. 运行中重载的两层语义

### 4.1 现行架构：SIGHUP 不是整配置热加载

`signalHandler.reloadConfig`（internal/home/signal.go:137）在 SIGHUP 时只做
两件事：`clientStorage.ReloadARP` 和 `tlsManager.Refresh`。**不重读配置文件**；
TLS 刷新失败只记 error 日志，运行态不受影响。运行中改配置走 API →
`defaultConfigModifier` → `config.write` 的路径，与安装时共用同一个落盘函数，
因此持久化格式与运行态回读逻辑一致。

### 4.2 next 架构：configmgr 的统一更新与其中断面

`configmgr.Manager`（internal/next/configmgr/configmgr.go）把"改配置"建模为
`UpdateDNS`/`UpdateWeb`，在 `updMu` 写锁内按序执行：

1. `updateDNS/updateWeb`：**先 Shutdown 旧服务，再 New 新服务**；
2. `updateCurrentDNS/updateCurrentWeb`：更新内存 `current`；
3. `write`：整体落盘。

中断时的状态分歧：

- 旧服务 Shutdown 失败 → 直接返回错误，`m.dns` 仍指向可能已部分关闭的旧服务；
- 旧服务已停、新服务 `New` 失败 → `m.dns` 未更新，仍指向**已关闭**的旧服务，
  服务实际中断，但内存与磁盘配置都还是旧值（配置一致、服务缺失）；
- 服务已切换、`write` 落盘失败 → 返回错误，但运行态和 `current` 已是新配置，
  磁盘仍是旧配置——运行态与持久化分裂，进程重启后回退到旧配置。
- 另注意 `UpdateDNS` 中的 TODO（configmgr.go:235）：配置写回在该路径尚未完整
  实现。

与现行架构相比，configmgr 把校验前置（`New`/`Validate` 时 read+Validate，失败
不启动），但更新路径是"先换运行态、后落盘"，与 `finalizeInstall` 一样存在
运行态/持久化的短暂分裂窗口。

---

## 5. 一致性保证总结

| 阶段 | 顺序 | 失败时的状态 |
| --- | --- | --- |
| 迁移+校验（parseConfig） | 内存升级 → 原子写回 → 校验 | 磁盘原配置保留，进程退出，无降级运行 |
| 首装应用（finalizeInstall） | 运行态 → 持久化 → HTTP 重绑定 | 部分回滚（仅 4 字段）；用户与已启动模块残留；写盘失败后运行态/磁盘分裂 |
| HTTP 热重绑定 | ErrServerClosed 触发循环重绑 | 新地址监听失败 → panic 退出；配置已落盘，重启自愈 |
| SIGHUP | 仅 ARP/TLS 局部刷新 | 失败仅记日志，运行态不变；不触配置文件 |
| configmgr 更新（next） | 换服务 → 改内存 → 落盘 | 服务可能已关未起；落盘失败则运行态新、磁盘旧 |

贯穿两条架构的共同原则：**磁盘写入一律走 renameio 原子写且仅在内容变化时写**，
因此"原配置保留"在迁移/校验阶段是强保证；而"运行态与持久化一致"在应用/更新
阶段是尽力而为——两者都把持久化放在运行态变更之后，中断窗口内以运行态为准，
重启后以磁盘为准。
