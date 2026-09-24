# AdGuard Home Web 鉴权链路与 API 中间件分析报告

> 分析对象：本仓库当前代码快照（`internal/home`、`internal/aghuser`、`internal/aghhttp`、`openapi/openapi.yaml`）。
>
> 前置说明：本快照中**不存在 Bearer Token 认证**（全仓库检索无 `Bearer` 出现）。程序化访问管理接口使用的是 **HTTP Basic Auth**（见 `openapi/openapi.yaml` 的 `securitySchemes: basicAuth` 与全局 `security: basicAuth`）。下文以"会话 Cookie + Basic Auth"这两条实际存在的凭据通道展开，并在结尾说明这一事实对结论的影响。

## 1. 鉴权链路：登录会话、密码校验、程序化认证与中间件如何协作

### 1.1 中间件在请求链中的位置

所有 HTTP 流量在 `web.wrapMux`（`internal/home/web.go:392`）中被统一包裹：

```
mux → limitRequestBody → logMw → auth.middleware().Wrap(h)
```

即**鉴权中间件是整个 mux 的最外层边界**，浏览器页面请求与 `/control/*` API 请求经过同一道关卡，不存在"页面一套、API 一套"的双边界。`auth.middleware()`（`internal/home/auth.go`）按部署形态二选一：

- 默认形态：`authMiddlewareDefault`（`internal/home/authhttp.go`）；
- GL.iNet 路由器形态：`authMiddlewareGLiNet`（`internal/home/authglinet.go`），用 `Admin-Token` Cookie 对照路由器上的 `gl_token_*` 文件（TTL 3600 秒），不走本地用户库，也**不挂限速器**。

### 1.2 登录会话的建立（POST /control/login）

`handleLogin`（`internal/home/authhttp.go`）的处理顺序：

1. 解析 JSON `{name, password}`，失败返回 400；
2. **限速预检**：用 `r.RemoteAddr`（而非 `X-Forwarded-For` 等可伪造头，见代码注释引用的 issue #2799）调用 `rateLimiter.check`，若被封禁返回 **429 + `Retry-After`**；
3. `newCookie` 中查用户并校验密码：
   - 用户不存在 → `rateLimiter.inc(remoteIP)`，返回 `errInvalidLogin`；
   - `user.Password.Authenticate` 即 **bcrypt 比较**（`internal/aghuser/aghuser.go`，`bcrypt.CompareHashAndPassword`）失败 → 同样 `inc` 并返回 `errInvalidLogin`；
   - 成功 → `rateLimiter.remove(remoteIP)` 清除失败记录，`sessions.New` 签发会话；
4. 会话令牌是 **16 字节 `crypto/rand` 随机数**（`aghuser.NewSessionToken`），以 hex 编码写入 `agh_session` Cookie（`HttpOnly`、`SameSite=Lax`、路径 `/`、浏览器侧过期 365 天），响应体为 `OK` 并带禁缓存头。

会话本身持久化在 bbolt 库 `sessions.db`（bucket `sessions-2`，`internal/aghuser/sessionstorage.go`），服务端过期时间由 `session_ttl` 决定（默认 **30 天**，`internal/home/config.go:399`）。注意 **Cookie 的 365 天 Expires 只是浏览器侧提示，真正的边界是服务端 30 天的 SessionTTL**——过期会话在 `FindByToken` 时被惰性删除，重启加载时也会清理过期或属主已不存在的会话。

### 1.3 请求级认证：Cookie 优先，Basic Auth 兜底

中间件 `Wrap` 的逻辑（`authMiddlewareDefault`）：

1. `needsAuthentication`：用户库为空（未初始化场景）时**完全不鉴权**，全部放行；
2. `userFromRequest`：先取 `agh_session` Cookie → hex 解码、长度校验、`FindByToken` 查会话、再按 `UserLogin` 反查用户；**没有 Cookie 时回退到 `Authorization: Basic`**（`userFromRequestBasicAuth`）；
3. Basic Auth 路径与登录接口**共享同一个 `loginRateLimiter` 实例、同一个用户库、同一个 bcrypt 校验、同一个 `errInvalidLogin` 错误**：先 `check` 是否被封，失败则 `inc`，成功则 `remove`；
4. 任一通道认证成功后，用户被放进请求 context（`withWebUser`），下游 handler（如 `handleGetProfile`）用 `webUserFromContext` 取用；已认证用户访问 `/login.html` 会被 302 回 `/`；
5. 未认证时：公共资源（`/assets/*`、`/login.*`、`/control/login`、安装接口、Apple mobileconfig）与 DoH 路由直接放行；`/`、`/index.html` 302 到登录页；其余一律 **401**。

**协作结论**：浏览器会话与程序化 Basic Auth 是同一中间件内的两条凭据支路，共享用户库、bcrypt 校验、限速器和同一条放行/拒绝边界；登录接口只是"把一次性密码校验换成持久会话"的签发点。

## 2. 凭据失效与暴力登录时的状态变化

### 2.1 限速器状态机（`internal/home/authratelimiter.go`）

`authRateLimiter` 以**客户端 IP 字符串**（`RemoteAddr`，不含端口）为键维护 `map[string]failedAuth{until, num}`：

- 每次失败 `inc`：计数 `num+1`，记录在 1 分钟（`failedAuthTTL`）滑动窗口内有效；达到 `maxAttempts`（配置 `auth_attempts`，默认 **5**）时，`until` 被设为 `now + blockDur`（配置 `block_auth_min`，默认 **15 分钟**）；
- `check`：先清理过期条目，仅当 `num >= maxAttempts` 时返回剩余封禁时长，否则返回 0（放行）；
- `remove`：任意一次**成功**认证立即删除该 IP 的全部失败记录；
- 配置任一为 0 时退化为 `emptyRateLimiter`（空实现），启动日志告警 `authratelimiter is disabled`，此时暴力破解**无任何限速**（`internal/home/home.go:1101`）。

关键状态变化要点：

- 登录接口与 Basic Auth 写入**同一张表**，攻击者无法通过"换通道"绕过封禁；
- 封禁键是 IP 而非账号，故对同一账号的分布式尝试（多 IP）不受此限；反之，NAT 后多个合法用户会互相连坐；
- 限速判定**不信任代理头**，`trustedProxies` 只影响日志里记录的 `logIP`，不影响封禁键——这是有意为之（issue #2799），代价是位于反向代理后的部署会把所有客户端算成同一个代理 IP；
- 封禁状态只在内存中，**重启即清零**。

### 2.2 凭据失效的路径

- **会话过期**：`FindByToken` 发现超过 `Expire` 即删除并返回 nil，请求按匿名处理；启动时 `loadSessions` 也会清掉过期会话和属主已被删除的会话；
- **主动登出**：`GET /control/logout` 调 `DeleteByToken` 删除服务端会话并下发过期 Cookie，302 到登录页；Cookie 缺失时直接视为已登出；
- **Cookie 损坏**（hex 解码失败、长度不等于 16）：`userFromCookie` 返回错误，中间件记日志后按匿名处理，不区分"无效"与"没有"；
- **改密/删用户**：本快照**没有修改密码的接口**（`/control/profile/update` 只改语言和主题），且 `SessionStorage` 接口没有 `DeleteAll`（代码中有 TODO），即用户密码或账号变化**不会主动吊销已签发的会话**，只能等 TTL 到期或重启加载时按"属主不存在"清理；
- **Basic Auth 无状态**：每次请求独立校验，密码在配置中变更后下一次请求即生效，不存在"失效延迟"。

### 2.3 不同请求来源的处理对比

| 来源 | 凭据形式 | 限速 | 失败反馈 | 成功结果 |
| --- | --- | --- | --- | --- |
| 浏览器登录 | `POST /control/login` JSON | 共享限速器（按 RemoteAddr） | 403 `invalid username or password`；被封时 429 + `Retry-After` | `agh_session` Cookie + 200 |
| 浏览器会话 | `agh_session` Cookie | 不参与 | 按匿名处理：页面 302 去登录页，API 401 | 用户注入 context |
| 程序化客户端 | `Authorization: Basic` | 共享限速器（同一实例同一键） | 中间件 401（错误细节只进服务端日志） | 用户注入 context |
| GL.iNet 模式 | `Admin-Token` Cookie 对 token 文件 | **无限速** | 401 / 302 | 放行 |
| 公共/DoH 路由 | 无 | 不参与 | 不涉及 | 直接放行 |

## 3. 三类拒绝的客户端响应与信息泄露分析

### 3.1 中间件拒绝（未认证访问受保护资源）

`w.WriteHeader(http.StatusUnauthorized)`——**空响应体**，无 `WWW-Authenticate` 头，无任何错误文本。根路径则是 302 到 `login.html`。

- 不泄露任何后端细节（连"该用哪种认证方式"都不提示；缺少 `WWW-Authenticate` 也意味着浏览器不会弹 Basic 认证框）；
- 副作用：攻击者可借此区分"资源存在但需认证"（401）与"不存在"（404），但这属于路由表本身的暴露，信息量极低。

### 3.2 控制接口拒绝（已通过认证，handler 内部拒绝）

`aghhttp.ErrorAndLog` / `writeErrorWithIP` 走 `http.Error(w, text, code)`，**把内部错误文本直接写进响应体**，例如 JSON 解析失败（400，含解码错误）、方法不允许（405）、Content-Type 不符（415，含完整的弃用提示文案）、校验失败（400，含校验错误细节）、安装接口在非首启时访问（403 `Forbidden`）。

- 这些响应会把**内部校验逻辑、错误包装链、弃用计划**等实现细节暴露给客户端；
- 但前提是请求已通过认证中间件，受众基本是合法管理员，风险等级低；真正的隐患是若某个 `/control/*` 路由被误列入公共清单，这些详细错误就会未认证可达——当前公共清单（`isPublicResource`）只含登录、安装与 mobileconfig，未见此类问题。

### 3.3 登录失败（`/control/login` 与 Basic Auth 校验失败）

- 登录接口失败统一返回 **403 `invalid username or password`**（`errInvalidLogin`），"用户不存在"与"密码错误"**报文完全相同**，不存在基于响应体的账号枚举；
- 触发封禁后返回 **429**，响应体为 `auth: blocked for 15m0s` 且带 `Retry-After` 头——这会向攻击者**确认封禁已生效并泄露剩余封禁时长**，属于有意的设计取舍（便于合法用户理解为何被拒）；
- 文档与实现不一致：`openapi/openapi.yaml` 把登录失败标为 **400**，代码实际返回 **403**，客户端若按文档处理会漏判；
- 时序侧信道：用户不存在时 `newCookie` 直接返回，**跳过 bcrypt 比较**；密码错误则多一次约几十毫秒的 bcrypt 运算。响应时间差异理论上可区分"账号是否存在"，统一文案并未消除这一通道；
- Basic Auth 失败时错误细节（含 `login attempt blocked for ...`）只写服务端日志，客户端只收到中间件的空 401，泄露面比登录接口更小。

## 结尾：三类错误响应差异归纳

| 维度 | 中间件拒绝（401） | 控制接口拒绝（4xx/5xx） | 登录失败（403/429） |
| --- | --- | --- | --- |
| 触发点 | 认证中间件，请求未到达 handler | 已通过认证，handler/包装层内部 | 登录接口或 Basic Auth 校验 |
| 状态码 | 401（根路径为 302） | 400/403/405/415/500 等，按语义区分 | 403（失败）、429（被封，带 `Retry-After`） |
| 响应体 | 空 | `http.Error` 文本，含内部错误细节 | 固定文案 `invalid username or password` 或封禁剩余时长 |
| 信息泄露 | 几乎为零（连认证方案都不提示） | 泄露实现/校验细节，但仅限已认证者 | 文案防枚举，但泄露封禁状态与时长，且存在 bcrypt 时序侧信道 |
| 对限速器的影响 | 不涉及 | 不涉及 | 失败计数 +1，成功清零，超限封禁 |

一句话总结：**中间件拒绝是"沉默的边界"（空 401），控制接口拒绝是"对内的详细报错"（文本 4xx），登录失败是"统一文案但暴露封禁语义的关口"（403/429）**；三者共享同一套用户库与限速边界，差异只在离攻击面的远近与反馈的信息量。另需注意本快照的程序化认证是 Basic Auth 而非 Bearer，且 `openapi.yaml` 中登录失败的状态码（400）与实现（403）不一致，属于应修正的文档偏差。
