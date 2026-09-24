# AdGuard Home Web 鉴权链路与 API 中间件分析报告

> 分析对象：`internal/home/`（auth.go、authhttp.go、authratelimiter.go、middlewares.go、control.go、web.go）、`internal/aghuser/`、`internal/aghhttp/`。

## 0. 术语澄清：代码中并不存在 Bearer 认证

全仓库检索不到任何 `Bearer` 关键字。管理接口的"程序化认证"实际是 **HTTP Basic Auth**（`Authorization: Basic ...`），由 [authhttp.go](internal/home/authhttp.go) 中的 `userFromRequestBasicAuth` 实现。唯一的类 Bearer 机制是 GLiNet 定制模式下的 `Admin-Token` Cookie（[authglinet.go](internal/home/authglinet.go)，对照路由器下发的 token 文件，TTL 3600 秒），本文以默认模式为主。

## 1. 鉴权链路：登录会话、密码校验与 API 中间件如何协作

### 1.1 中间件装配顺序

[web.go](internal/home/web.go) 的 `wrapMux` 自外向内包装：

```
auth.middleware()  →  日志中间件  →  limitRequestBody  →  mux（含 postInstallHandler / ensure）
```

- `limitRequestBody`（[middlewares.go](internal/home/middlewares.go)）与鉴权无关，只限制请求体（默认 64 KB，`/control/access/set`、`/control/filtering/set_rules` 放宽到 4 MB）。
- 鉴权中间件是**最外层**，所有请求（含静态资源）都先过它。

### 1.2 登录（会话建立）

`POST /control/login` → `handleLogin`（[authhttp.go](internal/home/authhttp.go)）：

1. JSON 解码失败 → 400。
2. 取 `r.RemoteAddr`（**故意不用** `realIP`/X-Forwarded-For，防伪造绕过限流，见 issue #2799）做限流检查，被封锁 → 429 + `Retry-After`。
3. `newCookie` 中：`users.ByLogin` 查用户 → `user.Password.Authenticate`（bcrypt 校验，哈希存于配置 `users[].password`）→ `sessions.New` 生成 16 字节随机 token（`aghuser.SessionTokenLength = 16`），持久化到 `data/sessions.db`（bbolt），服务端 TTL 由 `session_ttl` 控制。
4. 下发 Cookie：`agh_session=<hex(token)>`，`HttpOnly`、`SameSite=Lax`、Path=/，浏览器侧有效期 365 天（`cookieTTL`），并带 `Cache-Control: no-store` 等禁缓存头。

### 1.3 请求鉴权（会话消费 + Basic Auth 回退）

`authMiddlewareDefault.Wrap` 的判定顺序：

1. `needsAuthentication`：配置中无任何用户 → 直接放行（首次安装场景）。
2. `userFromRequest`：**先查 Cookie**（hex 解码 → `sessions.FindByToken`，过期会话返回 "expired session" 错误 → 再按 login 查用户）；**无 Cookie 则回退 Basic Auth**（同样过限流器 + bcrypt 校验）。
3. 认证成功：把 `*aghuser.User` 注入 request context（`withWebUser`）放行；若访问 `/login.html` / `/forgot_password.html` 则 302 到 `/`。
4. 未认证：命中公开资源白名单（`isPublicResource`：`/assets/*`、`/login.*`、`/control/login`、`/control/install/*`、mobileconfig、DoH 路由等）→ 放行；访问 `/` → 302 到 `login.html`；其余 → **401，空响应体**。

协作要点：Cookie 会话与 Basic Auth 共享**同一个用户库、同一个 bcrypt 校验、同一个限流器**，是同一边界的两个入口；区别仅在凭证载体和限流触发点（登录接口在 handler 内限流，Basic Auth 在中间件内限流）。

## 2. 凭据失效与暴力破解时的状态变化

### 2.1 限流器状态机（[authratelimiter.go](internal/home/authratelimiter.go)）

- 键：**客户端 IP 字符串**（`RemoteAddr` 的主机部分），不是用户名——同一 IP 换账号继续撞也会被累计。
- `inc`：失败计数 +1，计数窗口 `failedAuthTTL = 1 分钟`；达到 `maxAttempts`（默认 `auth_attempts: 5`）后，`until` 被设为 `now + blockDur`（默认 `block_auth_min: 15` 分钟）。
- `check`：计数 ≥ 阈值且未过 `until` → 返回剩余封锁时长；否则返回 0。过期条目惰性清理。
- `remove`：登录**成功**即清除该 IP 的全部失败记录。
- 配置 `auth_attempts=0` 或 `block_auth_min=0` 时退化为 `emptyRateLimiter`（完全不限流，仅打一条 warning 日志）。

### 2.2 不同请求来源的处理对比

| 来源 | 失败计数时机 | 被封锁时的表现 |
|---|---|---|
| 浏览器表单 `POST /control/login` | handler 内 `newCookie`：用户不存在或密码错误都 `inc` | 429 + `Retry-After: <秒>`，body 为 `auth: blocked for ...` |
| 程序化 Basic Auth（任意 API） | 中间件内 `userFromRequestBasicAuth`：check 先行，失败 `inc`，成功 `remove` | 不返回 429，错误只进日志，客户端统一收到 **401 空响应** |
| Cookie 会话失效/过期 | **不计数**（`FindByToken` 失败只记日志，不触限流） | 401 空响应（API）或 302 到 login.html（根路径） |

注意不对称性：登录接口的限流状态对客户端**可见**（429 + Retry-After），而 Basic Auth 路径的限流对客户端**不可见**（与"凭证错误"无法区分）。另外 `trustedProxies` 只影响日志里记录哪个 IP，不影响限流键——限流始终按直接对端 IP。

## 3. 三类拒绝的客户端响应对比与信息泄露分析

### 3.1 中间件拒绝（未通过鉴权）

```
HTTP/1.1 401 Unauthorized
（空响应体，无 WWW-Authenticate，无错误文本）
```

- 不区分"无凭证 / 会话过期 / Basic 密码错 / 被限流"，信息熵最低。
- 副作用：缺少 `WWW-Authenticate: Basic` 头，浏览器不会弹原生 Basic 认证框——这是有意为之（前端走自己的登录页）。
- 对 `/`、`/index.html` 不返回 401 而是 302 到 `login.html`，属于浏览器友好分支。

### 3.2 控制接口拒绝（路由/生命周期/方法层）

- `preInstallHandler`：安装完成后访问 `/control/install/*`、`/install.html` → **403 `Forbidden`**（`http.StatusText`，纯文本）。
- `postInstallHandler`：首次运行期间访问非 install 路径 → **302 到 install.html**（不暴露任何 API）。
- `ensure`：方法不符 → **405 `only method X is allowed`**；Content-Type 不符 → **415**，且错误文本回显请求头值（如 `empty body with content-type "..." not allowed`）。
- 这类拒绝发生在鉴权**之后**（中间件已放行），泄露的是"端点存在但状态/方法不对"，属于 API 结构的正常自描述，风险低；415 回显输入但仅限请求头内容，无敏感数据。

### 3.3 登录失败（凭证校验层）

```
HTTP/1.1 403 Forbidden
invalid username or password
```

- 用户不存在与密码错误返回**完全相同的报文**（`errInvalidLogin`），有效防用户名枚举。
- 触发限流后变为 429 + `Retry-After`，明确告知封锁剩余时间——这是可用性与信息暴露的权衡：攻击者能精确知道封锁窗口，但无法据此区分账号是否存在。
- 登录接口用 403 而非 401 表示"认证失败"，与中间件的 401（"未认证"）语义区分开。

### 3.4 信息泄露评估

- 唯一可观察的账号枚举侧信道是**时序**：用户不存在时跳过 bcrypt 校验，响应略快。代码未做 dummy-hash 补偿，但 bcrypt 耗时在网络噪声下实际可利用性低。
- 限流在登录路径以 IP 为键、报文统一，不泄露"哪个用户名被尝试"。
- 详细错误（如 `auth: blocked for 14m32s`、会话过期原因）只写服务端日志，不进响应体——除了 429 的 body 本身会带封锁时长。

## 4. 总结：三类错误响应的差异

| 维度 | 中间件拒绝 (401) | 控制接口拒绝 (403/405/415/302) | 登录失败 (403/429) |
|---|---|---|---|
| 触发位置 | 最外层鉴权中间件 | mux 内路由包装器（鉴权已通过） | `/control/login` handler 内部 |
| 语义 | "未认证，无可奉告" | "端点/方法/生命周期状态不对" | "你声称的身份验证失败" |
| 响应体 | 空 | 简短状态文本，可能回显请求头 | 固定报文 `invalid username or password`，限流时附 `Retry-After` |
| 是否计入限流 | 仅 Basic Auth 失败计入；Cookie 失效不计 | 不计 | 计入（按 IP），成功即清零 |
| 信息泄露面 | 最小（连失败原因都不给） | 泄露 API 结构，属正常自描述 | 统一报文防枚举，但 429 暴露限流策略参数 |
| 浏览器行为 | 根路径 302 到 login.html，其余 401 | 首装期全量 302 到 install.html | 前端读取 403/429 展示错误 |

核心结论：会话 Cookie 与 Basic Auth 共用同一套用户库、bcrypt 校验和按 IP 的限流器，构成统一边界；三类拒绝在状态码、响应体详细程度和限流可见性上刻意分层——越靠近凭证校验层，响应越"标准化防枚举"；越靠近外层中间件，响应越"沉默"。
