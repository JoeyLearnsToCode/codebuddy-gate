# codebuddy-gate

把本机多个 codebuddy code 会话聚合到一个 HTTP 入口：登录鉴权、会话列表、按会话透明反代。

```
浏览器 -> [可选：nginx -> auth_request] -> codebuddy-gate -> codebuddy 会话 endpoint
```

## 快速开始

```bash
go build -o bin/codebuddy-gate.exe .
bin\codebuddy-gate.exe -password-sha256 $(printf '你的口令' | sha256sum | cut -d' ' -f1)
# 也可以图省事用明文：-password 你的口令
# 打开 http://127.0.0.1:8787/list
```

## 路由

| 路径 | 说明 |
| --- | --- |
| `/list` | 会话列表页，5 秒自动刷新，默认只显示心跳活跃（`CBC_GATE_ACTIVE_WINDOW` 内）的会话，`?all=1` 显示全部 |
| `/login`、`/logout` | 登录 / 登出。登录成功后跳回 `next` 参数指定的站内地址 |
| `/auth` | nginx `auth_request` 配套端点：已登录 200，未登录 401 |
| `/_gate/api/sessions` | 会话列表 JSON（`?all=1` 不过滤） |
| `/healthz` | 健康检查 |
| `/<sessionId>/<任意路径>` | 反代到该会话的 endpoint，`/<任意路径>` 原样转发（支持 query、静态资源、API、WebSocket、SSE） |
| `/<pid>/<任意路径>` | 同上，用进程号代替 sessionId |

`<任意路径>` 可以为空，即 `/<sessionId>` 也等价于访问会话根路径。

## 关于路径改写

codebuddy code 的 Web UI 全部使用根绝对路径（`/assets/*`、`/api/v1/*`、WebSocket 等），直接挂在
`/<sessionId>/` 前缀下会 404。网关做了两层处理：

1. **响应体改写**：`html / js / css / svg` 响应中的 `/api/`、`/assets/`、`/internal/`、`/sw.js` 等
   应用自有路径会被补上 `/<sessionId>` 前缀；上游的 `Location` 跳转头同样会被改写。
   白名单只收录确定是根绝对路径的前缀 —— `/events` 这类既可能是根路径、也可能只是拼在
   `/api/v1/agent-home` 后面的相对后缀，一律不能收录，否则会拼出
   `/api/v1/agent-home/<sessionId>/events` 这种 404 的 URL。
2. **Cookie 兜底**：访问 `/<sessionId>/...` 时下发 `cbg_session` 亲和 cookie，万一有漏改写的
   根路径请求（`/assets/xxx.js`）也能落到正确的会话。

另外，codebuddy 的 endpoint 会校验 `Origin` 白名单，只放行自己的 origin。对浏览器来说网关
就是来源站点，因此转发时会把 `Origin` 换成上游的 origin，否则所有 `POST`/`PUT`（含 WebSocket
的 `acp/connect`）都会被上游以 `Origin not allowed` 拒绝。

### 监控页里的会话地址

系统监控页和 Workers 面板由 `/api/v1/workers` 提供数据，里面每一项都带着原始 endpoint
（`http://127.0.0.1:<port>`）。网关会把响应体里的这些 endpoint 换成
`${dynamicHost}/<sessionId>`（`dynamicHost` 取当前请求的 scheme + Host，即浏览器访问网关用的
那个 origin），面板上的链接点开后仍然走网关，不会因为直连 127.0.0.1 而打不开。
认不出来的 endpoint（不在会话目录里）保持原样。

## 配置

优先级：**命令行参数 > 环境变量 > 内置默认值**。

```bash
# 推荐用 sha256 设置口令，明文口令会出现在命令行历史与进程列表里
HASH=$(printf '你的口令' | sha256sum | cut -d' ' -f1)
codebuddy-gate -addr 0.0.0.0:8787 -password-sha256 "$HASH" -debug

codebuddy-gate -h          # 查看全部参数
```

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-addr` | `CBC_GATE_ADDR` | `127.0.0.1:8787` | 监听地址 |
| `-sessions-dir` | `CBC_GATE_SESSIONS_DIR` | `%USERPROFILE%\.codebuddy\sessions` | 会话 json 目录 |
| `-user` | `CBC_GATE_USER` | `codebuddy` | 登录用户名 |
| `-password-sha256` | `CBC_GATE_PASSWORD_SHA256` | - | 口令的 sha256 十六进制，**推荐**，口令不会出现在命令行历史与进程列表里 |
| `-password` | `CBC_GATE_PASSWORD` | - | 登录口令（明文），只图方便时用；与 `-password-sha256` 同时给出会报错 |
| - | `CBC_GATE_SECRET` | 随机 | 鉴权 cookie 的 HMAC 密钥；不设置时每次启动随机，重启后需重新登录 |
| `-cookie-ttl` | `CBC_GATE_COOKIE_TTL` | `8760h` | 登录有效期 |
| `-active-window` | `CBC_GATE_ACTIVE_WINDOW` | `5m` | 心跳超过该时长视为会话已退出 |
| `-no-auth` | `CBC_GATE_NO_AUTH` | `false` | 关闭鉴权，仅限本机调试 |
| `-log-level` | `CBC_GATE_LOG_LEVEL` | `info` | 日志级别 `debug\|info\|warn\|error` |
| `-debug` | - | `false` | 等价于 `-log-level=debug` |

口令取值顺序：`-password` / `-password-sha256` > `CBC_GATE_PASSWORD_SHA256` >
`CBC_GATE_PASSWORD` > 随机生成（启动时在日志里打印，重启即失效）。
口令的 sha256 可以这样算：

```bash
printf '你的口令' | sha256sum        # Linux / Git Bash
```

## 日志

默认级别 `info`，只输出启动/告警/错误。**逐请求的访问日志是 `debug` 级别**，不会默认刷屏：

```bash
codebuddy-gate -debug
# [gate] 2026/09/08 16:31:31 debug GET /healthz -> 200 (0s)
```

## 界面

网关自己的三个页面（会话列表、登录、错误页）共用一套设计令牌，定义在
`internal/web/templates/styles.html`（`{{define "styles"}}`，各页 `<style>{{template "styles"}}</style>` 引入）：

- **亮色 SaaS 风格**：背景 `#F8FAFC`、文字 `#0F172A`、主色 `#2563EB`，语义色走 CSS 变量，不写字面量
- **窄屏自适应**：`≤760px` 时会话表格转成卡片（表头隐藏、每行用 `data-label` 显示字段名，
  版本/Endpoint 收起），主按钮撑满且 `min-height: 44px`
- **触控与无障碍**：输入控件 ≥48px、`viewport-fit=cover` + `env(safe-area-inset-*)`、
  `:focus-visible` 焦点环、状态用「圆点 + 文字」而非仅靠颜色、错误提示带 `role="alert"`、
  密码框可显示/隐藏、尊重 `prefers-reduced-motion`

配色与风格取自 `ui-ux-pro-max`（Data-Dense Dashboard + SaaS 亮色 + Inter/系统字体）。

## 目录结构

```
main.go                     路由装配、优雅退出、DEBUG 访问日志
internal/config             命令行参数 + 环境变量配置（命令行优先）
internal/session            扫描并解析 ~/.codebuddy/sessions/*.json
internal/proxy              按会话反代 + 绝对路径改写 + endpoint 改写
internal/web                登录鉴权、/list 页面与页面模板（含共享设计令牌 styles.html）
internal/logging            分级日志（默认 info）
```
