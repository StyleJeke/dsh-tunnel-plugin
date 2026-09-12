# dsh-tunnel-plugin

把本机的 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) Web GUI **安全地**发布到公网，
让你在外面用浏览器就能用家里那台机器。

装好后在 DSH 的「设置」里会多出一页 **内网穿透**，点一下启停。访问时先过一页账号密码登录。

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [特性](#特性)
- [前置要求](#前置要求)
- [安装](#安装)
- [配置](#配置)
- [使用](#使用)
- [安全边界](#安全边界)
- [常见问题](#常见问题)
- [开发与自测](#开发与自测)
- [许可](#许可)

---

## 它解决什么问题

**直接把隧道指向 `127.0.0.1:3080` 是不行的。** DSH 自己有三道门，每一道都会把远端挡在外面：

| 门 | 表现 |
| --- | --- |
| `dsh web --host 0.0.0.0` 被写死拒绝 | 源码里明说会「把远程代码执行暴露到网络」 |
| `/api` 的 Host/Origin 信任栅栏 | 隧道送来的是公网主机名，栅栏返回 **403**。而且**只改 `Host` 不够** —— 回环 Host + 外部 Origin 实测同样是 403 |
| 每个 RPC 都要浏览器会话 cookie | 签名绑定 authority；`?token=` 那个启动令牌是进程内随机数，远端浏览器拿不到 |

所以中间必须有一层边界代理。它做三件事：

1. 把 `Host` 与 `Origin` **一起**重写成回环权威，让栅栏放行；
2. 用 `$DSH_HOME/.credentials.yaml` 里的持久签名密钥**铸造**一个合法的会话 cookie 注入 —— 这正是远端拿不到 `?token=` 时的替代方案；
3. 用账号密码把守入口，并对登录失败限速。

> 只重写 `Host` 是行不通的。这是整个项目存在的理由，也是我实测撞到的第一个 403。

## 特性

- **设置页一键启停**，不需要碰命令行
- **账号密码登录**，不是把密钥塞在 URL 里
- **Cloudflare Named Tunnel**：域名固定，重启不变
- **自动重连**：cloudflared 意外退出后自己爬起来（最多 6 次，间隔 5 秒）
- **默认不自动断开**：出差在外时，一条定时断开的隧道等于把自己锁在门外
- **口令强度自检** + **登录失败按来源 IP 逐次加倍锁定**
- 约 90 条断言的探针，**都经真实公网回打本机验证**，不只是本机自环

## 前置要求

| 需要 | 说明 |
| --- | --- |
| DSH | 已能用 `dsh web` 启动。本插件挂在 `web` profile 下 |
| Node.js | 跟 DSH 走，无需另装 |
| cloudflared | Windows：`winget install Cloudflare.cloudflared`；macOS：`brew install cloudflared`；Linux：见 Cloudflare 文档 |
| Cloudflare 账号 + 域名 | **仅固定域名需要**。没有也能用，见下面「快速隧道」 |

> 开发与验证都在 Windows 上完成。宿主半按 PATH 查找 cloudflared（Windows 额外回退两个常见安装路径），
> 边界代理不依赖平台，macOS / Linux 应当可用，但未实测 —— 有问题欢迎开 issue。

## 安装

下面用 `DSH_HOME` 表示 Harness 主目录（默认 `~/.dsh`，Windows 常见为 `C:\Users\<你>\.dsh`）。
profile 目录是 `$DSH_HOME/profiles/web`。示例路径按需替换。

### 1. 克隆到一个固定位置

```powershell
git clone https://github.com/StyleJeke/dsh-tunnel-plugin.git C:\plugins\dsh-tunnel-plugin
```

放在哪里都行，但**别放在会被清理的临时目录**，profile 里会用软链指过来。

### 2. 软链进 profile 的 node_modules

插件以 `link:` 方式安装 —— 实体文件留在原地，改代码重启即生效，不必反复 install。

**Windows**（不需要管理员，`/J` 建的是目录联接）：

```powershell
New-Item -ItemType Junction `
  -Path   "$env:USERPROFILE\.dsh\profiles\web\node_modules\dsh-tunnel-plugin" `
  -Target "C:\plugins\dsh-tunnel-plugin"
```

**macOS / Linux**：

```bash
ln -s /path/to/dsh-tunnel-plugin ~/.dsh/profiles/web/node_modules/dsh-tunnel-plugin
```

> 也可以让 `dsh plugin --profile web add <路径>` 代劳。但如果你的 profile 里还有
> `github:` 形式的依赖，pnpm 会去重新解析它们（可能需要 SSH 密钥），此时手工建软链更省事。

### 3. 在 profile 里登记这一行

编辑 `$DSH_HOME/profiles/web/cordis.patch.yml`，追加：

```yaml
- insert:
    - id: dsh-tunnel
      name: 'dsh-tunnel-plugin'
```

`name` 必须与**包名**一致（本仓库 `package.json` 里的 `name` 是 `dsh-tunnel-plugin`）。

### 4. 设置登录账号密码

```powershell
node C:\plugins\dsh-tunnel-plugin\lib\set-credentials.mjs
```

口令**隐藏输入**、只在本机输入、不接受命令行参数（避免出现在进程列表里），落盘的只有 scrypt 摘要。

> 这一步不能跳过：**没有 `credentials.json` 时边界代理会拒绝启动** —— 唯一的门槛不能缺。

### 5. 重启 `dsh web`

插件包是进程启动时 import 的，改完必须重启：

```
# 关掉正在运行的 dsh web，然后重新启动
dsh web
```

### 6. 打开设置页

DSH 界面左下角 **设置** → 左侧导航里的 **内网穿透**。

---

## 配置

全部落在 `$DSH_HOME/tunnel/`：

| 文件 | 作用 |
| --- | --- |
| `credentials.json` | 登录账号 + scrypt 摘要 + 会话签名密钥。**由 `set-credentials.mjs` 生成，不要手写** |
| `named-tunnel.json` | 存在即走固定域名。内容：`{"name":"dsh","hostname":"dsh.example.com"}` |
| `autostart` | 空文件即可。存在表示 DSH 启动后自动开隧道 |

### 固定域名（推荐长期使用）

**云快速隧道的域名是每次创建隧道时随机分配的，只有 cloudflared 进程活着才固定。**
进程或 DSH 一重启，域名必变 —— 而你在外地时旧链接已死、新链接又拿不到，等于失联。
要长期在外使用，请配一个 Named Tunnel：

```bash
cloudflared tunnel login                       # 浏览器授权，选你的域名
cloudflared tunnel create dsh                  # 建隧道，记下它的名字
cloudflared tunnel route dns dsh dsh.example.com   # 把域名指到隧道
```

然后写配置：

```jsonc
// $DSH_HOME/tunnel/named-tunnel.json
{ "name": "dsh", "hostname": "dsh.example.com" }
```

删掉这个文件就退回快速隧道。

### 自动开启

```powershell
New-Item -ItemType File "$env:USERPROFILE\.dsh\tunnel\autostart" -Force
```

有了它，DSH 启动约 5 秒后隧道会自动开。想关掉就删掉这个文件。

> 这只是让**隧道**跟着 DSH 走。**DSH 自己的开机自启要你另行配置**（Windows 计划任务或启动文件夹、
> systemd、launchd 等）。如果你会长期在外，建议一并做掉 —— 机器重启后 DSH 不自己起来，
> 再稳的域名也连不上。

### 改口令

重跑 `set-credentials.mjs`，然后在设置页点一次 **停止** → **启动**。
每次写入都会轮换会话签名密钥，所以**所有已登录的浏览器会立刻失效** —— 这正是改口令该有的效果。

---

## 使用

### 启停

设置 → 内网穿透 → **启动**。启动后页面会显示访问链接，点输入框可全选复制。

### 登录

把链接发到另一台电脑打开，会看到登录页。登录成功后 **30 天内免登录**。

退出登录：访问 `<你的链接>/__tunnel/logout`。

### 链接会不会变

| 场景 | 域名 | 登录状态 |
| --- | --- | --- |
| 固定域名 + cloudflared 崩溃重连 | **不变** | 保持 |
| 固定域名 + 重启 DSH | **不变** | 保持 |
| 快速隧道 + 任何重启 | **会变** | 保持（cookie 在域名下，域名换了要重新登录） |

所以长期在外请用固定域名。

### 面板上的状态

- **运行中 / 已停止 / 启动中 / 出错** —— 四态，出错时会显示子进程日志尾部
- **已自动重连 N 次** —— 只要 cloudflared 进程不重启，域名就不会变
- **链接已更换** —— 快速隧道下重连换了域名时会显眼提示，旧链接立刻作废

---

## 安全边界

**这层代理是唯一的口令关卡。** 打开链接的人登录之后，就能在这台机器上执行任意命令 ——
等同本机 DSH 的全部权限（`danger-full-access` 时尤其如此）。

已经做到的：

- 口令只在本机输入，落盘的是 scrypt 摘要（`N=32768, r=8, p=1`），没有原文
- 连续输错按来源 IP 逐次加倍锁定：15 秒起，15 分钟封顶
- 会话 cookie 是 `HttpOnly` + `SameSite=Lax` + `Secure` 的 HMAC 签名值
- 边界代理只监听 `127.0.0.1`，公网侧由 cloudflared 承担
- 默认**不自动断开** —— 这是刻意的取舍，见上文

你应当知道的：

- **口令强度**：脚本只硬挡退化口令（长度 < 8、估算熵 < 30 bit、常见弱口令表）。
  真正扛住在线爆破的是那条限速，不是字符规则
- **限速是按来源 IP 且存在内存里的**：DSH 重启会清零，多 IP 的攻击者也能分摊尝试次数
- 想彻底作废一条链接：删掉 `gate-key`（若存在）与 `credentials.json` 并重设口令，
  或者 `cloudflared tunnel delete dsh` 删掉隧道

---

## 常见问题

**启动时报「找不到账号密码文件」**
按提示在本机跑 `node lib/set-credentials.mjs`。这是失败关闭的设计，不是 bug。

**登录时提示「账号或密码不正确」，但口令明明是对的**
先确认隧道是在设置密码**之后**重启的。若仍然不对，多半是摘要参数不一致 ——
早期版本有过 `scryptSync` 选项名写错（`n` 应为 `N`）导致摘要按默认参数计算的 bug，
重跑一次 `set-credentials.mjs` 即可（新版本写入前会自检）。

**登录时提示「cross-origin login rejected」**
同源校验误判。它只防登录 CSRF，不该拦住正常登录 —— 请带上错误里括号内的
`origin=... host=... xfh=...` 开 issue。

**端口 3081 被占用（EADDRINUSE）**
多半是上一次的代理进程没退干净（例如 DSH 被强杀）。代理自带父进程看门狗，
正常情况下会随之退出。手工清理：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 3081 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

**面板显示的公网链接是 `api.trycloudflare.com` 之类**
那是 Cloudflare 的控制面地址，不是隧道地址 —— 说明那次创建隧道失败了。
旧版本的正则太宽松会把它抓走；现已要求主机名至少含一个连字符。

**改了 `cordis.patch.yml` 但没生效**
`patchReload: "live"` 会热重载，但**一次失败的补丁重放会静默掐断热重载通道**，
此后所有改动都不生效。重启 `dsh web` 即可恢复。另外，**插件包本身的改动一律需要重启**
（模块是启动时 import 的）。

**设置页里根本没有「内网穿透」这一页**
按顺序确认：软链建了没 → `cordis.patch.yml` 那行加了没 → `dsh web` 重启了没 →
`dsh --profile web --dump-config` 里能不能看到 `dsh-tunnel-plugin` 这一行。

---

## 开发与自测

```
node probe-host.mjs       宿主半：起真隧道，走完整登录流程
                          （含 403 真跨站、Origin: null、429 锁定、自动重连）
node probe-client.mjs     浏览器包体：模块加载 + apply 契约 + 真实渲染两帧
node probe-watchdog.mjs   父进程死掉后不留残进程占端口
node probe-boot.mjs       客户端包已进入 DSH 启动图
node bootcheck.mjs <包名>  打印客户端启动图里是否包含某包
```

`probe-host.mjs` 跑在**临时 `DSH_HOME`** 里，不会碰你真实的 `credentials.json`；
有 `named-tunnel.json` 就走固定域名路径，没有就退回快速隧道。

### 实际踩过并已修掉的坑

- **`scryptSync` 的选项是 `N`，不是 `n`。** 小写会被静默忽略、回落到默认的 16384，
  于是摘要按 16384 算、文件里却记着 32768，正确口令永远对不上。现在写入前会用
  代理那套参数重算自检。
- **`cmd.exe` 按 OEM 代码页解析 `.cmd`。** UTF-8 中文注释会变成乱码，其中一些字节脱离
  `rem` 变成真命令，把脚本搞坏。`.cmd` 一律保持纯 ASCII。
- **Cloudflare 快速隧道失败时会打印控制面地址** `https://api.trycloudflare.com` 然后退出。
  宽松的正则会把它当成隧道地址，界面于是显示一个死链接（打开只会得到
  `{"success":false,...,"message":"Method Not Allowed"}`）。
- **同源校验别拿 `Origin` 去比 `Host`。** cloudflared 会把 `Host` 改写成源站地址，
  两者永远不等；另外浏览器在沙箱上下文等情形会发 `Origin: null`，那是合法请求。
- **同源校验先后拦掉两次正常登录、拦下的攻击是 0。** 它是纵深防御，不承担认证职责 ——
  不该放在能挡住认证的位置上。

## 许可

MIT
