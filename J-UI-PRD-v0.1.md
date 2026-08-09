# J-UI 产品需求文档（PRD）

版本：v0.1

状态：立项草案

产品类型：自托管 VPS 节点管理与临时出口编排面板

目标平台：Linux VPS 服务端 + 响应式 Web 管理端
项目代号：J-UI

---

## 1. 产品概述

### 1.1 产品定义

J-UI 是一个可在单台 Linux VPS 上一键部署的轻量级代理节点管理面板。

它面向希望快速获得可用订阅、但不愿投入大量时间理解复杂代理核心配置的个人用户。J-UI 将常用节点部署、多客户端订阅导出、服务器监控和临时 VPNGate 出口整合到一个响应式 Web 管理界面中，不依赖 Cloudflare Worker、Pages、D1 或外部数据库。

产品核心不是提供最多的配置选项，而是：

> 让用户以尽可能少的操作完成自建节点、生成订阅，并在需要时临时切换到 VPNGate 等特定出口。

### 1.2 产品愿景

成为比传统全功能代理面板更精简、比脚本部署更直观、比纯订阅生成器更完整的个人 VPS 节点工具。

### 1.3 核心价值

1. 一条命令完成安装。
2. 图形化创建经过验证的常用节点。
3. 一个订阅适配多种主流客户端。
4. 一键创建和停止临时 VPNGate 出口。
5. 节点入口地址保持稳定，出口可动态更换。
6. 在同一个页面查看 VPS 和代理服务状态。
7. 默认配置安全、可用，减少用户排障成本。

---

## 2. 背景与用户问题

### 2.1 市场现状

现有个人代理面板通常存在以下问题：

- 功能庞杂，新用户难以理解大量协议和参数。
- 面板安装成功不代表节点配置可用。
- 证书、端口、防火墙、Reality 密钥等环节容易出错。
- 客户端订阅格式不统一。
- 服务器监控、节点管理和出口管理分散在不同工具中。
- 临时使用 VPNGate 时，需要手动下载配置、拨号、验证出口并配置链式代理。
- 一些轻量工具依赖额外的 Cloudflare Worker、Pages 或远程数据库。

### 2.2 目标用户痛点

典型用户已经购买一台 VPS，希望：

- 快速搭建一个自己的节点。
- 在网页中管理节点，而不是直接编辑 JSON。
- 一键生成适用于 v2rayN、Mihomo/Clash、Shadowrocket 等客户端的订阅。
- 偶尔需要不同地区或相对干净的临时出口。
- 不想长期维护不稳定的 VPNGate 节点。
- 不需要传统大型面板的大部分高级功能。
- 希望节点故障时能够清楚看到原因，而不是反复试错。

---

## 3. 产品目标与非目标

### 3.1 第一阶段产品目标

- 在主流 Linux VPS 上一键安装 J-UI。
- 通过浏览器完成初始化、登录和节点创建。
- 支持 sing-box 的常用入站协议。
- 自动生成 Base64 通用订阅和 Mihomo/Clash YAML。
- 展示 VPS 基础性能与代理核心状态。
- 配置变更前自动校验，失败时保留或恢复旧配置。
- 提供完整安装、更新、备份和卸载入口。

### 3.2 第二阶段产品目标

- 从 VPNGate 获取实时节点列表。
- 按国家创建一个或多个临时出口。
- 每个出口运行在独立 Linux network namespace 中。
- 将指定代理节点绑定到指定 VPNGate 出口。
- 支持手动换 IP、停止出口和设置自动过期时间。
- OpenVPN 断线时严格阻断代理流量，禁止回退到 VPS 原生出口。

### 3.3 非目标

首个正式版本不计划：

- 成为机场级大规模商业计费系统。
- 支持集群、跨 VPS 调度或高可用控制中心。
- 实现复杂财务、支付和工单系统。
- 支持所有代理协议及其全部组合。
- 对 VPNGate IP 的住宅属性作绝对保证。
- 长期维护或出售静态住宅 IP。
- 默认公开 VPNGate 原始 SOCKS5 服务。
- 取代专业服务器监控平台。

---

## 4. 用户画像

### 4.1 个人 VPS 用户

- 拥有一台 Linux VPS。
- 熟悉域名、SSH 等基本概念。
- 不熟悉 sing-box/Xray 的完整配置结构。
- 需要稳定自用节点和多客户端订阅。

### 4.2 临时出口用户

- 偶尔需要日本、韩国、美国等地区的临时出口。
- 接受 VPNGate 不稳定、随时变化的特性。
- 希望按需开启，用完即停。
- 更关心操作成本，而不是出口长期在线率。

### 4.3 轻量面板替代用户

- 当前使用 3X-UI 等面板。
- 实际只使用节点创建、用户凭据和链接导出功能。
- 希望面板更简洁，并增加探针和出口绑定能力。

---

## 5. 核心使用场景

### 5.1 首次安装

1. 用户在 VPS 以 root 身份运行安装命令。
2. 安装器检测系统、架构、端口和依赖。
3. 安装 J-UI、sing-box 和必要组件。
4. 初始化 SQLite 数据库。
5. 生成随机管理路径、管理员密码和恢复密钥。
6. 启动 systemd 服务。
7. 输出管理地址和登录信息。

### 5.2 一键创建节点

1. 用户进入“节点”页面。
2. 点击“创建节点”。
3. 选择推荐预设，例如“VLESS Reality Vision”。
4. 系统自动生成 UUID、Reality 密钥、short ID 和建议端口。
5. 系统检查端口、防火墙、SNI 和核心配置。
6. 配置验证成功后无损重载 sing-box。
7. 页面显示节点链接和订阅入口。

### 5.3 导入客户端

1. 用户进入“订阅”页面。
2. 复制通用订阅或点击对应客户端。
3. 系统根据客户端返回匹配格式。
4. 用户导入 v2rayN、Mihomo/Clash、Shadowrocket 或 sing-box。

### 5.4 创建临时 VPNGate 出口

1. 用户进入“出口”页面。
2. 点击“创建临时出口”。
3. 选择国家、数量和有效时长。
4. 系统按 VPNGate 元数据筛选候选并尝试拨号。
5. 每条成功线路进入独立 netns。
6. 系统验证真实出口 IP。
7. 用户将一个或多个入站节点绑定到该出口。
8. 到期后系统停止 OpenVPN、移除 netns 并清理规则。

### 5.5 手动更换出口

1. 用户点击“更换 IP”。
2. 当前候选进入本次会话黑名单。
3. 系统保持入口端口、UUID 和订阅链接不变。
4. 系统在同国家候选中重新拨号。
5. 成功后更新出口 IP 和状态。

---

## 6. 功能需求

### 6.1 安装与系统管理

#### 必须

- 支持 Debian 11/12、Ubuntu 22.04/24.04。
- 支持 amd64、arm64。
- 使用 systemd 管理服务。
- 自动检测 `/dev/net/tun`。
- 自动安装或提示安装必要依赖。
- 工作目录默认 `/var/lib/j-ui`。
- 配置目录默认 `/etc/j-ui`。
- 日志可通过 Web 页面和 `journalctl` 查看。
- 提供 `j-ui` 命令行管理工具：

```text
j-ui status
j-ui info
j-ui restart
j-ui log
j-ui update
j-ui backup
j-ui restore
j-ui uninstall
```

#### 应该

- 安装前检查管理端口和节点端口冲突。
- 安装失败时自动回滚已创建文件和服务。
- 在线更新前自动备份数据库和配置。
- 更新包必须校验 SHA-256。

### 6.2 管理员认证

#### 必须

- 首次安装生成随机管理员密码。
- 密码只保存安全哈希。
- 登录会话有过期时间。
- Cookie 使用 HttpOnly、SameSite。
- 登录失败按来源 IP 限速。
- 支持修改密码和使全部会话失效。
- 支持随机管理路径。

#### 应该

- 支持 TOTP 两步验证。
- 提供恢复密钥。
- 可限制管理页面只允许指定 IP/CIDR。

### 6.3 仪表盘与服务器探针

#### 必须

- 显示 CPU、内存、磁盘和系统负载。
- 显示实时上传、下载速率和累计流量。
- 显示系统运行时间。
- 显示 J-UI、sing-box 和 OpenVPN 状态。
- 显示节点数量、启用数量和故障数量。
- 显示 VPNGate 活跃出口和到期时间。
- 数据通过 WebSocket 或 SSE 实时更新。

#### 应该

- 显示系统版本、内核、虚拟化类型和公网 IP。
- 显示端口监听状态。
- 显示最近配置失败和服务重启原因。

### 6.4 代理核心管理

#### 必须

- MVP 使用 sing-box。
- J-UI 通过适配层管理代理核心，避免业务代码与 sing-box 配置结构强耦合。
- 配置采用“生成临时文件 → 核心校验 → 原子替换 → 重载 → 健康检查”流程。
- 校验失败时不得覆盖现有可用配置。
- 重载失败时自动回滚旧配置。
- 页面显示当前核心版本和配置版本。

建议接口：

```go
type ProxyEngine interface {
    Version() (string, error)
    Capabilities() []Capability
    Validate(config []byte) error
    Apply(config []byte) error
    Reload() error
    Healthy() bool
}
```

### 6.5 节点管理

#### MVP 必须支持

- VLESS Reality Vision
- VLESS WebSocket TLS
- Trojan TLS
- Hysteria2
- TUIC
- SOCKS5

#### 节点通用字段

- 名称
- 协议
- 监听地址
- 端口
- 启用状态
- 用户/客户端凭据
- 传输方式
- TLS/Reality 配置
- 当前出口
- 创建时间
- 最后修改时间

#### 操作

- 创建、编辑、复制、启用、停用和删除节点。
- 自动生成 UUID、密码和密钥。
- 自动检查端口冲突。
- 根据协议自动放行 TCP/UDP 防火墙。
- 删除节点时清理相关防火墙规则。
- 每个节点可添加多个客户端凭据。
- 单独重置某个客户端凭据，不影响其他用户。
- 可将节点绑定到原生、VPNGate、WARP 或手动 SOCKS5 出口。

### 6.6 TLS 与 Reality

#### 必须

- 自动生成 Reality X25519 密钥和 short ID。
- 提供经过验证的 Reality 预设。
- 支持导入已有证书。
- 页面显示证书路径、域名和到期时间。

#### 第二阶段

- 内置 ACME 自动申请 Let's Encrypt 证书。
- 支持 HTTP-01 或 DNS-01。
- 自动续期并在成功后重载核心。
- 续期失败不得破坏现有证书。

### 6.7 订阅管理

#### 必须

- 每个用户拥有独立随机订阅 Token。
- Token 可重置，重置后旧链接立即失效。
- 未授权 Token 返回 404。
- 订阅只包含启用且未失效的节点。
- 支持以下格式：

| 格式 | 目标客户端 | MVP |
|---|---|---|
| Base64 URI | v2rayN、Shadowrocket、Hiddify | 是 |
| Mihomo YAML | Clash Verge Rev、Mihomo Party | 是 |
| sing-box JSON | sing-box 客户端 | 第二阶段 |
| 单节点 URI | 手动导入 | 是 |

建议 URL：

```text
/sub/{token}
/sub/{token}?format=base64
/sub/{token}?format=clash
/sub/{token}?format=singbox
```

#### 输出要求

- 正确处理 IPv4、IPv6、URL 编码和 YAML 字符转义。
- 自动设置客户端识别所需的响应头。
- Clash 配置默认生成 `PROXY` 和 `AUTO` 代理组。
- 对不支持的协议明确跳过并记录原因。
- 提供订阅预览和格式校验。

### 6.8 VPNGate 节点获取

#### 必须

- 从 VPNGate 官方 CSV API 获取节点。
- 解析：
  - HostName
  - IP
  - CountryLong
  - CountryShort
  - Ping
  - Speed
  - Score
  - NumVpnSessions
  - Uptime
  - OpenVPN 配置
- 缓存最近一次成功结果。
- VPNGate API 暂时不可用时继续展示缓存。
- 支持按国家、Ping、速度和会话数筛选。
- 不把 VPNGate 声明速度描述为本 VPS 实测速度。

### 6.9 VPNGate 隧道编排

#### 必须

- 每条出口运行在独立 netns。
- 每条 netns 使用独立 veth、子网和 OpenVPN 进程。
- 最大并发出口数量可配置，默认 5。
- 同一个 VPNGate 节点默认只允许一个出口占用。
- 一个候选连接失败时自动尝试同国家下一个候选。
- 每次最多尝试 6 个候选。
- 成功后通过至少两个 HTTPS 服务验证真实出口 IP。
- 保持“出口槽位”和本地 SOCKS5 端口稳定。
- 更换 VPNGate 节点不得修改已生成的订阅入口。
- 停止出口时清理进程、netns、veth、路由、防火墙和临时配置。

#### 临时策略

- 手动停止
- 30 分钟
- 1 小时
- 2 小时
- 自定义时间
- 永久运行（显示风险提示）

### 6.10 本地 SOCKS5 桥接

#### 必须

- 每条 VPNGate 出口对应一个本地 SOCKS5 服务。
- 默认只监听 `127.0.0.1`。
- 支持 RFC 1929 用户名密码认证。
- 初期仅支持 TCP CONNECT。
- 拒绝 IPv6 目标，防止绕过 IPv4 VPN 隧道。
- sing-box 通过本地 SOCKS5 出站连接对应 netns。

#### 可选

- 用户可明确开启“公开原始 SOCKS5”。
- 开启时必须设置强随机凭据、来源 IP 白名单和连接数限制。

### 6.11 出口绑定与路由

支持出口类型：

- VPS 原生出口
- VPNGate 临时出口
- 手动 SOCKS5
- WARP IPv4
- WARP IPv6
- WARP 双栈

节点可以：

- 全局绑定某个出口。
- 恢复原生出口。
- 在出口失效时选择“阻断”或“自动换同国家节点”。

默认故障策略必须为：

```text
出口不可用 → 阻断流量 → 尝试恢复
```

不得静默回退到 VPS 原生 IP。

---

## 7. 安全需求

以下为发布阻断项，不属于可延后加分功能。

### 7.1 OpenVPN 配置清洗

仅允许必要指令，禁止至少包括：

```text
script-security
up
down
route-up
route-pre-down
plugin
management
client-connect
client-disconnect
learn-address
daemon
log
log-append
writepid
chroot
cd
config
```

- 强制使用候选记录中的预期远程 IP。
- 忽略 VPNGate 推送的宿主系统 DNS 和非必要路由。
- OpenVPN 只在对应 netns 中运行。

### 7.2 严格 Kill Switch

每个 netns 只允许：

- 通过 veth 连接当前 VPNGate 服务端 IP/端口。
- 连接建立 VPN 所需的 DNS。
- 已建立连接的回包。
- 通过 `tun0` 访问互联网。

其余非 `tun0` 业务流量全部拒绝。

OpenVPN 断开时，用户业务不得通过 veth/NAT 回退到 VPS 原生出口。

### 7.3 Web 管理安全

- 默认不建议将纯 HTTP 管理端暴露公网。
- 支持内置 HTTPS 或生成反向代理配置。
- 管理接口支持 IP 白名单。
- 所有状态变更 API 只接受 POST/PUT/DELETE。
- 实施 CSRF 防护。
- 敏感数据不写入普通日志。
- 不在前端返回代理核心私钥，除非用户执行明确的导出操作。

### 7.4 进程权限

长期目标：

- Web/API 主进程以非 root 用户运行。
- 使用单独的受限特权 Helper 执行 netns、路由、防火墙等操作。
- Helper 只允许固定参数和固定操作，不接受任意 shell 命令。

MVP 如暂时以 root 运行，systemd 至少应配置：

- 私有临时目录
- 文件系统保护
- 限制可写目录
- 合理的文件描述符和进程数上限
- 服务停止时完整清理子进程

### 7.5 配置与升级安全

- 数据库和私钥权限为 `0600`。
- 工作目录权限为 `0700`。
- 更新包校验哈希。
- 配置写入使用临时文件和原子替换。
- 更新、恢复和重载失败时保留可用版本。

---

## 8. 非功能需求

### 8.1 性能

- J-UI 空闲内存目标低于 80 MB，不含 sing-box/OpenVPN。
- 仪表盘更新不得显著影响代理转发。
- 监控采样间隔默认 2 秒。
- 数据库写操作批量化，避免高频磁盘写入。
- 单 VPS 默认支持至少 100 个节点配置和 5 条 VPNGate 出口。

### 8.2 可靠性

- J-UI 重启后恢复节点和未过期出口。
- 配置错误不得导致全部节点永久离线。
- VPNGate API 不可用不得影响已有原生节点。
- 某条 VPNGate 出口失败不得影响其他出口。
- 系统重启后清理孤立 netns 和防火墙规则。

### 8.3 可维护性

- Go 后端模块化。
- 前后端 API 有版本号，例如 `/api/v1`。
- 数据库使用显式迁移。
- 代理核心配置生成具备单元测试和 Golden 文件测试。
- 订阅格式具备解析回归测试。
- netns、防火墙操作具备幂等性。

### 8.4 可用性

- 响应式界面支持桌面、平板和手机浏览器。
- 推荐配置与高级配置分层展示。
- 错误信息使用用户可理解的语言。
- 所有危险操作明确显示影响范围。
- 页面不要求用户理解底层 JSON。

---

## 9. 信息架构

### 9.1 登录页

- 管理密码
- 两步验证（后续）
- 登录失败提示

### 9.2 仪表盘

- 系统资源
- 服务状态
- 节点概览
- 出口概览
- 实时流量
- 最近事件

### 9.3 节点

- 节点列表
- 创建节点
- 节点详情
- 客户端凭据
- 出口绑定
- 单节点链接

### 9.4 出口

- VPS 原生
- VPNGate
- WARP
- 手动 SOCKS5
- 当前出口 IP
- 存活时间
- 更换、停止、延长

### 9.5 订阅

- 用户列表
- Token 管理
- 客户端格式
- 订阅预览
- 二维码

### 9.6 监控

- CPU/内存/磁盘
- 网络
- 节点流量
- 服务日志
- OpenVPN 状态

### 9.7 系统

- 核心版本
- HTTPS/证书
- 防火墙
- 备份恢复
- 更新
- 安全设置

---

## 10. 技术架构建议

### 10.1 服务端

- 语言：Go
- 数据库：SQLite
- Web：Go `net/http` 或轻量路由器
- 实时数据：WebSocket 或 SSE
- 前端资源：编译后嵌入 Go 二进制
- 服务管理：systemd
- 代理核心：sing-box
- VPN：官方 OpenVPN 客户端
- 隔离：Linux network namespace
- 防火墙：优先 nftables，必要时兼容 iptables

### 10.2 前端

可选：

- Vue 3 + TypeScript + Vite
- React + TypeScript + Vite

要求：

- 输出静态资源。
- 不依赖 Node.js 运行时。
- 构建后嵌入 Go 二进制。
- 移动端响应式。

### 10.3 模块划分

```text
cmd/j-ui
internal/
  auth/
  api/
  database/
  engine/
    singbox/
    xray/          # 预留
  node/
  subscription/
  monitor/
  certificate/
  firewall/
  vpngate/
  netns/
  updater/
web/
  src/
  dist/
```

---

## 11. 数据模型草案

### administrators

- id
- username
- password_hash
- totp_secret
- created_at
- updated_at

### sessions

- id
- token_hash
- administrator_id
- source_ip
- expires_at

### users

- id
- name
- subscription_token_hash
- enabled
- traffic_limit
- traffic_used
- expire_at
- created_at

### nodes

- id
- name
- protocol
- listen
- port
- enabled
- transport
- security
- config_json
- outbound_id
- created_at
- updated_at

### node_clients

- id
- node_id
- user_id
- name
- credential_json
- enabled
- created_at

### outbounds

- id
- name
- type
- status
- country_code
- exit_ip
- config_json
- failure_policy
- expire_at
- created_at
- updated_at

### vpngate_nodes_cache

- hostname
- ip
- country
- country_code
- ping
- speed
- score
- sessions
- uptime
- ovpn_config
- fetched_at

### outbound_events

- id
- outbound_id
- event_type
- old_exit_ip
- new_exit_ip
- message
- created_at

### traffic_daily

- id
- node_id
- user_id
- day
- upload_bytes
- download_bytes

### system_settings

- key
- value
- updated_at

---

## 12. API 草案

### 认证

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/password
GET    /api/v1/auth/session
```

### 系统

```text
GET    /api/v1/system/status
GET    /api/v1/system/info
GET    /api/v1/system/logs
POST   /api/v1/system/restart
POST   /api/v1/system/update
POST   /api/v1/system/backup
```

### 节点

```text
GET    /api/v1/nodes
POST   /api/v1/nodes
GET    /api/v1/nodes/{id}
PUT    /api/v1/nodes/{id}
DELETE /api/v1/nodes/{id}
POST   /api/v1/nodes/{id}/enable
POST   /api/v1/nodes/{id}/disable
POST   /api/v1/nodes/{id}/clone
POST   /api/v1/nodes/{id}/bind-outbound
```

### 客户端凭据

```text
GET    /api/v1/nodes/{id}/clients
POST   /api/v1/nodes/{id}/clients
PUT    /api/v1/nodes/{id}/clients/{clientId}
DELETE /api/v1/nodes/{id}/clients/{clientId}
POST   /api/v1/nodes/{id}/clients/{clientId}/reset
```

### VPNGate

```text
GET    /api/v1/vpngate/regions
GET    /api/v1/vpngate/nodes
POST   /api/v1/vpngate/refresh
POST   /api/v1/vpngate/outbounds
POST   /api/v1/vpngate/outbounds/{id}/swap
POST   /api/v1/vpngate/outbounds/{id}/extend
DELETE /api/v1/vpngate/outbounds/{id}
```

### 订阅

```text
GET    /sub/{token}
GET    /sub/{token}?format=clash
GET    /sub/{token}?format=singbox
```

### 实时状态

```text
GET    /api/v1/events
```

---

## 13. 关键交互原则

### 13.1 推荐模式优先

创建节点时先展示：

```text
推荐：VLESS Reality Vision
推荐：Hysteria2
推荐：Trojan TLS
更多高级配置...
```

### 13.2 显示真实状态

必须区分：

- 已保存
- 配置校验成功
- 核心已重载
- 端口已监听
- 公网连通性未知
- 出口已验证

不得仅因数据库写入成功就显示“节点部署成功”。

### 13.3 故障可解释

错误示例：

```text
端口 443 已被 nginx 占用。
Reality 目标 addons.mozilla.org:443 无法完成 TLS 1.3 握手。
OpenVPN 已连接，但出口 IP 验证失败。
VPNGate 出口不可用，流量已阻断，未回退到 VPS 原生 IP。
```

---

## 14. MVP 验收标准

### 安装

- 在全新 Debian 12、Ubuntu 22.04 上一条命令安装成功。
- 重复执行安装器不会破坏已有配置。
- 安装完成后输出可访问的管理地址。

### 节点

- 用户可在 3 分钟内创建一个 VLESS Reality Vision 节点。
- 配置错误不会覆盖现有 sing-box 配置。
- 节点启停状态与实际监听状态一致。

### 订阅

- Base64 订阅可被 v2rayN 正确导入。
- Clash YAML 可被 Mihomo 核心校验通过。
- Shadowrocket 可以导入标准节点链接。
- Token 重置后旧订阅立即失效。

### 监控

- 仪表盘可实时显示 CPU、内存、磁盘和网络速率。
- sing-box 停止后，页面在 5 秒内显示异常。

### 可靠性

- J-UI 重启后节点配置不丢失。
- sing-box 重载失败后自动恢复上一份可用配置。
- 数据库备份能够在新安装环境恢复。

---

## 15. VPNGate 阶段验收标准

- 可以按国家创建 1～5 条并行出口。
- 每条出口位于独立 netns。
- 多条出口显示不同的真实公网 IP。
- 将节点绑定到出口后，客户端访问检测网站看到对应出口 IP。
- 更换 VPNGate 节点后，客户端订阅地址、端口和凭据保持不变。
- OpenVPN 断开时，代理业务无法通过 VPS 原生地址访问互联网。
- 到期后出口自动停止并彻底清理 netns 和防火墙规则。
- VPS SSH 和 J-UI 管理连接不受 VPNGate 默认路由影响。

---

## 16. 指标

### 产品指标

- 新用户从安装到获得首个可用节点不超过 10 分钟。
- 创建推荐节点所需必填字段不超过 4 个。
- 常见节点创建成功率达到 95%。
- 订阅导入成功率达到 98%。
- 90% 的日常操作可在 Web UI 中完成。

### 技术指标

- 配置失败导致全量节点中断的概率接近 0。
- VPNGate 断线回退 VPS 原生出口的次数必须为 0。
- J-UI 空闲 CPU 平均低于 1%。
- 核心状态异常在 5 秒内反映到页面。

---

## 17. 风险与应对

### VPNGate 不稳定

应对：

- 强调临时出口定位。
- 同地区自动尝试多个候选。
- 提供 TTL 和一键换 IP。
- VPNGate 故障不得影响原生节点。

### 协议组合过多

应对：

- 使用经过测试的预设。
- 高级模式后置。
- 通过能力矩阵限制无效组合。

### root 权限风险

应对：

- 固定特权操作集合。
- 后续拆分非 root Web 服务与特权 Helper。
- 配置清洗、参数校验和 systemd 加固作为发布底线。

### 客户端格式差异

应对：

- 建立订阅 Golden 测试。
- 使用实际客户端或对应核心做发布前验证。
- UI 明确显示每种客户端支持的协议。

### 范围膨胀

应对：

- MVP 只实现单 VPS、单管理员、常用节点和两种订阅。
- VPNGate、多用户和风险评分按阶段加入。
- 新功能必须服务于“更少配置获得可用节点”的核心目标。

---

## 18. 开源与许可

建议 J-UI 使用明确的开源许可证，例如 MIT 或 Apache-2.0。

如参考或复用以下项目代码，必须遵循其许可证并保留版权声明：

- K-UI / K-UI-workers
- fanout
- sing-box
- Xray-core
- OpenVPN

产品文档应明确：

- VPNGate 是第三方公益学术实验服务。
- J-UI 不运营、不控制 VPNGate 节点。
- 出口质量和在线时间不作保证。
- 用户应遵守当地法律及 VPNGate 使用条款。

---

## 19. 产品一句话

> J-UI：一键部署在个人 VPS 上的轻量节点、订阅、监控和临时出口管理面板。

## 20. MVP 发布定义

J-UI MVP 可以发布的最低条件：

1. 全新 VPS 一键安装。
2. Web 登录和系统仪表盘。
3. sing-box 配置事务与失败回滚。
4. 一键创建 VLESS Reality、Trojan TLS、Hysteria2。
5. 导出 Base64 和 Mihomo/Clash 订阅。
6. 节点启停、编辑和凭据重置。
7. SQLite 备份恢复。
8. Debian、Ubuntu 实机验证通过。

VPNGate 多出口属于紧随 MVP 的第二个可交付版本，不阻塞基础节点面板首次发布。
