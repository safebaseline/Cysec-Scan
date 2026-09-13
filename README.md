# Cysec-Scan · 攻击面资产发现与风险检测平台

以资产为中心、以空间测绘为入口、以攻击面发现为核心、以漏洞检测为结果的攻击面管理平台（ASM）。

单一 Go 二进制交付（前端嵌入），SQLite 存储，开箱即用。

> **本平台仅用于已授权资产的安全管理与检测。** 所有扫描能力默认采用低风险、非破坏性检测策略。

## 核心链路

```
导入/测绘 → 存活探测 → 子域名枚举 → 端口扫描 → 服务识别 → 资产分拣
→ Web 资产发现 → 技术指纹 → 风险检测 + PoC 规则扫描（含 OOB 反连）
→ 漏洞去重入库 → AI 研判（误报/实报）→ 风险评分/资产画像 → 变化监控 → 报告/导出
```

## 功能特性

### 资产发现与导入

- 资产导入：IP / IP 列表 / CIDR / IP 段 / 域名 / URL，批量导入，自动去重，公网/内网分类
- 空间测绘：内置 FOFA / Quake / Shodan / 0.zone / ZoomEye 适配器，密钥与接口地址均在界面配置；
  测绘结果先做**存活性探测**再入库；内置限速与 429 指数退避重试
- 子域名枚举：域名目标自动爆破子域名 + 证书透明度被动收集（[crt.name](https://crt.name)，不依赖字典、可发现历史子域），解析出的新 IP 纳入后续扫描；任务域名与收集到的子域名按 https/http 探测为 Web 资产，并与其解析 IP 上发现的开放 Web 端口拼接探测（覆盖 vhost / CDN 同 IP 多站点与非常用端口场景）
- 存活探测（TCP）、端口扫描（常用 / Top1000 / 指定 / 范围 / 全端口）、服务识别（端口规则 + Banner 抓取）
- 资产分拣：按端口/服务自动分类（服务器 / 数据库 / Web 服务器 / DNS / 邮件 / 文件服务等）
- Web 资产识别：状态码 / Title / Server / 证书 / Headers，非标准 HTTPS 端口自动 TLS 探测；
  技术指纹 25+ 规则（Nginx、Spring、WordPress、Vue 等）
- 资产关联：IP ↔ Domain ↔ Port ↔ Service ↔ Web ↔ Tech ↔ Vuln 全链路关联与 IP 资产画像
- 资产变化检测：新增 IP / 端口 / Web / 漏洞自动记录，前端可查
- 资产白名单：白名单内资产跳过全部漏洞扫描（资产发现与端口扫描不受影响）
- 全局搜索、CSV / JSON 导出、列表分页

### 漏洞检测引擎

- **三种规则格式**：nuclei（http + matchers + DSL）、xray（CEL 表达式）、afrog（set 变量 + CEL），
  导入时自动识别格式，不支持的语法自动标记为不可执行
- **DSL 求值器**：自研递归下降解析器，支持 40+ nuclei DSL 函数与逻辑运算
- **OOB 反连检测**：内置 interactsh 兼容服务端，单会话注册多子域复用，支持 `{{interactsh-url}}` 模板变量与回调精确匹配
- **误报治理**（多层过滤）：
  - 基线指纹：随机路径探测取基线，命中响应与基线一致的 CDN/WAF/SPA 通用页面直接否决
  - internal 匹配器与无条件 DSL 规则需满足状态码、响应长度、动态内容特征等多重校验
  - WAF 拦截页（403/404 小页面）、SPA 前端页、静态资源页特征过滤
- **报文留痕**：每条漏洞记录完整请求/响应报文（Burp Suite 风格展示），便于人工复核
- **新增 Web 资产实时漏洞扫描**：任何来源（任务发现 / 资产导入 / 空间测绘导入）新增的 Web 资产入库后立即异步执行风险检测 + WIH + 规则库扫描（`scan.web_autoscan` 可关，白名单跳过）
- 漏洞统一格式与去重（资产 + 端口 + URL + 漏洞 ID），风险等级 Critical ~ Info
- 内置风险检测（非破坏性）：HTTP 安全头、敏感路径泄露、SSL/TLS、组件版本、敏感服务暴露
- **WIH JS 敏感信息检测**：扫描站点首页与引用 JS，正则匹配云 AK/SK、JWT、密码、机器人 Webhook 等泄露并入库（默认规则集移植自 [WIHscan](https://github.com/ifacker/WIHscan)，MIT；规则可在漏洞规则库页管理，支持单 URL 即时检测）

### AI 研判

- 对接 OpenAI 兼容接口（DeepSeek / Qwen / GPT / Ollama 等均可），界面配置 base_url / api_key / model
- 一键获取可用模型列表；单条研判或"AI 全部研判"批量处理
- 扫描完成后可自动对新检出漏洞做误报/实报研判，给出置信度与理由
- 漏洞支持人工标记（实报 / 误报 / 取消），与 AI 研判结果并存

### 规则库管理

- POC 文件仓库：`data/poc/` 下默认 xray / nuclei / afrog 三个目录，界面浏览、上传、新建文件夹、在线编辑
- 模板源更新：配置 GitHub 仓库源，git clone / pull 自动同步；网络不畅时可配置镜像前缀（如 ghproxy）；
  支持每日定时自动更新；**增量对比**——仅对新增规则触发全资产漏洞扫描
- POC 目录监控：监视规则文件变化（默认 60 秒），新增规则文件自动入库并触发全资产扫描
- 界面化管理：按来源/等级/启用状态/可执行性筛选，单规则在线测试、启停、删除

### 任务与平台

- 任务管理：快速 / 标准 / 深度三种模式，暂停 / 恢复 / 终止，并发与超时控制，优先级
- 扫描周期：一次性 / 8 小时 / 24 小时 / 每周 / **自定义小时间隔**
- 全局出站代理：http / socks5（含用户名密码认证），配置写回 config.yaml；流量分流——**Web 资产探测与漏洞扫描引擎走代理**，**TCP 层（存活探测/端口扫描/服务识别）与空间测绘走直连**（代理层对任意目标返回连接成功，端口判定会虚高）
- 全局 User-Agent：所有出站请求统一 UA，界面可配置
- Web 管理界面（React + TypeScript，全中文），列表统一分页（每页 20 条）
- Token 鉴权 + RBAC（admin / auditor / viewer），操作审计日志
- 插件化架构：发现 / 测绘 / 扫描 / 指纹 / 风险全部为插件，可注册扩展
### 页面截图
<img width="1477" height="1025" alt="image" src="https://github.com/user-attachments/assets/d2ee4993-d021-4b7c-9e1e-90ce10b446f3" />
<img width="1491" height="1032" alt="image" src="https://github.com/user-attachments/assets/743d1cf9-908a-4966-963b-80c1af8c6764" />
<img width="1489" height="1025" alt="image" src="https://github.com/user-attachments/assets/15ab794c-f99c-4547-8da5-7c2493f7cf4e" />
<img width="1483" height="1046" alt="image" src="https://github.com/user-attachments/assets/78d5d12d-f5a5-4564-abdc-6371fee50cdd" />
<img width="1468" height="1036" alt="image" src="https://github.com/user-attachments/assets/ed16f3ff-dbe1-479e-9e75-a37280e357be" />

## 快速开始

```bash
# 源码构建（前端 + 后端单二进制）
make build
./dist/cysec -config configs/config.yaml
```

程序启动时自动初始化：`config.yaml` 不存在则生成默认配置；数据库文件不存在则自动建库建表；
每次启动自动备份数据库至 `data/backups/`（保留最近 7 份）。

访问 http://127.0.0.1:8080 ，默认账号 `admin / admin123`（首次登录后请修改配置并重启）。

可选 Docker 方式：`cd deploy && docker compose up -d`。

## 扫描模式

| 模式 | 空间测绘 | 端口范围 | 漏洞扫描 | 其他 |
|------|---------|---------|---------|------|
| 快速 | ✅ | 常见端口 | ❌ | 探测失败且未指定端口的目标直接跳过 |
| 标准 | ✅ | Top1000 | ✅ 风险检测 + 全部规则 | — |
| 深度 | ✅ | 全端口 1-65535 | ✅ 风险检测 + 全部规则 | URL / API 发现（首页链接提取） |

任务显式指定端口时优先使用指定端口；周期任务到期自动执行。

## 配置

`configs/config.yaml` 主要段落（代理、测绘密钥、AI 等均支持界面配置并写回）：

| 段落 | 说明 |
|------|------|
| `server` | 监听地址 / 端口 |
| `auth` | 管理员引导账号、Token 有效期 |
| `database` | SQLite 路径 |
| `worker` | 任务并发 |
| `scan` | 超时、常用端口表（top_ports）、单目标最大端口数、子域名爆破开关/并发/字典 |
| `proxy` | 全局出站代理（http/socks5 + 认证） |
| `user_agent` | 全局出站 User-Agent |
| `mapping` | 空间测绘数据源密钥与开关 |

## 目录结构

```
Cysec-Scan/
├── server/               Go 后端（API + Worker 一体）
│   ├── cmd/cysec/        入口（嵌入前端产物、初始化/备份/定时更新/目录监控）
│   ├── internal/
│   │   ├── ai/           AI 研判（OpenAI 兼容接口）
│   │   ├── api/          REST API 层
│   │   ├── auth/         鉴权 + RBAC
│   │   ├── config/       YAML 配置
│   │   ├── engine/       任务调度 + 扫描流水线 + 目标/端口解析
│   │   ├── mapper/       空间测绘数据源（FOFA/Quake/Shodan/0.zone/ZoomEye）
│   │   ├── model/        数据模型
│   │   ├── netproxy/     全局出站代理（http/socks5）
│   │   ├── oob/          OOB 反连检测（interactsh 兼容）
│   │   ├── plugins/      插件接口与注册中心
│   │   ├── store/        SQLite 存储层（自动建表/迁移）
│   │   ├── subdomain/    子域名枚举
│   │   ├── ua/           User-Agent 管理
│   │   ├── vulnrule/     漏洞规则引擎（解析/执行/DSL/监控/模板源）
│   │   └── ...           model 等
│   └── plugins/builtin/  内置插件（探测/扫描/识别/测绘/指纹/风险）
├── web/                  React + TS + Vite 前端
├── configs/              配置模板
├── data/                 运行时数据（数据库 / 备份 / POC 仓库）
│   └── poc/              xray / nuclei / afrog 三类 POC 目录
├── deploy/               Dockerfile / docker-compose
└── docs/                 API 文档 / 部署文档 / 用户手册 / 数据库设计
```

## 插件扩展

实现 `server/internal/plugins` 中任一接口并注册即可，无需修改核心逻辑：

```go
package myext

import "cysec/internal/plugins"

type FOFAProvider struct{}
func (p *FOFAProvider) Name() string { return "fofa" }
func (p *FOFAProvider) Map(ip string) []plugins.MappingRecord { /* 调用 FOFA API */ }

func init() { plugins.RegisterMapper(&FOFAProvider{}) }
```

可扩展点：`Prober`（存活）、`PortScanner`（端口）、`ServiceIdentifier`（服务）、
`DomainResolver`（DNS）、`SpaceMapper`（空间测绘数据源）、`Fingerprinter`（指纹）、`RiskScanner`（风险）。

## 文档

- [API 文档](docs/API.md)
- [部署文档](docs/DEPLOY.md)
- [用户手册](docs/USER_GUIDE.md)
- [数据库设计](docs/DATABASE.md)
