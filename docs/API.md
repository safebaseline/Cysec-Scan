# Cysec-Scan REST API 文档

Base URL: `http://<host>:8080/api`

除 `POST /login` 与 `GET /health` 外，全部接口需携带 `Authorization: Bearer <token>`。

角色权限：
- `admin`：全部权限
- `auditor`：只读 + 创建/控制任务 + 导入资产
- `viewer`：只读

---

## 认证

### POST /login
```json
{ "username": "admin", "password": "admin123" }
```
返回 `{ "token": "..." }`，有效期默认 72 小时（配置 `auth.token_ttl_hours`）。

### POST /logout
注销当前 Token。

---

## 项目

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /projects | 创建项目 `{name, description}`（admin） |
| GET | /projects | 项目列表 |

---

## 资产

### POST /assets — 导入资产（自动去重）
```json
{ "project_id": 1, "type": "mixed", "content": "192.168.1.1\n192.168.1.0/24\nexample.com\nhttps://a.example.com" }
```
返回 `{ "ips": n, "domains": n, "urls": n, "new_ips": n, "new_domains": n }`

### GET /assets?type=ip|domain|port|web|url&project_id=1&q=&limit=&offset=
统一资产列表（分页 + 搜索）。

### GET /assets/ip/{ip}?project_id=1
IP 资产画像：关联域名 / 端口 / Web / 漏洞 / 风险评分。

### 其余资产 API
| 方法 | 路径 |
|---|---|
| GET | /ips |
| GET | /domains |
| GET | /ports |
| GET | /services |
| GET | /urls |
| GET | /webs |
| GET | /vulnerabilities（支持 `severity=` 过滤、`q=` 搜索；列表不含报文瘦身） |
| GET | /vulnerabilities/{id} | 漏洞详情，含 `request` / `response` 检测报文 |

---

## 任务

### POST /tasks — 创建扫描任务
```json
{
  "project_id": 1,
  "name": " weekly-scan",
  "targets": "192.168.1.0/24\nexample.com",
  "target_type": "ip",
  "mode": "standard",          // quick | standard | deep
  "ports": "",                 // 空=常用端口；"80,443"；"1-1000"；"full"
  "concurrency": 8,
  "timeout_sec": 5,
  "priority": 5                // 数字越小优先级越高
}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /tasks?project_id=&status= | 任务列表 |
| GET | /tasks/{id} | 任务详情（状态/进度） |
| GET | /tasks/{id}/logs | 任务日志 |
| POST | /tasks/{id}/pause | 暂停 |
| POST | /tasks/{id}/resume | 恢复 |
| POST | /tasks/{id}/cancel | 终止 |

任务状态：`pending / running / paused / done / failed / canceled`

---

## 统计 / 搜索 / 变化 / 报告

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /stats?project_id= | 资产与漏洞统计 |
| GET | /search?project_id=&q= | 全局搜索（IP/域名/URL/端口/漏洞） |
| GET | /changes?project_id= | 资产变化记录（新增 IP/端口/Web/漏洞） |
| GET | /reports?project_id= | 汇总报告 JSON（统计 + 高风险资产 + 漏洞详情） |
| GET | /export?project_id=&type=ips\|domains\|ports\|webs\|urls\|vulnerabilities&format=csv\|json | 导出 |

---

## 空间测绘（网络空间测绘数据源）

平台内置 FOFA / Quake（360） / Shodan / 0.zone（零零信安） / ZoomEye 五个测绘引擎适配器，
统一输入 IP 或域名，统一输出归一化测绘记录（IP/Domain/Port/Service/URL/Title/指纹）并自动入库建立关联。
标准/深度扫描任务会在本地端口扫描前自动调用已启用的引擎。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /system/mapping | 当前测绘配置与状态 |
| PUT | /system/mapping | 更新测绘配置（admin），立即生效并持久化 |
| POST | /system/mapping/test | 用表单配置对目标试查询（不保存），返回记录样例与各引擎错误 |
| POST | /mapping/query | 即时测绘并导入项目 `{project_id, target}` |

配置字段：`enabled`（总开关）、`size`（单次条数）、`fofa_enable/fofa_key/fofa_base_url`、
`quake_enable/quake_key/quake_base_url`、`shodan_enable/shodan_key/shodan_base_url`、
`zerozone_enable/zerozone_key_id/zerozone_base_url`、`zoomeye_enable/zoomeye_key/zoomeye_base_url`。
各引擎的 `*_base_url` 均支持界面配置，留空使用官方端点（见上表），可用于切换镜像或内网代理地址。

各引擎鉴权与查询语法（按目标自动构造）：

| 引擎 | 端点 | 鉴权 | IP 查询 | 域名查询 |
|---|---|---|---|---|
| FOFA | GET fofa.info/api/v1/search/all | key 参数 | `ip="x.x.x.x"` | `domain="x.com"` |
| Quake | POST quake.360.cn/api/v3/search/quake_service | X-QuakeToken | `ip:"x.x.x.x"` | `domain:"x.com"` |
| Shodan | GET api.shodan.io/shodan/host/search | key 参数 | `ip:x.x.x.x` | `hostname:x.com` |
| 0.zone | POST 0.zone/api/data/ | zone_key_id | `ip=x.x.x.x` | `url==x.com` |
| ZoomEye | POST api.zoomeye.org/v2/search | API-KEY 头 | `ip="x.x.x.x"` | `domain="x.com"` |

测绘出站流量统一走全局代理（`/system/proxy`）。

## 漏洞规则库（nuclei / xray / afrog PoC）

支持导入三种主流 YAML PoC 格式并统一执行（自动识别格式，非破坏性 HTTP 检测）：
nuclei（http + matchers）、xray（rules + CEL 表达式）、afrog（id/info + set 变量 + CEL 表达式）。
表达式/匹配器超出引擎支持子集的规则仍会入库但标记为不可执行。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /vuln-rules/import | `{path}` 服务器目录递归导入 .yml/.yaml（admin） |
| GET | /vuln-rules?source=&severity=&enabled=&supported=&q=&limit= | 规则列表 |
| GET | /vuln-rules/stats | 统计（总数/可执行/启用/按来源与等级） |
| GET | /vuln-rules/{id} | 规则详情（含原始 YAML） |
| POST | /vuln-rules/{id}/toggle | 启用/停用 `{enabled}` |
| DELETE | /vuln-rules/{id} | 删除规则 |
| POST | /vuln-rules/{id}/test | `{target}` 单规则对目标 URL 试探 |
| GET/PUT | /vuln-rules/settings | 扫描执行设置 `{enabled_in_scan, max_per_target}` |
| GET | /vuln-rules/sources | 模板源配置与更新状态（源列表/镜像/自动更新/进行中日志） |
| PUT | /vuln-rules/sources | 保存模板源配置 `{sources:[{url,enabled}], mirror, auto_daily}` |
| POST | /vuln-rules/sources/update | 触发后台更新（clone/pull + 导入，409=已有任务运行） |
| GET | /vuln-rules/watcher | POC 目录监控状态（启用/间隔/监控文件数/最近扫描结果） |
| PUT | /vuln-rules/watcher | 监控设置 `{enabled, interval_sec}`（5-3600s，热生效） |
| GET | /poc-files?path= | 浏览 POC 文件仓库（data/poc） |
| POST | /poc-files/mkdir | `{path}` 创建文件夹（支持多级） |
| POST | /poc-files/save | `{path, content}` 保存 .yml/.yaml（先校验规则格式） |
| DELETE | /poc-files?path= | 删除文件/目录（递归） |
| POST | /poc-files/import | `{path}` 将子目录导入规则库 |

启用后（默认关闭），**深度模式**任务对每个 Web 资产按严重度优先执行限量的启用规则，
命中即写入漏洞结果（组件标注 `规则库(来源)`）。

## 系统

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /system/plugins | 已注册插件列表 |
| GET | /system/logs | 操作审计日志（admin/auditor） |
| GET | /health | 健康检查 |
