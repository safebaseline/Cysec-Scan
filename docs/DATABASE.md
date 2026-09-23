# 数据库设计

MVP 使用 SQLite（单文件、零运维），表结构与 PostgreSQL 兼容，后续多 Worker / 多租户阶段可平滑迁移。

## 表清单

| 表 | 用途 | 关键唯一键（去重） |
|---|---|---|
| users | 用户（bcrypt 密码、角色） | username |
| tokens | 登录令牌 | token |
| projects | 项目 | name |
| asset_ips | IP 资产（网络类型/存活/风险评分） | (project_id, ip) |
| asset_domains | 域名资产（CNAME / 解析 IP） | (project_id, domain) |
| asset_ports | 端口资产（服务/版本/Banner/分拣类别） | (project_id, ip, port, protocol) |
| asset_web | Web 资产（状态码/Title/Server/证书/技术栈/Headers） | (project_id, url) |
| asset_urls | URL 资产池（页面/API/静态资源） | (project_id, url) |
| asset_fingerprints | 技术指纹明细 | (project_id, web_url, category, name) |
| vulnerabilities | 漏洞结果 | (project_id, ip, port, url, vuln_id) |
| scan_tasks | 扫描任务（模式/状态/进度/并发/优先级） | — |
| scan_logs | 任务日志 | — |
| asset_changes | 资产变化记录（新增/下线） | — |
| system_logs | 操作审计日志 | — |
| vuln_rules | 漏洞规则库（nuclei/xray/afrog，含可执行模型 JSON） | (source, rule_id) |
| settings | 运行时设置（代理/测绘/规则执行） | key |

## 资产关联模型

```
asset_domains.ip ──→ asset_ips.ip
asset_ports.(ip) ──→ asset_ips.ip
asset_web.ip     ──→ asset_ips.ip
asset_web.url    ──→ asset_urls.web_id / asset_fingerprints.web_url
vulnerabilities.(ip, port, url) ──→ asset_ips / asset_ports / asset_web
```

以 `project_id` 实现项目级数据隔离。

## 漏洞去重指纹

```
Asset(IP) + Port + URL + Vulnerability ID
```

同一位置同一漏洞重复扫描仅刷新 `last_seen`，不重复入库、不重复展示。

## 风险评分（asset_ips.risk_score，0-100）

```
score = Σ(漏洞严重度: critical×25, high×12, medium×5, low×1)
      + min(开放端口,10)×2 + min(Web数,10)×3 + 敏感服务数×8   （上限 100）
```

| 分数 | 等级 |
|---|---|
| 90-100 | 极高 |
| 70-89 | 高 |
| 40-69 | 中 |
| 1-39 | 低 |
| 0 | 无风险 |
