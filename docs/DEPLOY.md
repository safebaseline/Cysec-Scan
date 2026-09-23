# 部署文档

## 一、直接编译运行（推荐）

依赖：Go ≥ 1.24；如需重新构建前端，还需 Node.js ≥ 20（前端产物已预嵌入，仅改后端时无需 Node）。

```bash
make build          # 构建前端并嵌入，产出 dist/cysec 单一二进制（约 28MB）
./dist/cysec -config configs/config.yaml
```

仅改后端代码时的快速编译：

```bash
cd server && CGO_ENABLED=0 go build -o ../dist/cysec ./cmd/cysec
cd .. && ./dist/cysec -config configs/config.yaml
```

**首次启动自动初始化**：程序启动时检测 `-config` 指定的配置文件与数据库文件——不存在则自动生成（配置生成带注释的默认模板、数据库自动建全部数据表并创建默认管理员），已存在则跳过，日志以「[初始化]」标注。

数据存储在配置指定的 SQLite 文件（默认 `data/cysec.db`，位于运行目录下），自动建表、自动创建默认管理员。日志可重定向：`./dist/cysec -config configs/config.yaml > logs/cysec.log 2>&1 &`

> 若构建环境访问 `proxy.golang.org` 超时，使用镜像：`GOPROXY=https://goproxy.cn,direct`

## 二、Docker 部署（可选）

```bash
cd deploy
docker compose up -d          # 构建并启动，端口 8080
docker compose logs -f
```

数据卷 `cysec-data` 持久化 SQLite 数据库；配置通过 `configs/config.yaml` 挂载。

## 三、配置说明（configs/config.yaml）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| server.host / server.port | 0.0.0.0 / 8080 | 监听地址 |
| database.path | data/cysec.db | SQLite 数据库路径 |
| worker.concurrency | 8 | 全局默认并发 |
| auth.bootstrap_admin_user / pass | admin / admin123 | 首次启动创建的管理员（**部署后请修改**） |
| auth.token_ttl_hours | 72 | 登录 Token 有效期 |
| scan.timeout_seconds | 5 | 单次探测超时 |
| scan.max_targets_per_task | 65536 | 单任务目标上限（防护） |
| scan.max_ports_per_target | 1024 | 端口范围解析上限 |
| scan.top_ports | 常用 28 端口 | 默认扫描端口集合 |
| proxy.enable / type / host / port | false / http | 全局出站代理：`type` 支持 `http`、`socks5` |
| proxy.username / password | 空 | 代理认证（HTTP Basic / SOCKS5 用户名密码），留空为匿名代理 |

### 全局代理说明

启用后扫描出站流量统一经代理出口，包括：TCP 存活探测与端口扫描、Banner 抓取、HTTP/HTTPS Web 探测、深度模式 URL 爬取、TLS 风险检测。**空间测绘引擎（FOFA/Quake/Shodan/0.zone/ZoomEye）的 API 请求始终直连，不走代理。**SOCKS5 支持任意 TCP 隧道；HTTP 代理通过 CONNECT 隧道转发 TCP 流量（需代理放行 CONNECT，仅支持 Basic 认证）。

域名 DNS 解析仍走系统解析器（UDP DNS 不经代理）；如需代理 DNS，可改用 socks5 且由远端解析。启动日志会打印 `出站代理: socks5://host:port (auth)` 便于确认生效。

```yaml
proxy:
  enable: true
  type: socks5
  host: 192.168.1.100
  port: 1080
  username: scan
  password: secret
```

### 空间测绘数据源

`mapping:` 配置段（或 系统设置→空间测绘 界面）管理 FOFA / Quake / Shodan / 0.zone / ZoomEye 五个测绘引擎的
开关与密钥。密钥建议在 Web 界面填写（存于本地数据库，不落配置文件）；`enabled: true` 且某引擎 `*_enable: true`
并配置密钥后，标准/深度扫描任务会在端口扫描前自动调用该引擎扩展资产，单个引擎失败仅记录告警不影响任务。
各引擎调用消耗账户额度，请按需设置 `size`（单次查询条数，上限 1000）。

## 四、环境变量 / Go 代理

若构建环境访问 `proxy.golang.org` 超时，可使用镜像：

```bash
GOPROXY=https://goproxy.cn,direct go build ./cmd/cysec
```

## 五、安全建议

1. 首次登录后修改默认管理员密码（更新配置中的 bootstrap 值不影响已建用户，需直接删除数据库或用 SQL 更新）。
2. 平台仅对任务中声明的授权目标发起探测；请确保目标在授权范围内。
3. 建议将服务置于反向代理（TLS）之后对外提供。
4. 定期备份 `data/cysec.db`。

## 六、验收自检清单（对应需求文档 第四十一节）

1. ✅ 创建项目并导入授权 IP / 域名 / URL
2. ✅ IP 进入空间测绘流程（端口→服务→URL 扩展）
3. ✅ 测绘结果归一为统一资产表
4. ✅ IP/域名/端口/服务/URL 关联（`GET /api/assets/ip/{ip}`）
5. ✅ 自动识别 Web 资产
6. ✅ 基础 Web 技术指纹
7. ✅ 任务创建/暂停/恢复/终止
8. ✅ 风险检测结果统一保存
9. ✅ 资产与漏洞去重
10. ✅ IP → 关联 URL 查看；URL → IP/端口/技术栈/风险
11. ✅ CSV / JSON 导出
12. ✅ 超时、并发、权限控制
13. ✅ 扫描限定授权目标范围
14. ✅ 核心 discovering/mapping/scanning 插件化
