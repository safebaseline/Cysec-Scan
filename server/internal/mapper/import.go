package mapper

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"cysec/internal/model"
	"cysec/internal/netproxy"
	"cysec/internal/store"
	"cysec/plugins/builtin"
)

// Import 将测绘记录归一化写入资产库（自动去重），返回新增统计。
// 这是「IP 进入空间测绘后自动扩展出 Domain/Port/Service/URL/Web」的核心落库逻辑。
func Import(st *store.Store, projectID, taskID int64, recs []Record) (newIPs, newDomains, newPorts, newWebs int) {
	for _, r := range recs {
		if r.IP == "" && r.URL == "" && r.Domain == "" {
			continue
		}
		// IP 资产
		if r.IP != "" {
			isNew, err := st.UpsertIP(model.AssetIP{
				ProjectID: projectID, IP: r.IP,
				Network: networkOf(r.IP), Source: r.Provider,
			})
			if err == nil && isNew {
				newIPs++
				st.AddChange(model.AssetChange{ProjectID: projectID, TaskID: taskID, AssetType: "ip", Asset: r.IP, Change: "add", Detail: "测绘发现(" + r.Provider + ")"})
			}
		}
		// 域名资产（含解析 IP 关联）
		if r.Domain != "" {
			isNew, err := st.UpsertDomain(model.AssetDomain{
				ProjectID: projectID, Domain: r.Domain, IP: r.IP, Source: r.Provider,
			})
			if err == nil && isNew {
				newDomains++
				st.AddChange(model.AssetChange{ProjectID: projectID, TaskID: taskID, AssetType: "domain", Asset: r.Domain, Change: "add", Detail: "测绘发现(" + r.Provider + ")"})
			}
		}
		// 端口资产（含服务识别与分拣）
		if r.IP != "" && r.Port > 0 {
			service := r.Service
			if service == "" {
				service = builtin.CategoryOf(r.Port, "")
			}
			isNew, err := st.UpsertPort(model.AssetPort{
				ProjectID: projectID, IP: r.IP, Port: r.Port,
				Protocol: orDefault(r.Protocol, "tcp"), State: "open",
				Service: service, Version: "", Banner: r.Banner(),
				Category: builtin.CategoryOf(r.Port, service), Source: r.Provider,
			})
			if err == nil && isNew {
				newPorts++
				st.AddChange(model.AssetChange{ProjectID: projectID, TaskID: taskID, AssetType: "port",
					Asset: fmt.Sprintf("%s:%d", r.IP, r.Port), Change: "add", Detail: service + " (" + r.Provider + ")"})
			}
		}
		// Web 资产 + URL 资产池
		if r.URL != "" {
			r.URL = NormalizeURL(r.URL, r.Port)
			webID, isNew, err := st.UpsertWeb(model.AssetWeb{
				ProjectID: projectID, URL: r.URL, IP: r.IP, Domain: r.Domain, Port: r.Port,
				Protocol: schemeOf(r.URL), Title: r.Title, Server: r.Server,
				Tech: r.Fingerprint, Source: r.Provider,
			})
			if err == nil {
				if isNew {
					newWebs++
					st.AddChange(model.AssetChange{ProjectID: projectID, TaskID: taskID, AssetType: "web", Asset: r.URL, Change: "add", Detail: r.Title})
				}
				st.UpsertURL(model.AssetURL{ProjectID: projectID, WebID: webID, URL: r.URL, Source: r.Provider})
			}
		}
	}
	return
}

// Banner 生成简短 Banner 摘要（便于溯源）
func (r Record) Banner() string {
	parts := []string{}
	if r.Title != "" {
		parts = append(parts, "title: "+r.Title)
	}
	if r.Fingerprint != "" {
		parts = append(parts, "fp: "+r.Fingerprint)
	}
	return strings.Join(parts, " | ")
}

// NormalizeURL 保证 URL 以 http:// 或 https:// 开头。
// 端口为 443/8443/4433 直接判定 https；非标准端口用 TLS 握手探测（握手成功=https，失败=http），
// 探测超时 3 秒，走全局代理。
func NormalizeURL(u string, port int) string {
	u = strings.TrimSpace(u)
	if u == "" || strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	scheme := "http"
	if port == 443 || port == 8443 || port == 4433 || probeTLS(u, port) {
		scheme = "https"
	}
	return scheme + "://" + u
}

// probeTLS 对 host:port 做一次 TLS 握手，成功返回 true
func probeTLS(host string, port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	h := u2host(host)
	if i := strings.LastIndex(h, ":"); i > 0 {
		// URL 自带端口且 host 部分是 IP 时拆掉（避免 host:port:port）
		if net.ParseIP(h[:i]) != nil {
			h = h[:i]
		}
	}
	if h == "" {
		return false
	}
	addr := net.JoinHostPort(h, fmt.Sprint(port))
	conn, err := netproxy.TLSDial(addr, 3*time.Second, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func u2host(u string) string {
	// 去掉可能存在的 scheme 前缀与路径
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.Index(u, "/"); i > 0 {
		u = u[:i]
	}
	return u
}

func networkOf(ip string) string {
	if n := net.ParseIP(ip); n != nil && (n.IsLoopback() || n.IsPrivate() || n.IsLinkLocalUnicast()) {
		return "private"
	}
	return "public"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func schemeOf(u string) string {
	if strings.HasPrefix(u, "https") {
		return "https"
	}
	return "http"
}
