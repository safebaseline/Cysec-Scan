package builtin

import (
	"fmt"
	"net"
	"strings"

	"cysec/internal/plugins"
)

// localMapper 本地空间测绘插件：通过本地端口探测与 Web 识别完成 IP → Domain/Port/Service/URL 的测绘。
// 对接 FOFA / Hunter / Quake / Shodan 等外部数据源时，实现 plugins.SpaceMapper 接口
// （例如返回 API 查询结果），并调用 plugins.RegisterMapper 注册即可，无需修改引擎。
type localMapper struct{}

func (m *localMapper) Name() string { return "local-mapper" }

func (m *localMapper) Map(ip string) []plugins.MappingRecord {
	records := []plugins.MappingRecord{}
	scanner := &connectScanner{}
	ident := &bannerIdentifier{}
	open := scanner.Scan(ip, defaultTopPorts(), 3)
	for _, pr := range open {
		pr = ident.Identify(ip, pr, 3)
		rec := plugins.MappingRecord{
			IP:       ip,
			Port:     pr.Port,
			Protocol: "tcp",
			Service:  pr.Service,
			Source:   m.Name(),
		}
		// Web 服务自动提取 URL 进入 Web 资产池
		if strings.Contains(pr.Service, "HTTP") {
			scheme := "http"
			if pr.Port == 443 || pr.Port == 8443 || strings.Contains(pr.Service, "HTTPS") {
				scheme = "https"
			}
			host := ip
			if rec.Domain != "" {
				host = rec.Domain
			}
			rec.URL = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprint(pr.Port)))
			if wr := ProbeWeb(rec.URL, ip, 5); wr != nil {
				rec.Title = wr.Title
				rec.Fingerprint = wr.Server
			}
		}
		records = append(records, rec)
	}
	return records
}

func defaultTopPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 3306, 3389, 5432, 5900, 6379, 7001, 8080, 8443, 8888, 9200, 11211, 27017}
}
