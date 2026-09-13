package wih

import (
	"io"
	"net/http"

	"cysec/internal/netproxy"
	"cysec/internal/ua"
)

// ScanURL 拉取指定 URL（页面或 JS）内容并执行规则匹配，
// 单目标即时检测入口，对应 WIHscan 的 -u 模式。
func ScanURL(rules []Rule, target string, timeoutSec int) ([]Hit, error) {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	client := netproxy.NewHTTPClient(timeoutSec, 0)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	ua.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	if err != nil {
		return nil, err
	}
	return ScanBody(rules, string(body)), nil
}
