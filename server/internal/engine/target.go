// Package engine 扫描任务调度与流水线执行。
package engine

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// TargetType 目标类型
const (
	TargetIP     = "ip"
	TargetDomain = "domain"
	TargetURL    = "url"
)

// ParseTargets 解析目标文本（换行/逗号分隔），支持 IP、CIDR、IP 段、域名、URL。
// 所有扫描严格限定在这些授权目标解析出的范围内（需求文档 三十五节）。
func ParseTargets(text, targetType string, maxTargets int) ([]string, []string, []string, error) {
	ips := []string{}
	domains := []string{}
	urls := []string{}
	count := 0
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == ';' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.Contains(line, "://"): // URL
			u, err := url.Parse(line)
			if err != nil || u.Host == "" {
				continue
			}
			urls = append(urls, strings.TrimRight(line, "/"))
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				ips = appendIfNew(ips, host)
			} else {
				domains = appendIfNew(domains, host)
			}
			count++
		case strings.Contains(line, "/"): // CIDR
			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("无效 CIDR: %s", line)
			}
			expand := expandCIDR(ip, ipnet, maxTargets-count)
			if len(expand) == 0 {
				return nil, nil, nil, fmt.Errorf("CIDR 范围过大: %s", line)
			}
			for _, e := range expand {
				ips = appendIfNew(ips, e)
				count++
			}
		case strings.Contains(line, "-") && net.ParseIP(strings.SplitN(line, "-", 2)[0]) != nil: // IP 段 a.b.c.d-a.b.c.e
			// 前半段必须是合法 IP 才视为 IP 段；否则落到域名分支（域名可含连字符，
			// 如 my-site.com，此前在此被静默丢弃）
			parts := strings.SplitN(line, "-", 2)
			start := net.ParseIP(strings.TrimSpace(parts[0]))
			end := net.ParseIP(strings.TrimSpace(parts[1]))
			if end == nil {
				continue
			}
			n := 0
			for ip := start; ip != nil && compareIP(ip, end) <= 0; ip = nextIP(ip) {
				ips = appendIfNew(ips, ip.String())
				count++
				n++
				if count >= maxTargets || n >= 65536 {
					break
				}
			}
		case net.ParseIP(line) != nil: // 单 IP
			ips = appendIfNew(ips, line)
			count++
		default: // 域名
			if isDomainLike(line) {
				domains = appendIfNew(domains, line)
				count++
			}
		}
		if count >= maxTargets {
			break
		}
	}
	_ = targetType
	return ips, domains, urls, nil
}

func isDomainLike(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	return true
}

func expandCIDR(ip net.IP, ipnet *net.IPNet, limit int) []string {
	if limit <= 0 {
		limit = 1
	}
	ones, bits := ipnet.Mask.Size()
	size := bits - ones
	if size > 20 { // 超过 /12 的 IPv4 范围拒绝
		return nil
	}
	out := []string{}
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		out = append(out, cur.String())
		if len(out) >= limit {
			break
		}
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
		if i == 0 {
			return nil // 溢出
		}
	}
	if ip.To4() != nil && next.To4() == nil {
		return nil
	}
	return next
}

func compareIP(a, b net.IP) int {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		for i := 0; i < 4; i++ {
			if a4[i] != b4[i] {
				if a4[i] < b4[i] {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	return strings.Compare(a.String(), b.String())
}

func appendIfNew(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// ParsePorts 解析端口配置：空=常用端口；"full"=全端口；"80,443"、"1-1000"
func ParsePorts(spec string, topPorts []int, maxPorts int) []int {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" {
		return topPorts
	}
	if spec == "full" || spec == "1-65535" {
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if end-start > maxPorts {
				end = start + maxPorts
			}
			for p := start; p <= end && p <= 65535; p++ {
				if p > 0 && !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return topPorts
	}
	return ports
}

// IsPrivateIP 公网/内网分类
func IsPrivateIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "private"
	}
	return "public"
}

var _ = math.MaxInt32
