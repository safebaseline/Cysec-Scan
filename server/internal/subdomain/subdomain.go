// Package subdomain 子域名爆破：学习 boy-hack/ksubdomain 的核心思路——
// 高并发 DNS 查询 + 子域字典 + 泛解析(wildcard)检测过滤 + 多解析器轮询。
package subdomain

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// Result 爆破结果
type Result struct {
	Subdomain string
	IP        string
	CNAME     string
}

// Options 爆描选项
type Options struct {
	Workers    int      // 并发
	Resolvers  []string // DNS 服务器（空则用系统）
	Wordlist   []string // 子域字典
	TimeoutSec int      // 单次查询超时
}

// DefaultResolvers 内置公共 DNS（阿里/Google/114）
var DefaultResolvers = []string{"223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8"}

// lookupFunc 可注入的解析函数（单测用）
type lookupFunc func(host string) (ips []string, cname string, err error)

// Brute 对域名执行子域名爆破：字典 + 泛解析过滤，返回去重后的有效子域
func Brute(domain string, opts Options) []Result {
	if opts.Workers <= 0 {
		opts.Workers = 500
	}
	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = 4
	}
	lookup := realLookup(opts)
	return brute(domain, opts.Wordlist, opts.Workers, lookup)
}

func brute(domain string, wordlist []string, workers int, lookup lookupFunc) []Result {
	domain = strings.Trim(strings.ToLower(domain), ".")
	if domain == "" || len(wordlist) == 0 {
		return nil
	}

	// 泛解析检测（ksubdomain 同款思路）：随机不存在子域若能解析 => 泛解析
	wildcardIPs := map[string]bool{}
	for i := 0; i < 2; i++ {
		r := randomLabel()
		if ips, _, err := lookup(r + "." + domain); err == nil {
			for _, ip := range ips {
				wildcardIPs[ip] = true
			}
		}
	}

	seen := map[string]bool{}
	words := make(chan string)
	results := make(chan Result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range words {
				host := strings.ToLower(w) + "." + domain
				ips, cname, err := lookup(host)
				if err != nil || len(ips) == 0 {
					continue
				}
				// 过滤无效 IP（0.x 垃圾记录、回环、组播等）
				valid := make([]string, 0, len(ips))
				for _, ip := range ips {
					if isUsableIP(ip) {
						valid = append(valid, ip)
					}
				}
				if len(valid) == 0 {
					continue
				}
				ips = valid
				// 泛解析过滤：全部 IP 都命中泛解析 IP 集的子域视为无效
				if len(wildcardIPs) > 0 {
					allWC := true
					for _, ip := range ips {
						if !wildcardIPs[ip] {
							allWC = false
							break
						}
					}
					if allWC {
						continue
					}
				}
				// 取首个非泛解析 IP
				ip := ""
				for _, cand := range ips {
					if !wildcardIPs[cand] {
						ip = cand
						break
					}
				}
				if ip == "" {
					ip = ips[0]
				}
				cname = strings.TrimSuffix(strings.ToLower(cname), ".")
				results <- Result{Subdomain: host, IP: ip, CNAME: cname}
			}
		}()
	}
	go func() {
		for _, w := range wordlist {
			words <- w
		}
		close(words)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := []Result{}
	for r := range results {
		if !seen[r.Subdomain] {
			seen[r.Subdomain] = true
			out = append(out, r)
		}
	}
	return out
}

// realLookup 构造真实 DNS 查询（自定义解析器轮询 + 超时）
func realLookup(opts Options) lookupFunc {
	resolvers := opts.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	var idx int32
	var mu sync.Mutex
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			r := resolvers[int(idx)%len(resolvers)]
			idx++
			mu.Unlock()
			d := net.Dialer{Timeout: time.Duration(opts.TimeoutSec) * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(r, "53"))
		},
	}
	return func(host string) ([]string, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec)*time.Second)
		defer cancel()
		addrs, err := res.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, "", err
		}
		cname := ""
		if cn, err := res.LookupCNAME(ctx, host); err == nil {
			cname = cn
		}
		return addrs, cname, nil
	}
}

// isUsableIP 过滤 DNS 污染/垃圾记录（0.0.0.1 等）与本地保留地址
func isUsableIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return false // 0.x.x.x
	}
	return true
}

func randomLabel() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
