// Package netproxy 全局出站代理层：扫描出站流量统一经过此处分流。
// 支持 http（含 CONNECT 隧道）与 socks5 代理，均支持用户名/密码认证。
//
// 流量分流策略：Web 资产探测与漏洞扫描引擎（HTTP 层）走全局代理；
// TCP 层扫描（存活探测 / 端口扫描 / 服务识别）与空间测绘等数据源走直连——
// SOCKS/HTTP 代理对任意目标通常直接返回连接成功，端口开放判定会全面虚高。
package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Proxy 全局出站代理配置（http / socks5，支持用户名密码）。
// 定义在 netproxy（叶子包）以避免与 config 循环依赖；Proxy 为其别名。
type Proxy struct {
	Enable   bool   `yaml:"enable" json:"enable"`
	Type     string `yaml:"type" json:"type"` // http / socks5
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

var (
	mu      sync.RWMutex
	current = Proxy{Type: ""} // 默认直连
)

// Configure 设置全局代理配置（运行时可通过 API 热更新，扫描流量立即走新配置）
func Configure(p Proxy) error {
	if p.Enable && p.Type != "" && p.Type != "none" {
		if p.Type != "http" && p.Type != "https" && p.Type != "socks5" && p.Type != "socks5h" {
			return fmt.Errorf("不支持的代理类型: %s（支持 http / socks5）", p.Type)
		}
		if p.Host == "" || p.Port <= 0 {
			return fmt.Errorf("代理已启用但 host/port 未配置")
		}
	}
	mu.Lock()
	current = p
	mu.Unlock()
	return nil
}

// Current 返回当前生效的代理配置
func Current() Proxy {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Enabled 当前是否启用代理
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return current.Enable && current.Type != "" && current.Type != "none"
}

// ProxyAddr 代理服务器地址 host:port
func ProxyAddr() string {
	mu.RLock()
	defer mu.RUnlock()
	return net.JoinHostPort(current.Host, fmt.Sprint(current.Port))
}

func auth() *proxy.Auth {
	mu.RLock()
	defer mu.RUnlock()
	if current.Username == "" && current.Password == "" {
		return nil
	}
	return &proxy.Auth{User: current.Username, Password: current.Password}
}

func proxyURL() *url.URL {
	mu.RLock()
	defer mu.RUnlock()
	u := &url.URL{
		Scheme: current.Type,
		Host:   net.JoinHostPort(current.Host, fmt.Sprint(current.Port)),
	}
	if current.Username != "" || current.Password != "" {
		u.User = url.UserPassword(current.Username, current.Password)
	}
	return u
}

// Test 经当前代理配置对目标发起一次 TCP 连通性测试，返回时延
func Test(target string, timeout time.Duration) (int64, error) {
	if target == "" {
		target = "www.baidu.com:80"
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			target = net.JoinHostPort(u.Hostname(), port)
		}
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	start := time.Now()
	conn, err := DialTimeout("tcp", target, timeout)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// DialTimeout 代理感知的 TCP 拨号：socks5 走 x/net/proxy，http 走 CONNECT 隧道，未启用直连。
// 供 Web 层探测与漏洞扫描引擎使用；TCP 层扫描（存活/端口/服务识别）应使用 DirectDialTimeout。
func DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	p := Current()
	if !p.Enable || p.Type == "" || p.Type == "none" {
		d := &net.Dialer{Timeout: timeout}
		return d.DialContext(context.Background(), network, addr)
	}
	return dialVia(p, network, addr, timeout)
}

// DirectDialTimeout 强制直连的 TCP 拨号（忽略全局代理）：端口扫描/存活探测/服务识别专用，
// 避免代理层对任意目标返回连接成功导致开放端口全面虚高
func DirectDialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(context.Background(), network, addr)
}

func authOf(p Proxy) *proxy.Auth {
	if p.Username == "" && p.Password == "" {
		return nil
	}
	return &proxy.Auth{User: p.Username, Password: p.Password}
}

func addrOf(p Proxy) string {
	return net.JoinHostPort(p.Host, fmt.Sprint(p.Port))
}

// httpConnect 通过 HTTP 代理建立 CONNECT 隧道（支持 Basic 认证）
func httpConnect(p Proxy, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addrOf(p), timeout)
	if err != nil {
		return nil, fmt.Errorf("连接代理失败: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if p.Username != "" || p.Password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("代理 CONNECT 失败: HTTP %d", resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// TLSDial 代理感知的 TLS 拨号
func TLSDial(addr string, timeout time.Duration, tlsCfg *tls.Config) (*tls.Conn, error) {
	raw, err := DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr == nil {
		tlsCfg.ServerName = host
	}
	tlsConn := tls.Client(raw, tlsCfg)
	raw.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return tlsConn, nil
}

// NewTransport 代理感知的 http.Transport（HTTP/HTTPS 请求统一出口）
func NewTransport() *http.Transport {
	tr := &http.Transport{
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	p := Current()
	if p.Enable && p.Type != "" && p.Type != "none" {
		if p.Type == "socks5" || p.Type == "socks5h" {
			dialer, err := proxy.SOCKS5("tcp", addrOf(p), authOf(p), proxy.Direct)
			if err == nil {
				if cd, ok := dialer.(proxy.ContextDialer); ok {
					tr.DialContext = cd.DialContext
				}
			}
		} else {
			u := &url.URL{Scheme: p.Type, Host: addrOf(p)}
			if p.Username != "" || p.Password != "" {
				u.User = url.UserPassword(p.Username, p.Password)
			}
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return tr
}

// NewDirectTransport 直连 Transport：忽略全局代理配置（用于空间测绘等不应走代理的出站）
func NewDirectTransport() *http.Transport {
	return &http.Transport{
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		Proxy:               nil,
	}
}

// NewDirectHTTPClient 直连 HTTP 客户端（不走全局代理）
func NewDirectHTTPClient(timeoutSec int, redirectLimit int) *http.Client {
	if redirectLimit <= 0 {
		redirectLimit = 3
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: NewDirectTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= redirectLimit {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// NewHTTPClient 代理感知的 HTTP 客户端
func NewHTTPClient(timeoutSec int, redirectLimit int) *http.Client {
	if redirectLimit <= 0 {
		redirectLimit = 3
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: NewTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= redirectLimit {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// DescribeOf 描述指定配置（不改变当前状态）
func DescribeOf(p Proxy) string {
	if !p.Enable || p.Type == "" || p.Type == "none" {
		return "direct"
	}
	authMark := ""
	if p.Username != "" {
		authMark = " (auth)"
	}
	return fmt.Sprintf("%s://%s%s", p.Type, addrOf(p), authMark)
}

// Describe 当前代理描述（用于日志/API 展示）
func Describe() string {
	p := Current()
	if !p.Enable || p.Type == "" || p.Type == "none" {
		return "direct"
	}
	authMark := ""
	if p.Username != "" {
		authMark = " (auth)"
	}
	return fmt.Sprintf("%s://%s%s", p.Type, addrOf(p), authMark)
}

// ---------- 全局代理连通性守护 ----------
// 配置了代理（host/port 非空）即周期检测；异常时自动切直连（Enable=false），
// 恢复后自动切回代理（Enable=true）。守护仅由用户主动停用代理或清空配置终止。

var (
	healthMu      sync.RWMutex
	healthOn      bool // 守护开关（用户保存 enable=true 的代理时激活）
	healthLast    string
	healthLastAt  time.Time
	healthLastChk time.Time // 上次检测时刻（置零=立即检测）
	healthRunning bool
)

// HealthActive 守护是否激活
func HealthActive() bool { healthMu.RLock(); defer healthMu.RUnlock(); return healthOn }

// SetHealthActive 设置守护开关（用户保存代理时接线）；激活时立即触发一次检测
func SetHealthActive(on bool) {
	healthMu.Lock()
	healthOn = on
	if on {
		healthLastChk = time.Time{}
	}
	healthMu.Unlock()
}

// HealthState 最近一次检测结果（"ok"/"fail"/"-" 与时间）
func HealthState() (string, time.Time) {
	healthMu.RLock()
	defer healthMu.RUnlock()
	return healthLast, healthLastAt
}

// TestConfiguredDial 忽略 Enable 状态、经已配置的代理对探测目标发起完整连通性测试：
// 与"测试"按钮同口径（真实穿越代理握手+建连），而非仅 TCP 探测代理端口——
// 代理端口可达但无法转发流量的半故障（认证失败/上游断路）也能被守护发现。
func TestConfiguredDial(target string, timeout time.Duration) error {
	p := Current()
	if p.Host == "" || p.Port <= 0 {
		return fmt.Errorf("代理未配置")
	}
	if target == "" {
		target = "www.baidu.com:80"
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			target = net.JoinHostPort(u.Hostname(), port)
		}
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	conn, err := dialVia(p, "tcp", target, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// dialVia 按给定代理参数拨号（不读全局 Enable，守护在自动切直连后仍能持续检测代理）
func dialVia(p Proxy, network, addr string, timeout time.Duration) (net.Conn, error) {
	switch p.Type {
	case "socks5", "socks5h":
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(p.Host, fmt.Sprint(p.Port)), authOf(p), &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return cd.DialContext(ctx, network, addr)
		}
		return dialer.Dial(network, addr)
	case "http", "https":
		return httpConnect(p, addr, timeout)
	}
	return nil, fmt.Errorf("未知代理类型 %s", p.Type)
}

// healthApply 应用检测结果：状态翻转时切换 Enable 并回调（持久化+日志由调用方处理）
func healthApply(ok bool, apply func(enable bool)) {
	healthMu.Lock()
	defer healthMu.Unlock()
	now := time.Now()
	state := "fail"
	if ok {
		state = "ok"
	}
	if state != healthLast && apply != nil {
		apply(ok)
	}
	healthLast, healthLastAt = state, now
}

// StartHealthWatch 启动连通性守护循环（幂等；间隔由 loadInterval 回调即时读取）
func StartHealthWatch(loadInterval func() int, apply func(enable bool)) {
	healthMu.Lock()
	if healthRunning {
		healthMu.Unlock()
		return
	}
	healthRunning = true
	healthMu.Unlock()
	go func() {
		for {
			// 短步进轮询：间隔修改 2 秒内生效；激活（或重新激活）后立即首检
			time.Sleep(2 * time.Second)
			interval := loadInterval()
			if interval < 10 {
				interval = 10
			}
			healthMu.Lock()
			due := healthOn && time.Since(healthLastChk) >= time.Duration(interval)*time.Second
			if due {
				healthLastChk = time.Now()
			}
			healthMu.Unlock()
			if !due {
				continue
			}
			p := Current()
			if p.Host == "" || p.Port <= 0 {
				continue // 未配置代理：不检测也不干预
			}
			healthApply(TestConfiguredDial(healthProbeTarget(), 5*time.Second) == nil, apply)
		}
	}()
}

// DescribeHealth 守护状态摘要（设置页展示）
func DescribeHealth() map[string]any {
	last, at := HealthState()
	return map[string]any{
		"active": HealthActive(), "last": last,
		"last_at": at.Format("2006-01-02 15:04:05"),
	}
}

// healthProbeTarget 守护探测目标（设置键 proxy_health_target，默认 www.baidu.com:80）
var healthTargetMu sync.RWMutex
var healthTarget = "www.baidu.com:80"

// SetHealthProbeTarget 设置守护探测目标
func SetHealthProbeTarget(t string) {
	healthTargetMu.Lock()
	if t = strings.TrimSpace(t); t != "" {
		healthTarget = t
	}
	healthTargetMu.Unlock()
}

func healthProbeTarget() string {
	healthTargetMu.RLock()
	defer healthTargetMu.RUnlock()
	return healthTarget
}

// HealthProbeTarget 返回守护探测目标
func HealthProbeTarget() string { return healthProbeTarget() }
