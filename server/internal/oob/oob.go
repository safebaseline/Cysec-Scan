// Package oob OOB(Out-of-Band) 反连检测引擎。
// 学习 projectdiscovery/interactsh 的设计：单一会话注册，生成多个唯一子域，
// 目标触发 DNS/HTTP 请求后轮询获取交互记录。
package oob

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction OOB 交互记录
type Interaction struct {
	Protocol  string    `json:"protocol"`
	Remote    string    `json:"remote"`
	Host      string    `json:"host"`
	URL       string    `json:"url"`
	RawReq    string    `json:"raw_request"`
	Timestamp time.Time `json:"timestamp"`
}

// Server OOB 会话（学习 interactsh-client：单注册、多子域复用）
type Server struct {
	ServerURL     string
	CorrelationID string
	SecretKey     string

	urlPrefix string

	mu         sync.Mutex
	messages   []Interaction
	registered bool
	httpClient *http.Client
}

var defaultServers = []string{"https://oast.pro", "https://oast.live", "https://oast.site", "https://oast.online"}

// 全局共享会话（避免每条规则都注册新会话，学习 interactsh 单会话模式）
var (
	globalSrv *Server
	globalMu  sync.RWMutex
)

// New 获取或创建全局 OOB 会话
func New() (*Server, error) {
	globalMu.RLock()
	if globalSrv != nil && globalSrv.registered {
		s := globalSrv
		globalMu.RUnlock()
		return s, nil
	}
	globalMu.RUnlock()

	globalMu.Lock()
	defer globalMu.Unlock()
	if globalSrv != nil && globalSrv.registered {
		return globalSrv, nil
	}

	s := &Server{
		CorrelationID: randomHex(13),
		SecretKey:     randomHex(13),
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}
	for _, srv := range defaultServers {
		s.ServerURL = srv
		if err := s.register(); err == nil {
			globalSrv = s
			return s, nil
		}
	}
	return nil, fmt.Errorf("所有 OOB 服务注册失败")
}

// register 向公共 OOB 服务注册（仅一次）
func (s *Server) register() error {
	url := fmt.Sprintf("%s/register?id=%s&secret=%s", s.ServerURL, s.CorrelationID, s.SecretKey)
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		DNSName string `json:"dns_name"`
		FQDN    string `json:"fqdn"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if result.FQDN != "" {
		s.urlPrefix = result.FQDN
	} else if result.DNSName != "" {
		s.urlPrefix = result.DNSName
	} else {
		s.urlPrefix = fmt.Sprintf("%s.%s", randomHex(10), s.CorrelationID)
	}
	s.registered = true
	return nil
}

// NewURL 生成一个新的唯一回调 URL（学习 interactsh：同会话多子域）
func (s *Server) NewURL() string {
	return fmt.Sprintf("%s.%s", randomHex(10), s.urlPrefix)
}

// Poll 轮询 OOB 服务获取交互记录
func (s *Server) Poll() ([]Interaction, error) {
	if !s.registered {
		return nil, fmt.Errorf("未注册")
	}
	url := fmt.Sprintf("%s/poll?id=%s&secret=%s", s.ServerURL, s.CorrelationID, s.SecretKey)
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Data []struct {
			Protocol string `json:"protocol"`
			Remote   string `json:"remote_address"`
			Host     string `json:"full-id"`
			RawReq   string `json:"raw_request"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	out := []Interaction{}
	for _, d := range result.Data {
		out = append(out, Interaction{
			Protocol: d.Protocol, Remote: d.Remote, Host: d.Host, RawReq: d.RawReq,
			Timestamp: time.Now(),
		})
	}
	s.mu.Lock()
	s.messages = append(s.messages, out...)
	s.mu.Unlock()
	return out, nil
}

// Interactions 获取累计的交互记录
func (s *Server) Interactions() []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Interaction, len(s.messages))
	copy(out, s.messages)
	return out
}

// WaitForCallback 带超时等待指定子域的回调（学习 interactsh-client 的轮询策略：
// 立即查一次 → 1秒间隔轮询 → 超时返回）
func (s *Server) WaitForCallback(subdomain string, timeout time.Duration) []Interaction {
	deadline := time.Now().Add(timeout)
	s.Poll()
	if s.HasInteractionsFor(subdomain) {
		return s.InteractionsFor(subdomain)
	}
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		s.Poll()
		if s.HasInteractionsFor(subdomain) {
			return s.InteractionsFor(subdomain)
		}
	}
	return nil
}

// InteractionsFor 获取指定子域的交互记录
func (s *Server) InteractionsFor(subdomain string) []Interaction {
	out := []Interaction{}
	for _, m := range s.Interactions() {
		if strings.Contains(m.Host, subdomain) || strings.Contains(m.RawReq, subdomain) {
			out = append(out, m)
		}
	}
	return out
}

// HasInteractionsFor 检查指定子域是否有交互记录
func (s *Server) HasInteractionsFor(subdomain string) bool {
	return len(s.InteractionsFor(subdomain)) > 0
}

// HasProtocol 检查是否有指定协议的交互
func (s *Server) HasProtocol(protocol string) bool {
	for _, m := range s.Interactions() {
		if strings.EqualFold(m.Protocol, protocol) {
			return true
		}
	}
	return false
}

// HasContains 检查交互记录中是否包含指定内容
func (s *Server) HasContains(substr string) bool {
	for _, m := range s.Interactions() {
		if strings.Contains(strings.ToLower(m.RawReq), strings.ToLower(substr)) ||
			strings.Contains(strings.ToLower(m.Host), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// ---- 本地回调监听 ----

// LocalListener 本地 HTTP 回调监听器
type LocalListener struct {
	Port     int
	Tokens   map[string]bool
	Interact chan Interaction
	mu       sync.Mutex
	listener net.Listener
}

// StartLocal 在指定端口启动本地 HTTP 回调监听
func StartLocal(port int) (*LocalListener, error) {
	l := &LocalListener{
		Port:     port,
		Tokens:   make(map[string]bool),
		Interact: make(chan Interaction, 100),
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	l.listener = ln
	go l.serve()
	return l, nil
}

func (l *LocalListener) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), ".", 2)[0]
		l.mu.Lock()
		_, known := l.Tokens[token]
		l.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		inter := Interaction{
			Protocol: "http", Remote: r.RemoteAddr, Host: r.Host, URL: r.URL.String(),
			RawReq:    fmt.Sprintf("%s %s %s\nHost: %s\n\n%s", r.Method, r.URL.Path, r.Proto, r.Host, string(body)),
			Timestamp: time.Now(),
		}
		if known {
			select {
			case l.Interact <- inter:
			default:
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	http.Serve(l.listener, mux)
}

// NewToken 生成新的回调 token 并注册
func (l *LocalListener) NewToken() string {
	t := randomHex(10)
	l.mu.Lock()
	l.Tokens[t] = true
	l.mu.Unlock()
	return t
}

// Collect 收集交互记录（非阻塞）
func (l *LocalListener) Collect() []Interaction {
	out := []Interaction{}
	for {
		select {
		case i := <-l.Interact:
			out = append(out, i)
		default:
			return out
		}
	}
}

// Stop 停止监听
func (l *LocalListener) Stop() {
	if l.listener != nil {
		l.listener.Close()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
