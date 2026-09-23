package netproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestConfigureValidation(t *testing.T) {
	defer Configure(Proxy{}) // 恢复直连

	if err := Configure(Proxy{Enable: true, Type: "vmess", Host: "1.2.3.4", Port: 1080}); err == nil {
		t.Fatal("不支持的类型应报错")
	}
	if err := Configure(Proxy{Enable: true, Type: "http", Host: "", Port: 8080}); err == nil {
		t.Fatal("缺少 host 应报错")
	}
	if err := Configure(Proxy{Enable: true, Type: "socks5", Host: "127.0.0.1", Port: 1080, Username: "u", Password: "p"}); err != nil {
		t.Fatalf("合法配置不应报错: %v", err)
	}
	if !Enabled() {
		t.Fatal("应处于启用状态")
	}
	if got := Describe(); got != "socks5://127.0.0.1:1080 (auth)" {
		t.Fatalf("Describe = %s", got)
	}
	if err := Configure(Proxy{Enable: false}); err != nil || Enabled() {
		t.Fatal("禁用后应直连")
	}
}

// 起一个要求 Basic 认证的 HTTP CONNECT 代理，验证 DialTimeout 全链路
func TestDirectTransportIgnoresProxy(t *testing.T) {
	defer Configure(Proxy{})
	Configure(Proxy{Enable: true, Type: "http", Host: "10.9.9.9", Port: 1})

	dt := NewDirectTransport()
	req, _ := http.NewRequest("GET", "http://target.example/", nil)
	if dt.Proxy != nil {
		if u, err := dt.Proxy(req); u != nil || err != nil {
			t.Fatalf("直连 Transport 不应配置代理: %v %v", u, err)
		}
		t.Fatal("直连 Transport 的 Proxy 应为 nil")
	}

	pt := NewTransport()
	if u, err := pt.Proxy(req); u == nil {
		t.Fatalf("代理感知 Transport 应走代理: %v %v", u, err)
	}
}

func TestHTTPConnectProxyWithAuth(t *testing.T) {
	const user, pass = "proxyuser", "proxypass"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("无法监听本地端口")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
				if req.Header.Get("Proxy-Authorization") != want {
					c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					return
				}
				if req.Method != http.MethodConnect {
					c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}
				// CONNECT 目标回写给自己监听的地址，验证隧道内容
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				io.Copy(c, c) // echo
			}(c)
		}
	}()

	if err := Configure(Proxy{
		Enable: true, Type: "http", Host: "127.0.0.1",
		Port: ln.Addr().(*net.TCPAddr).Port, Username: user, Password: pass,
	}); err != nil {
		t.Fatal(err)
	}
	defer Configure(Proxy{})

	conn, err := DialTimeout("tcp", "example.com:80", 3*time.Second)
	if err != nil {
		t.Fatalf("经代理拨号失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("隧道写入失败: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("隧道回读失败: %v %q", err, buf)
	}
}

func TestHTTPClientProxyURL(t *testing.T) {
	defer Configure(Proxy{})
	Configure(Proxy{Enable: true, Type: "http", Host: "10.0.0.1", Port: 7890, Username: "u", Password: "p"})
	tr := NewTransport()
	req, _ := http.NewRequest("GET", "http://target.example/", nil)
	proxyURL, err := tr.Proxy(req)
	if err != nil || proxyURL == nil {
		t.Fatalf("未生效代理: %v", err)
	}
	if proxyURL.String() != "http://u:p@10.0.0.1:7890" {
		t.Fatalf("proxy url = %s", proxyURL.String())
	}
	if _, ok := proxyURL.User.Password(); !ok {
		t.Fatal("代理认证信息丢失")
	}
}

func TestProxyURLNoAuth(t *testing.T) {
	defer Configure(Proxy{})
	Configure(Proxy{Enable: true, Type: "socks5", Host: "10.0.0.2", Port: 1080})
	u := proxyURL()
	if u.String() != "socks5://10.0.0.2:1080" || u.User != nil {
		t.Fatalf("u = %s", (&url.URL{}).String())
	}
	if auth() != nil {
		t.Fatal("无认证时 auth 应为 nil")
	}
}

// TestDirectDialTimeout 直连拨号在代理启用时也应直连成功（本地回环监听验证）
func TestDirectDialTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listen unavailable")
	}
	defer ln.Close()
	// 启用一个必然不可达的代理配置，验证 DirectDialTimeout 不受影响
	if err := Configure(Proxy{Enable: true, Type: "socks5", Host: "127.0.0.1", Port: 1}); err != nil {
		t.Fatal(err)
	}
	defer Configure(Proxy{Enable: false})
	conn, err := DirectDialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("直连拨号失败: %v", err)
	}
	conn.Close()
	// 对照：代理感知拨号此时应失败（代理不可达）
	if c, err := DialTimeout("tcp", ln.Addr().String(), 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("代理不可达时 DialTimeout 不应成功")
	}
}
