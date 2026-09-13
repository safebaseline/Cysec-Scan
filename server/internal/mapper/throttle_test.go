package mapper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.WriteHeader(429)
			w.Write([]byte(`{"error":true,"errmsg":"[45012] 请求速度过快"}`))
			return
		}
		w.Write([]byte(`{"code":0,"message":"ok","data":[{"ip":"1.2.3.4","port":80,"service":{"name":"http"}}]}`))
	}))
	defer srv.Close()

	quake := &quakeProvider{}
	cfg := Config{Enabled: true, QuakeEnable: true, QuakeKey: "k", QuakeBaseURL: srv.URL, Size: 10, IntervalMs: 1}
	recs, err := quake.Query(cfg, "1.1.1.1", false)
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if len(recs) != 1 || recs[0].IP != "1.2.3.4" {
		t.Fatalf("结果: %+v", recs)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("应重试至第3次: %d", calls)
	}
}

func TestRateLimitRetryExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":true,"errmsg":"[45012] 请求速度过快"}`))
	}))
	defer srv.Close()
	quake := &quakeProvider{}
	cfg := Config{Enabled: true, QuakeEnable: true, QuakeKey: "k", QuakeBaseURL: srv.URL, IntervalMs: 1}
	_, err := quake.Query(cfg, "1.1.1.1", false)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("重试耗尽应返回429错误: %v", err)
	}
}

func TestThrottleSpacing(t *testing.T) {
	delete(thLast, "unit-test")
	iv := 80
	start := time.Now()
	throttle("unit-test", iv)
	throttle("unit-test", iv)
	elapsed := time.Since(start)
	if elapsed < time.Duration(iv)*time.Millisecond {
		t.Fatalf("两次调用间隔不足: %v", elapsed)
	}
}

func TestEffectiveInterval(t *testing.T) {
	if effectiveInterval("fofa", Config{}) != providerMinIntervalMs["fofa"] {
		t.Fatal("默认间隔应生效")
	}
	if effectiveInterval("fofa", Config{IntervalMs: 3000}) != 3000 {
		t.Fatal("更大配置间隔应覆盖默认")
	}
	if effectiveInterval("fofa", Config{IntervalMs: 100}) != providerMinIntervalMs["fofa"] {
		t.Fatal("更小配置间隔不降低内置默认")
	}
}
