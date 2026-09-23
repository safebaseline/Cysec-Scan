package auth

import (
	"testing"
	"time"
)

// TestLoginThrottleBlockAndReset 验证失败计数达上限后拦截、成功登录清零
func TestLoginThrottleBlockAndReset(t *testing.T) {
	th := newLoginThrottle(50*time.Millisecond, 3)
	for i := 0; i < 3; i++ {
		if th.blocked("1.2.3.4", "admin") {
			t.Fatalf("第 %d 次失败前不应被拦截", i+1)
		}
		th.recordFailure("1.2.3.4", "admin")
	}
	if !th.blocked("1.2.3.4", "admin") {
		t.Fatal("达到失败上限后应被拦截")
	}
	// 双维度拦截：同账号任意来源（防分布式爆破单账号）、同来源任意账号（防单源喷洒）
	if !th.blocked("5.6.7.8", "admin") {
		t.Fatal("同用户名达到上限时，其他 IP 也应被拦截（账号维度）")
	}
	if !th.blocked("1.2.3.4", "other") {
		t.Fatal("同 IP 达到上限时，其他用户名也应被拦截（来源维度）")
	}
	if th.blocked("5.6.7.8", "other") {
		t.Fatal("无关的 IP 与用户名组合不应被拦截")
	}
	// 成功登录清零
	th.reset("1.2.3.4", "admin")
	if th.blocked("1.2.3.4", "admin") {
		t.Fatal("reset 后不应再拦截")
	}
}

// TestLoginThrottleWindowExpiry 验证窗口滑动后计数过期
func TestLoginThrottleWindowExpiry(t *testing.T) {
	th := newLoginThrottle(30*time.Millisecond, 2)
	th.recordFailure("1.2.3.4", "admin")
	th.recordFailure("1.2.3.4", "admin")
	if !th.blocked("1.2.3.4", "admin") {
		t.Fatal("窗口内达到上限应被拦截")
	}
	time.Sleep(60 * time.Millisecond)
	if th.blocked("1.2.3.4", "admin") {
		t.Fatal("窗口外旧失败应过期，不再拦截")
	}
}
