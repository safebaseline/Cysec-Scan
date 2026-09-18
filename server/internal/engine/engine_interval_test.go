package engine

import (
	"testing"
	"time"
)

func TestParseInterval(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"8h", 8 * time.Hour},
		{"24h", 24 * time.Hour},
		{"1w", 7 * 24 * time.Hour},
		{"6h", 6 * time.Hour},
		{"6", 6 * time.Hour},      // 纯数字按小时
		{" 12H ", 12 * time.Hour}, // 容忍空白与大小写
		{"1", time.Hour},
		{"8760h", 8760 * time.Hour},
		{"0", 0},
		{"0h", 0},
		{"-5h", 0},
		{"8761h", 0},
		{"1.5h", 0}, // 按小时设计：仅整数
		{"30m", 0},  // 不支持分钟
		{"2d", 0},   // 不支持天
		{"abc", 0},
		{"h", 0},
	}
	for _, c := range cases {
		if got := ParseInterval(c.in); got != c.want {
			t.Errorf("ParseInterval(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
