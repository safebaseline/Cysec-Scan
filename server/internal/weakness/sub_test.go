package weakness

import (
	"strings"
	"testing"
)

func TestParseLexicon(t *testing.T) {
	// UTF-8：注释、空行、URL 行、超长行、重复行、单字行
	utf8Body := "赌博\n# 注释\n\n博彩\nwww.example.com\nhttp://a.com/x\n" +
		strings.Repeat("超", 100) + "\n赌博\n日\nOK\n"
	got := ParseLexicon("text/plain; charset=utf-8", utf8Body)
	if len(got) != 3 || got[0] != "赌博" || got[1] != "博彩" || got[2] != "OK" {
		t.Fatalf("UTF-8 解析（单字'日'过滤、双字'OK'保留）: %v", got)
	}

	// GBK 词库归一为 UTF-8 后解析（"彩票" GBK = b2 ca c6 b1；"域名" = d3 f2 c3 fb）
	gbkBody := string([]byte{0xb2, 0xca, 0xc6, 0xb1, 0x0a, 0xd3, 0xf2, 0xc3, 0xfb, 0x0a})
	got2 := ParseLexicon("text/plain", gbkBody)
	if len(got2) != 2 || got2[0] != "彩票" || got2[1] != "域名" {
		t.Fatalf("GBK 解析: %q", got2)
	}
}

func TestMergeSensWords(t *testing.T) {
	merged := MergeSensWords([]string{"赌博", "", "博彩"}, []string{"博彩", "办证"})
	if len(merged) != 3 || merged[0] != "赌博" || merged[1] != "博彩" || merged[2] != "办证" {
		t.Fatalf("合并: %v", merged)
	}
	// 总量截断
	big := make([]string, sensWordLimit+100)
	for i := range big {
		big[i] = strings.Repeat("a", 2) + strings.Repeat(string(rune('0'+i%10)), i%5)
	}
	if got := MergeSensWords(big, nil); len(got) > sensWordLimit {
		t.Fatalf("截断失效: %d", len(got))
	}
}

func TestDefaultSubConfig(t *testing.T) {
	c := DefaultSubConfig()
	if c.Base != DefaultSensSubBase || c.UpdateTime == "" || len(c.Files) == 0 {
		t.Fatalf("默认配置异常: %+v", c)
	}
	on := 0
	for _, f := range c.Files {
		if f.Enabled {
			on++
		}
	}
	if on == 0 || on == len(c.Files) {
		t.Fatalf("默认勾选应介于全部与空之间: on=%d/%d", on, len(c.Files))
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/konsheng/Sensitive-lexicon":                      "https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/main",
		"https://github.com/konsheng/Sensitive-lexicon/tree/dev":             "https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/dev",
		"https://raw.githubusercontent.com/konsheng/Sensitive-lexicon":       "https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/main",
		"https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/main/": "https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/main",
		"http://127.0.0.1:18190/raw":                                         "http://127.0.0.1:18190/raw",
		"":                                                                   "",
		"not-a-url":                                                          "",
	}
	for in, want := range cases {
		if got := NormalizeBaseURL(in); got != want {
			t.Errorf("NormalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitHubTreeAPI(t *testing.T) {
	cases := map[string]string{
		"https://github.com/a/b":                    "https://api.github.com/repos/a/b/git/trees/main?recursive=1",
		"https://raw.githubusercontent.com/a/b/dev": "https://api.github.com/repos/a/b/git/trees/dev?recursive=1",
		"http://127.0.0.1:18190/raw":                "",
	}
	for in, want := range cases {
		if got := GitHubTreeAPI(in); got != want {
			t.Errorf("GitHubTreeAPI(%q) = %q, want %q", in, got, want)
		}
	}
}
