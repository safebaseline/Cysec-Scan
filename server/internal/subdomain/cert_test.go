package subdomain

import "testing"

func TestParseCertLines(t *testing.T) {
	body := "example.com\r\n" +
		"www.example.com\n" +
		"*.wild.example.com\r\n" +
		"dev.example.com\n" +
		"DEV.example.com \n" +
		"notexample.org\n" +
		"sub.other.com\n" +
		"\n" +
		".dot.example.com.\n"
	got := parseCertLines("example.com", body)
	want := []string{"www.example.com", "wild.example.com", "dev.example.com", "dot.example.com"}
	if len(got) != len(want) {
		t.Fatalf("解析结果数量不符: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 项不符: got %s want %s", i, got[i], want[i])
		}
	}
}

func TestParseCertLinesEmpty(t *testing.T) {
	if got := parseCertLines("example.com", ""); len(got) != 0 {
		t.Fatalf("空响应应无结果: %v", got)
	}
	if got := parseCertLines("example.com", "\n\n"); len(got) != 0 {
		t.Fatalf("空白响应应无结果: %v", got)
	}
}
