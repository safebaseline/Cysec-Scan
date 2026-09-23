package engine

import (
	"encoding/json"
	"testing"

	"cysec/internal/config"
	"cysec/internal/store"
	"cysec/internal/weakness"
)

// TestRawSettingsDarkRoundTrip 设置读写回归：
// 1) 保存后原样读回（dark/sens 不串列）——DefaultSettings 曾让两字段共享切片，
//    json 反序列化复用切片内存导致后解的 sensitive_words 覆盖 dark_keywords（字段别名）；
// 2) 二次保存不带 dark_keywords 时历史暗链词保留（界面已并入统一词库）；
// 3) 引擎生效视图：暗链 = 历史暗链词 ∪ 手动词库 ∪ 订阅 ForDark 文件词表。
func TestRawSettingsDarkRoundTrip(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := New(db, &config.Config{})

	if err := e.SetWeaknessSettings(weakness.Settings{Enabled: true, MaxPages: 3, MaxLinks: 4,
		DarkKeywords: []string{"DARKY"}, SensitiveWords: []string{"SENSX"}}); err != nil {
		t.Fatal(err)
	}
	raw := e.CurrentWeaknessSettings()
	if len(raw.DarkKeywords) != 1 || raw.DarkKeywords[0] != "DARKY" {
		t.Fatalf("CurrentWeaknessSettings dark = %v, want [DARKY]", raw.DarkKeywords)
	}
	if len(raw.SensitiveWords) != 1 || raw.SensitiveWords[0] != "SENSX" {
		t.Fatalf("CurrentWeaknessSettings sens = %v, want [SENSX]", raw.SensitiveWords)
	}

	if err := e.SetWeaknessSettings(weakness.Settings{Enabled: true, SensitiveWords: []string{"SENSZ"}}); err != nil {
		t.Fatal(err)
	}
	raw2 := e.CurrentWeaknessSettings()
	if len(raw2.DarkKeywords) != 1 || raw2.DarkKeywords[0] != "DARKY" {
		t.Fatalf("二次保存后 dark = %v, want [DARKY]（历史暗链词保留）", raw2.DarkKeywords)
	}

	eff := e.weaknessSettings()
	if b, _ := json.Marshal(eff.DarkKeywords); string(b) != `["DARKY","SENSZ"]` {
		t.Fatalf("生效暗链词表 = %s, want [DARKY SENSZ]", b)
	}
	if b, _ := json.Marshal(eff.SensitiveWords); string(b) != `["SENSZ"]` {
		t.Fatalf("生效敏感字词表 = %s, want [SENSZ]（无订阅时仅手动）", b)
	}
}
