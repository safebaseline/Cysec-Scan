package vulnrule

import (
	"os"
	"path/filepath"
	"testing"
)

const impNuclei = "id: imp-new-1\ninfo:\n  name: New One\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/x\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"

func TestImportDirCollectNewVsExisting(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(impNuclei), 0o644)

	store := map[string]bool{} // rule_id -> exists
	upsert := func(r Rule) (bool, error) {
		if store[r.RuleID] {
			return false, nil // 已存在 -> 更新（非新增）
		}
		store[r.RuleID] = true
		return true, nil
	}

	res, news, err := ImportDirCollect(dir, upsert)
	if err != nil || res.Imported != 1 || len(news) != 1 || news[0].RuleID != "imp-new-1" {
		t.Fatalf("首次导入: res=%+v news=%d err=%v", res, len(news), err)
	}

	// 重复导入：全部视为更新，无新增
	res2, news2, _ := ImportDirCollect(dir, upsert)
	if res2.Imported != 0 || res2.Updated != 1 || len(news2) != 0 {
		t.Fatalf("重复导入应无新增: %+v news=%d", res2, len(news2))
	}

	// 新增第二个文件：仅收集到新文件对应的规则
	os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("id: imp-new-2\ninfo:\n  name: Two\n  severity: low\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/y\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"), 0o644)
	_, news3, _ := ImportDirCollect(dir, upsert)
	if len(news3) != 1 || news3[0].RuleID != "imp-new-2" {
		t.Fatalf("增量导入应只收集新规则: %+v", news3)
	}
}
