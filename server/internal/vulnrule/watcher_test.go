package vulnrule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiffSnapshots(t *testing.T) {
	prev := map[string]fileStamp{"a.yaml": {1, 10}, "b.yaml": {1, 10}}
	curr := map[string]fileStamp{
		"a.yaml":        {1, 10}, // 未变
		"b.yaml":        {2, 20}, // 变更
		"c/nuclei.yaml": {3, 30}, // 新增
	}
	got := DiffSnapshots(prev, curr)
	if len(got) != 2 || got[0] != "b.yaml" || got[1] != "c/nuclei.yaml" {
		t.Fatalf("diff = %v", got)
	}
}

func TestSnapshotWalkOnlyYAML(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "nuclei"), 0o755)
	os.WriteFile(filepath.Join(dir, "nuclei", "a.yaml"), []byte("id: a"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("id: b"), 0o644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "d.yaml"), []byte("id: d"), 0o644)
	snap, err := snapshotWalk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 2 {
		t.Fatalf("应只收录 yml/yaml 且跳过 .git: %v", snap)
	}
	if _, ok := snap[filepath.Join("nuclei", "a.yaml")]; !ok {
		t.Fatal("缺少 nuclei/a.yaml")
	}
}

func TestWatcherConfigClamp(t *testing.T) {
	ConfigureWatcher(WatcherConfig{Enabled: true, IntervalSec: 1})
	if WatcherConfigOf().IntervalSec != 5 {
		t.Fatal("过小间隔应钳制到 5s")
	}
	ConfigureWatcher(WatcherConfig{Enabled: true, IntervalSec: 99999})
	if WatcherConfigOf().IntervalSec != 3600 {
		t.Fatal("过大间隔应钳制到 3600s")
	}
	ConfigureWatcher(DefaultWatcherConfig())
}
