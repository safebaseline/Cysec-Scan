// POC 目录监控：周期快照 data/poc 目录，发现新增/变更的 .yml/.yaml 规则文件后
// 自动导入规则库，并回调触发对新规则的全资产漏洞扫描。
package vulnrule

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// WatcherConfig 监控配置（持久化于 settings 表 key=poc_watcher）
type WatcherConfig struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"interval_sec"`
}

func DefaultWatcherConfig() WatcherConfig { return WatcherConfig{Enabled: true, IntervalSec: 60} }

// watcherState 运行状态（供 API/UI 展示）
var (
	wMu    sync.RWMutex
	wCfg   = DefaultWatcherConfig()
	wState = map[string]any{"last_check": "", "last_new_files": 0, "watching_files": 0,
		"last_scan": map[string]any{}, "scanning": false}
	wSuppress bool // 模板源更新等批量写入期间抑制：只刷新基线不判定新增
)

// ConfigureWatcher 更新监控配置（热生效）
func ConfigureWatcher(c WatcherConfig) {
	if c.IntervalSec < 5 {
		c.IntervalSec = 5
	}
	if c.IntervalSec > 3600 {
		c.IntervalSec = 3600
	}
	wMu.Lock()
	wCfg = c
	wMu.Unlock()
}

// WatcherConfigOf 当前监控配置
func WatcherConfigOf() WatcherConfig {
	wMu.RLock()
	defer wMu.RUnlock()
	return wCfg
}

// WatcherState 当前监控状态快照
func WatcherState() map[string]any {
	wMu.RLock()
	defer wMu.RUnlock()
	out := map[string]any{"enabled": wCfg.Enabled, "interval_sec": wCfg.IntervalSec}
	for k, v := range wState {
		out[k] = v
	}
	return out
}

func watcherSet(key string, val any) {
	wMu.Lock()
	wState[key] = val
	wMu.Unlock()
}

// fileStamp 文件指纹
type fileStamp struct {
	ModTime int64
	Size    int64
}

// snapshotWalk 递归收集 .yml/.yaml 文件指纹
func snapshotWalk(root string) (map[string]fileStamp, error) {
	out := map[string]fileStamp{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = fileStamp{ModTime: info.ModTime().Unix(), Size: info.Size()}
		return nil
	})
	return out, err
}

// DiffSnapshots 返回新增或变更的相对路径（导出便于单测）
func DiffSnapshots(prev, curr map[string]fileStamp) []string {
	changed := []string{}
	for rel, st := range curr {
		old, ok := prev[rel]
		if !ok || old != st {
			changed = append(changed, rel)
		}
	}
	sort.Strings(changed)
	return changed
}

// StartWatcher 启动监控循环（进程内单例，重复调用不产生第二个监控循环）。
// upsert 导入函数；onNewRules 在有新增规则后被调用（已过滤可执行规则），异常不影响监控。
func StartWatcher(root string, upsert func(Rule) (bool, error), onNewRules func([]Rule)) {
	watcherOnce.Do(func() {
		go watchLoop(root, upsert, onNewRules)
	})
}

var watcherOnce sync.Once

func watchLoop(root string, upsert func(Rule) (bool, error), onNewRules func([]Rule)) {
	{
		// 初始基线：首次启动只建立快照，不触发扫描（存量文件在导入/更新时已处理）
		prev, _ := snapshotWalk(root)
		watcherSet("watching_files", len(prev))
		watcherSet("last_check", time.Now().Format(time.RFC3339))
		nextCheck := time.Now()
		var suppressWalk time.Time
		for {
			time.Sleep(2 * time.Second) // 小步轮询，配置变更（含间隔）≤2s 热生效
			cfg := WatcherConfigOf()
			if !cfg.Enabled {
				continue
			}
			if wSuppressLocked() {
				// 抑制期间（如模板源批量克隆）放宽检查节奏，避免大目录频繁 walk
				if time.Since(suppressWalk) < 30*time.Second {
					continue
				}
				suppressWalk = time.Now()
			}
			if time.Now().Before(nextCheck) {
				continue
			}
			nextCheck = time.Now().Add(time.Duration(cfg.IntervalSec) * time.Second)
			curr, err := snapshotWalk(root)
			if err != nil {
				continue
			}
			watcherSet("watching_files", len(curr))
			watcherSet("last_check", time.Now().Format(time.RFC3339))
			if wSuppressLocked() {
				prev = curr // 抑制期间仅刷新基线
				continue
			}
			changed := DiffSnapshots(prev, curr)
			prev = curr
			if len(changed) == 0 {
				continue
			}
			watcherSet("last_new_files", len(changed))
			// 逐个解析入库（2MB 尺寸护栏：与 ImportDirCollect 一致，防止超大 YAML 造成内存尖峰）
			newRules := []Rule{}
			for _, rel := range changed {
				full := filepath.Join(root, rel)
				if fi, err := os.Stat(full); err == nil && fi.Size() > 2<<20 {
					log.Printf("[POC监控] 跳过超大文件 %s（%d 字节）", rel, fi.Size())
					continue
				}
				content, err := os.ReadFile(full)
				if err != nil {
					continue
				}
				r, err := ParseFile(full, content)
				if err != nil {
					continue
				}
				if _, err := upsert(*r); err != nil {
					continue
				}
				if r.Supported {
					newRules = append(newRules, *r)
				}
			}
			if len(newRules) > 0 && onNewRules != nil {
				scanning := false
				wMu.RLock()
				if b, ok := wState["scanning"].(bool); ok {
					scanning = b
				}
				wMu.RUnlock()
				if !scanning {
					go onNewRules(newRules)
				}
			}
		}
	}
}

// MarkScanState 更新扫描进行状态
func MarkScanState(scanning bool) { watcherSet("scanning", scanning) }

// SuppressWatcher 抑制/恢复目录监控（模板源更新等批量写入期间调用，避免误触发全资产扫描）
func SuppressWatcher(on bool) {
	wMu.Lock()
	wSuppress = on
	wMu.Unlock()
}

func wSuppressLocked() bool {
	wMu.RLock()
	defer wMu.RUnlock()
	return wSuppress
}

// SetLastScan 记录最近一轮新规则扫描结果
func SetLastScan(result map[string]any) { watcherSet("last_scan", result) }
