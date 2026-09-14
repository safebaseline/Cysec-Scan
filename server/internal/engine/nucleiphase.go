package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"cysec/internal/model"
	"cysec/internal/plugins"
	"cysec/internal/vulnrule"
)

// 官方 nuclei 引擎批量阶段：对本轮发现的全部 Web 资产执行启用的 nuclei 规则。
// 自研简化执行器对官方模板的匹配语义覆盖不全，误报率高；nuclei 源规则统一
// 改由官方引擎（vulnrule.RunNucleiBatch）执行，结果与 nuclei CLI 完全一致。
// xray / afrog 源规则仍由自研执行器在 detectWeb 内联执行。

// addScanWebURL 记录本轮任务发现的 Web 资产 URL（供任务级 nuclei 批量阶段收集）
func (e *Engine) addScanWebURL(taskID int64, url string) {
	if taskID <= 0 || url == "" {
		return
	}
	e.webURLMu.Lock()
	defer e.webURLMu.Unlock()
	e.webURLs[taskID] = append(e.webURLs[taskID], url)
}

// takeScanWebURLs 取出并清空任务本轮收集的 Web 资产 URL（去重）
func (e *Engine) takeScanWebURLs(taskID int64) []string {
	e.webURLMu.Lock()
	urls := e.webURLs[taskID]
	delete(e.webURLs, taskID)
	e.webURLMu.Unlock()
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// runNucleiPhase 官方 nuclei 引擎批量执行入口（任务级 / 实时扫描单目标共用）
func (e *Engine) runNucleiPhase(task *model.ScanTask, urls []string) {
	if len(urls) == 0 || vulnrule.NucleiTemplateRoot() == "" {
		return
	}
	st := vulnrule.DefaultSettings()
	if saved, _ := e.store.GetSetting("vuln_rule_settings"); saved != "" {
		json.Unmarshal([]byte(saved), &st)
	}
	if !st.EnabledInScan {
		return
	}
	ids := []string{}
	for _, r := range e.store.EnabledRulesForScan(st.MaxPerTarget) {
		if r.Source == "nuclei" {
			ids = append(ids, r.RuleID)
		}
	}
	if len(ids) == 0 {
		return
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("nuclei 官方引擎：对 %d 个 Web 资产执行 %d 条启用规则", len(urls), len(ids)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // 任务取消 → 中止引擎扫描
		select {
		case <-runCancel(e, task.ID):
			cancel()
		case <-ctx.Done():
		}
	}()

	findings, err := vulnrule.RunNucleiBatch(ctx, urls, ids, task.TimeoutSec)
	if err != nil {
		e.store.LogTask(task.ID, "warn", "nuclei 引擎执行异常: "+err.Error())
	}
	if len(findings) == 0 {
		e.store.LogTask(task.ID, "info", "nuclei 官方引擎：未检出漏洞")
		return
	}

	// Web 资产字段映射（IP/端口/域名）
	webs := e.store.WebsOfProject(task.ProjectID)
	webMap := make(map[string]*model.AssetWeb, len(webs))
	for i := range webs {
		w := webs[i]
		webMap[normalizeWebKey(w.URL)] = &w
	}
	matched := 0
	for _, f := range findings {
		w := &plugins.WebResult{URL: f.URL, Port: atoiOrZero(f.Port), IP: f.Host}
		if aw := webMap[normalizeWebKey(f.URL)]; aw != nil {
			w.IP, w.Domain, w.Port, w.URL = aw.IP, aw.Domain, aw.Port, aw.URL
		}
		e.saveVuln(task, plugins.VulnResult{
			VulnID:      f.TemplateID,
			Name:        orDefaultStr(f.Name, f.TemplateID),
			Severity:    orDefaultStr(f.Severity, "info"),
			Description: f.Description,
			Solution:    "参考模板修复建议: " + f.TemplateID,
			Evidence:    orDefaultStr(f.MatchedAt, f.URL),
			Request:     f.Request,
			Response:    f.Response,
			Component:   "规则库(nuclei)",
			Scanner:     "nuclei-engine",
		}, w)
		matched++
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("nuclei 官方引擎检出 %d 个漏洞", matched))
}

func normalizeWebKey(u string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u)), "/")
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
