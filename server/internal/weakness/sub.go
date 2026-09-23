package weakness

import (
	"strings"

	"cysec/internal/charset"
)

// 敏感字词库订阅：从 GitHub 词汇仓库（默认 konsheng/Sensitive-lexicon，MIT）
// 周期拉取分类词库，与界面手动词库合并后参与页面敏感字检测。

// DefaultSensSubBase 默认订阅源预设（仅首次未配置时与"恢复预设"使用，可任意替换）
const DefaultSensSubBase = "https://raw.githubusercontent.com/konsheng/Sensitive-lexicon/main"

// DefaultSensSubMirror GitHub 直连失败时的镜像加速前缀
const DefaultSensSubMirror = "https://ghproxy.com/"

// SubFile 订阅源内的单个词库文件
type SubFile struct {
	Path    string `json:"path"`     // 相对仓库根的路径（URL 拉取时按段转义）
	Name    string `json:"name"`     // 界面显示名
	Enabled bool   `json:"enabled"`  // 是否纳入拉取（敏感字）
	ForDark bool   `json:"for_dark"` // 词表同时用作暗链关键词（外链锚文本/URL 匹配；内容审核类词库慎开，易误报）
}

// SubConfig 订阅配置
type SubConfig struct {
	Base       string    `json:"base"`        // raw 基址（可换 fork/镜像站）
	Mirror     string    `json:"mirror"`      // 直连失败重试的镜像前缀（空=不重试）
	Files      []SubFile `json:"files"`       // 词库文件清单（勾选）
	AutoUpdate bool      `json:"auto_update"` // 每日自动更新
	UpdateTime string    `json:"update_time"` // 自动更新时刻 HH:MM（默认 02:00）
}

// SubState 订阅状态（不含词表本体，词表单独存 settings）
type SubState struct {
	LastUpdate string   `json:"last_update"` // 最近一次拉取时间（平台本地时区）
	LastOK     bool     `json:"last_ok"`     // 最近一次是否全部成功
	WordCount  int      `json:"word_count"`  // 生效词数
	FileCount  map[string]int `json:"file_count,omitempty"` // 各文件词条数
	Errors     []string `json:"errors,omitempty"`
}

// DefaultSubConfig 默认订阅预设：分类词库全开 + 网易前端过滤通用库；
// 零时-Tencent（约 20 万行）、非法网址（URL 清单）与 GFW 补充默认关闭（体积大/非页面文本词）
func DefaultSubConfig() SubConfig {
	f := func(name, path string, on bool) SubFile {
		return SubFile{Name: name, Path: path, Enabled: on}
	}
	return SubConfig{
		Base:       DefaultSensSubBase,
		Mirror:     DefaultSensSubMirror,
		UpdateTime: "02:00",
		Files: []SubFile{
			f("政治类型", "Vocabulary/政治类型.txt", true),
			f("反动词库", "Vocabulary/反动词库.txt", true),
			f("暴恐词库", "Vocabulary/暴恐词库.txt", true),
			f("色情类型", "Vocabulary/色情类型.txt", true),
			f("色情词库", "Vocabulary/色情词库.txt", true),
			f("贪腐词库", "Vocabulary/贪腐词库.txt", true),
			f("民生词库", "Vocabulary/民生词库.txt", true),
			f("涉枪涉爆", "Vocabulary/涉枪涉爆.txt", true),
			f("广告类型", "Vocabulary/广告类型.txt", true),
			f("补充词库", "Vocabulary/补充词库.txt", true),
			f("COVID-19", "Vocabulary/COVID-19词库.txt", true),
			f("新思想启蒙", "Vocabulary/新思想启蒙.txt", true),
			f("其他词库", "Vocabulary/其他词库.txt", true),
			f("网易前端过滤（通用大词库）", "Vocabulary/网易前端过滤敏感词库.txt", true),
			f("GFW 补充词库", "Vocabulary/GFW补充词库.txt", false),
			f("零时-Tencent（超大）", "Vocabulary/零时-Tencent.txt", false),
			f("非法网址（URL 清单）", "Vocabulary/非法网址.txt", false),
		},
	}
}

// NormalizeSubConfig 补全空字段（保存/更新前调用）；Mirror 留空表示禁用镜像重试。
// Base 支持 github.com 仓库页 / raw.githubusercontent.com / 任意 http(s) raw 基址，统一归一。
func NormalizeSubConfig(c SubConfig) SubConfig {
	c.Base = NormalizeBaseURL(c.Base)
	if c.Base == "" {
		c.Base = DefaultSensSubBase
	}
	if c.UpdateTime == "" {
		c.UpdateTime = defUpdateTime
	}
	return c
}

const defUpdateTime = "02:00"

// NormalizeBaseURL 订阅基址归一：
//   - github.com/{o}/{r}、github.com/{o}/{r}/tree/{br} → raw.githubusercontent.com/{o}/{r}/{br|main}
//   - raw.githubusercontent.com/{o}/{r}（缺分支）→ 补 main
//   - 其他 http(s) 地址原样保留（自定义 raw 源）
func NormalizeBaseURL(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if u == "" {
		return ""
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return ""
	}
	if s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"); strings.HasPrefix(s, "github.com/") {
		parts := strings.Split(s, "/") // github.com o r [tree br ...]
		if len(parts) >= 3 {
			br := "main"
			if len(parts) >= 5 && parts[3] == "tree" {
				br = parts[4]
			}
			return "https://raw.githubusercontent.com/" + parts[1] + "/" + parts[2] + "/" + br
		}
		return ""
	}
	if s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"); strings.HasPrefix(s, "raw.githubusercontent.com/") {
		parts := strings.Split(s, "/") // raw.githubusercontent.com o r [br ...]
		if len(parts) == 3 {           // 缺分支
			return u + "/main"
		}
	}
	return u
}

// GitHubTreeAPI 由订阅基址推导 GitHub 仓库 tree API（用于自动发现词库文件）；
// 非 GitHub 源返回空串（自定义 raw 源需手工填写文件路径）
func GitHubTreeAPI(base string) string {
	u := NormalizeBaseURL(base)
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if !strings.HasPrefix(s, "raw.githubusercontent.com/") {
		return ""
	}
	parts := strings.Split(s, "/") // raw.githubusercontent.com o r br ...
	if len(parts) < 4 {
		return ""
	}
	return "https://api.github.com/repos/" + parts[1] + "/" + parts[2] + "/git/trees/" + parts[3] + "?recursive=1"
}

// sensWordMaxLen 单词条长度上限（rune）：过滤误入的长句/整行文本
const sensWordMaxLen = 60

// ValidSensWord 词条统一校验：最短 2 字符（单字词在页面文本包含匹配中几乎必然误报，
// 任何入口——订阅解析/手工新增/存量清理——均按此规则过滤）、上限 60 字符
func ValidSensWord(w string) bool {
	r := []rune(w)
	return len(r) >= 2 && len(r) <= sensWordMaxLen
}

// sensWordLimit 合并后总词数上限（防护超大订阅把扫描拖垮）
const sensWordLimit = 60000

// ParseLexicon 解析词库文本为词条列表：编码归一（UTF-8/GBK/GB18030）、
// 去空白、跳过注释与 URL 型行、按长度过滤、保序去重
func ParseLexicon(contentType, body string) []string {
	text := string(charset.Normalize([]byte(body), contentType))
	seen := map[string]bool{}
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		w := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		if strings.Contains(w, "://") || strings.HasPrefix(strings.ToLower(w), "www.") {
			continue // URL 型行（如"非法网址"清单）不是页面文本敏感词
		}
		if strings.ContainsAny(w, "\t\"'`|") {
			continue // 混入的分隔符/引号行视为脏数据
		}
		if !ValidSensWord(w) { // 单字词与超长行过滤
			continue
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

// MergeSensWords 多份词表合并（保序去重、总量截断）——手动/订阅/暗链等来源统一入口
func MergeSensWords(lists ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, list := range lists {
		for _, w := range list {
			w = strings.TrimSpace(w)
			if w == "" || seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
			if len(out) >= sensWordLimit {
				return out
			}
		}
	}
	return out
}
