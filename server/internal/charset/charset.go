// Package charset 响应体编码规范化：GBK/GB18030 等中文页面按 UTF-8 解析会出现
// "锟斤拷/????"式乱码入库。非合法 UTF-8 时尝试 GBK 系解码，仍失败则剔除非法字节。
// 供 Web 探测（restrictedDoer）与弱点爬虫（colly）共用同一口径。
package charset

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// Normalize 按响应 Content-Type 与字节内容归一为合法 UTF-8
func Normalize(body []byte, contentType string) []byte {
	if utf8.Valid(body) {
		return body
	}
	encs := []encoding.Encoding{simplifiedchinese.GBK, simplifiedchinese.GB18030}
	if ct := strings.ToLower(contentType); strings.Contains(ct, "gb2312") || strings.Contains(ct, "gbk") {
		encs = []encoding.Encoding{simplifiedchinese.GB18030, simplifiedchinese.GBK}
	}
	for _, enc := range encs {
		if out, err := enc.NewDecoder().Bytes(body); err == nil && utf8.Valid(out) {
			return out
		}
	}
	return bytes.ToValidUTF8(body, []byte("?"))
}
