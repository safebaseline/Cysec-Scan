package main

import (
	"os"
	"testing"
)

// TestEmbeddedTemplateInSync 防漂移：嵌入二进制的默认模板必须与仓库根目录的示例文件内容一致
func TestEmbeddedTemplateInSync(t *testing.T) {
	repo, err := os.ReadFile("../../../configs/config.example.yaml")
	if err != nil {
		t.Skipf("仓库示例文件不可读（非源码环境）: %v", err)
	}
	if string(repo) != string(exampleConfigYAML) {
		t.Fatalf("cmd/cysec/config.example.yaml 与 configs/config.example.yaml 内容不一致，请同步两份文件")
	}
}
