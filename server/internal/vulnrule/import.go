package vulnrule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportDir 递归扫描目录，导入所有 .yml/.yaml 规则文件
func ImportDir(dir string, upsert func(Rule) (bool, error)) (*ImportResult, error) {
	res, _, err := ImportDirCollect(dir, upsert)
	return res, err
}

// ImportDirCollect 导入并返回本次「新增」的规则（upsert 判定为新插入的），
// 用于模板源更新后仅对新增 POC 触发全资产扫描
func ImportDirCollect(dir string, upsert func(Rule) (bool, error)) (*ImportResult, []Rule, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("目录不存在: %v", err)
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("不是目录: %s", dir)
	}
	res := &ImportResult{Errors: []string{}}
	newRules := []Rule{}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// 跳过明显无关的目录
			name := strings.ToLower(info.Name())
			if strings.HasPrefix(name, ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil // 符号链接文件跳过：Walk 不跟随，防止读到目录树之外的内容
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		if info.Size() > 2<<20 { // >2MB 跳过
			return nil
		}
		res.FilesScanned++
		content, err := os.ReadFile(path)
		if err != nil {
			res.Failed++
			if len(res.Errors) < 5 {
				res.Errors = append(res.Errors, path+": "+err.Error())
			}
			return nil
		}
		r, err := ParseFile(path, content)
		if err != nil {
			res.Failed++
			if len(res.Errors) < 5 {
				res.Errors = append(res.Errors, filepath.Base(path)+": "+err.Error())
			}
			return nil
		}
		if !r.Supported {
			res.Unsupported++
		}
		isNew, err := upsert(*r)
		if err != nil {
			res.Failed++
			if len(res.Errors) < 5 {
				res.Errors = append(res.Errors, path+": "+err.Error())
			}
			return nil
		}
		if isNew {
			res.Imported++
			if r.Supported {
				newRules = append(newRules, *r)
			}
		} else {
			res.Updated++
		}
		return nil
	})
	if err != nil {
		return res, nil, err
	}
	return res, newRules, nil
}
