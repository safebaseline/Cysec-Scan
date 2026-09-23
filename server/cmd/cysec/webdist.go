package main

import "embed"

// webdist 前端构建产物（由 Makefile / Docker 构建时从 web/dist 复制）
//
//go:embed all:webdist
var webdist embed.FS
