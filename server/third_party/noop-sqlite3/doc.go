// 空桩：用 go.mod replace 裁掉 nuclei 依赖树里的 mattn/go-sqlite3（其 init 注册 "sqlite3"
// 驱动名，与本平台 ncruces/go-sqlite3 冲突导致 sql.Register panic）。
// nuclei 的 fuzz 统计功能本平台不启用；如其运行时按名打开 "sqlite3"，会命中本平台的 ncruces 驱动。
package go_sqlite3_noop
