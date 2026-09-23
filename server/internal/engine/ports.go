package engine

import (
	"sort"
	"sync"
)

// top1000 标准模式默认端口集（Top1000），sync.Once 保护懒初始化（并发 worker 共用）
var (
	top1000Cached []int
	top1000Once   sync.Once
)

// servicePorts 精选常见服务端口（约 150 个，优先保证覆盖真实业务服务）
var servicePorts = []int{
	21, 22, 23, 25, 53, 67, 69, 80, 81, 88, 110, 111, 135, 137, 139, 143, 161, 162, 389, 427,
	443, 444, 445, 465, 514, 515, 543, 548, 554, 587, 631, 636, 646, 873, 990, 992, 993, 995,
	1080, 1433, 1521, 1723, 1900, 2049, 2121, 2222, 2375, 2376, 2601, 2604, 3000, 3001, 3128,
	3260, 3268, 3269, 3306, 3389, 3690, 4444, 4848, 5000, 5001, 5432, 5555, 5601, 5632, 5666,
	5800, 5900, 5901, 5984, 6000, 6001, 6379, 6443, 6666, 7000, 7001, 7002, 7070, 7180, 7547,
	7777, 8000, 8008, 8009, 8010, 8020, 8080, 8081, 8088, 8089, 8090, 8098, 8161, 8181, 8222,
	8333, 8443, 8500, 8649, 8686, 8761, 8786, 8800, 8848, 8868, 8888, 8983, 9000, 9001, 9002,
	9008, 9010, 9043, 9080, 9081, 9090, 9091, 9100, 9160, 9200, 9300, 9418, 9440, 9443, 9527,
	9600, 9800, 9869, 9981, 9986, 9999, 10000, 10001, 10050, 10051, 1099, 11211, 15672, 18080,
	18081, 19000, 20000, 20720, 20880, 22000, 22350, 23399, 26000, 27017, 28015, 28017, 3310,
	50000, 50070, 56000, 61616, 63790,
}

// Top1000Ports 标准模式默认端口集：精选服务端口 + 自 1024 起顺序填充至 1000 个
func Top1000Ports() []int {
	top1000Once.Do(func() {
		seen := map[int]bool{}
		out := make([]int, 0, 1000)
		add := func(p int) {
			if p > 0 && p < 65536 && !seen[p] && len(out) < 1000 {
				seen[p] = true
				out = append(out, p)
			}
		}
		for _, p := range servicePorts {
			add(p)
		}
		for p := 1024; len(out) < 1000 && p < 65536; p++ {
			add(p)
		}
		sort.Ints(out)
		top1000Cached = out
	})
	return top1000Cached
}

// FullPorts 1-65535 全端口（深度模式默认）
func FullPorts() []int {
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports
}

// DefaultPortsByMode 各模式默认端口集：
// quick=常见端口（配置 top_ports）、standard=Top1000、deep=全端口；任务显式指定端口时覆盖
func DefaultPortsByMode(mode string, topPorts []int) []int {
	switch mode {
	case "standard":
		return Top1000Ports()
	case "deep":
		return FullPorts()
	default:
		return topPorts
	}
}
