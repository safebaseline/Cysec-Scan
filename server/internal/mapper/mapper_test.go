package mapper

import (
	"encoding/json"
	"testing"
)

// 离线测试：各引擎响应解析逻辑（不发真实请求）

func TestParseFOFAResponse(t *testing.T) {
	body := []byte(`{"error":false,"size":2,"results":[
		["1.2.3.4","443","https","a.example.com","https://a.example.com","站点A","nginx"],
		["1.2.3.4","8080","http","","http://1.2.3.4:8080","站点B",""]
	]}`)
	var resp struct {
		Error   bool       `json:"error"`
		Errmsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error || len(resp.Results) != 2 {
		t.Fatalf("fofa resp: %+v", resp)
	}
	if resp.Results[0][3] != "a.example.com" || resp.Results[0][5] != "站点A" {
		t.Fatalf("fofa fields 解析错误: %v", resp.Results[0])
	}
}

func TestParseQuakeResponse(t *testing.T) {
	body := []byte(`{"code":0,"message":"Successful.","data":[{
		"ip":"1.2.3.4","port":443,"transport":"tcp","domain":"a.example.com",
		"service":{"name":"https","product":"nginx","http":{"title":"T","host":"a.example.com","server":"nginx","path":"/"}}
	}],"total_count":1}`)
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			IP        string `json:"ip"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Domain    string `json:"domain"`
			Service   struct {
				Name    string `json:"name"`
				Product string `json:"product"`
				HTTP    struct {
					Title  string `json:"title"`
					Host   string `json:"host"`
					Server string `json:"server"`
				} `json:"http"`
			} `json:"service"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 || len(resp.Data) != 1 || resp.Data[0].Service.HTTP.Title != "T" {
		t.Fatalf("quake resp: %+v", resp)
	}
	d := resp.Data[0]
	if getServiceName(d.Port, d.Transport, d.Service.Name, d.Service.Product) != "HTTPS" {
		t.Fatal("服务推断错误")
	}
}

func TestParseShodanResponse(t *testing.T) {
	body := []byte(`{"total":1,"matches":[{"ip_str":"1.1.1.1","port":8443,"transport":"tcp","product":"nginx","hostnames":["x.example.com"],"http":{"title":"X","host":"x.example.com","server":"nginx"}}]}`)
	var resp struct {
		Error   string `json:"error"`
		Matches []struct {
			IPStr     string   `json:"ip_str"`
			Port      int      `json:"port"`
			Transport string   `json:"transport"`
			Product   string   `json:"product"`
			Hostnames []string `json:"hostnames"`
			HTTP      struct {
				Title string `json:"title"`
				Host  string `json:"host"`
			} `json:"http"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" || len(resp.Matches) != 1 || resp.Matches[0].HTTP.Title != "X" {
		t.Fatalf("shodan resp: %+v", resp)
	}
}

func TestParseZeroZoneResponse(t *testing.T) {
	body := []byte(`{"code":0,"message":"","total":1,"data":[{"ip":"1.2.3.4","port":[80,443],"url":"http://a.example.com","title":"零","component":["nginx"],"service":["http"],"cname":""}]}`)
	var resp struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 || len(resp.Data) != 1 {
		t.Fatalf("0zone resp: %+v", resp)
	}
	d := resp.Data[0]
	if firstInt(d["port"]) != 80 || firstStr(d["title"]) != "零" {
		t.Fatalf("0zone 字段解析错误: %v", d)
	}
}

func TestParseZoomEyeResponse(t *testing.T) {
	body := []byte(`{"code":60000,"message":"Successful.","total":1,"data":[{"ip":"1.2.3.4","port":80,"transport":"tcp","service":{"name":"http","http":{"title":"Z","host":"http://z.example.com"}}}]}`)
	var resp struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 60000 || len(resp.Data) != 1 {
		t.Fatalf("zoomeye resp: %+v", resp)
	}
	svc, _ := resp.Data[0]["service"].(map[string]any)
	if firstInt(resp.Data[0]["port"]) != 80 || svc == nil {
		t.Fatal("zoomeye 字段解析错误")
	}
}

func TestProviderRegistry(t *testing.T) {
	names := []string{}
	for _, p := range Providers() {
		names = append(names, p.Name())
	}
	for _, want := range []string{"fofa", "quake", "shodan", "0.zone", "zoomeye"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少测绘引擎 %s（已注册: %v）", want, names)
		}
	}
}

func TestReadyChecks(t *testing.T) {
	cfg := Config{Enabled: true, FOFAEnable: true, FOFAKey: "k"}
	var f, q, s Provider
	for _, p := range Providers() {
		switch p.Name() {
		case "fofa":
			f = p
		case "quake":
			q = p
		case "shodan":
			s = p
		}
	}
	if !f.Ready(cfg) {
		t.Fatal("fofa 应就绪")
	}
	if q.Ready(cfg) {
		t.Fatal("quake 未配置 key 不应就绪")
	}
	if s.Ready(cfg) {
		t.Fatal("shodan 未配置 key 不应就绪")
	}
}

func TestQueryAllDisabled(t *testing.T) {
	Configure(Config{Enabled: false})
	defer Configure(Config{})
	recs, errs := QueryAll("1.2.3.4")
	if recs != nil || errs != nil {
		t.Fatal("总开关关闭时不应查询")
	}
}

func TestHelpers(t *testing.T) {
	if b64("ip=\"1.2.3.4\"") == "" || b64("x") == "x" {
		t.Fatal("b64 错误")
	}
	if firstInt("8080") != 8080 || firstInt(float64(443)) != 443 || firstInt([]any{float64(80)}) != 80 {
		t.Fatal("firstInt 错误")
	}
	if firstStr(float64(80)) != "80" || firstStr([]any{"a", "b"}) != "a" {
		t.Fatal("firstStr 错误")
	}
	if getServiceName(443, "tcp", "", "nginx") != "HTTPS" || getServiceName(22, "", "", "") != "SSH" {
		t.Fatal("服务推断错误")
	}
}

func TestEndpointURLOverride(t *testing.T) {
	if endpointURL("", defaultFOFAURL) != "https://fofa.info/api/v1/search/all" {
		t.Fatal("留空应回退默认")
	}
	if got := endpointURL("https://fofa.example.com/api/v1/search/all/", defaultFOFAURL); got != "https://fofa.example.com/api/v1/search/all" {
		t.Fatalf("自定义地址应去尾斜杠: %s", got)
	}
	if endpointURL("  ", defaultQuakeURL) != defaultQuakeURL {
		t.Fatal("空白应回退默认")
	}
}

func TestConfigNormalize(t *testing.T) {
	Configure(Config{Enabled: true, Size: 5000})
	defer Configure(Config{})
	if Current().Size != 1000 {
		t.Fatalf("Size 应被限制到 1000: %d", Current().Size)
	}
	Configure(Config{Enabled: true, Size: -3})
	if Current().Size != 100 {
		t.Fatal("非法 Size 应回退默认 100")
	}
}

func TestSynthesizeWebURL(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
		want string
	}{
		{"FOFA纯IP+HTTP服务", Record{IP: "1.2.3.4", Port: 11001, Service: "HTTP"}, "http://1.2.3.4:11001"},
		{"纯IP+443", Record{IP: "1.2.3.4", Port: 443, Service: "HTTPS"}, "https://1.2.3.4"},
		{"域名优先", Record{IP: "1.2.3.4", Port: 8443, Domain: "a.example.com", Service: "HTTP"}, "https://a.example.com:8443"},
		{"服务空但常见Web端口", Record{IP: "1.2.3.4", Port: 8080}, "http://1.2.3.4:8080"},
		{"非HTTP服务不合成", Record{IP: "1.2.3.4", Port: 3306, Service: "MySQL"}, ""},
		{"无端口特征不合成", Record{IP: "1.2.3.4", Port: 5555}, ""},
	}
	for _, c := range cases {
		if got := synthesizeWebURL(c.rec); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
