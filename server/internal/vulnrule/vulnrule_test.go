package vulnrule

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const nucleiSample = `
id: unauth-kubecost
info:
  name: KubeCost - Unauthenticated Dashboard Exposure
  severity: medium
  description: KubeCost Dashboard is exposed to external users.
  tags: misconfig,exposure,unauth
http:
  - method: GET
    path:
      - '{{BaseURL}}/overview.html'
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<title>Kubecost</title>"
      - type: word
        part: header
        words:
          - text/html
      - type: status
        status:
          - 200
`

const xraySample = `
name: poc-yaml-DT-File-reading
transport: http
rules:
  r0:
    request:
      method: GET
      path: /../../../../etc/passwd
    expression: response.status == 200 && response.body.bcontains(b'root:')
expression: r0()
detail:
  author: Superhero
  description: 任意文件读取
`

const afrogSample = `
id: tomcat-default-login
info:
  name: Apache Tomcat Manager Default Login
  severity: high
set:
  adminb64: base64('admin:admin')
rules:
  r0:
    request:
      method: GET
      path: /manager/html
      headers:
        Authorization: "Basic {{adminb64}}"
    expression: response.status == 200 && response.headers["set-cookie"].contains('JSESSIONID') && response.body.bcontains(b"<title>/manager</title>")
  r1:
    request:
      method: GET
      path: /manager/html
      headers:
        Authorization: "Basic {{adminb64}}"
    expression: response.status == 200 && response.body.bcontains(b"<title>/manager</title>")
expression: r0() || r1()
`

func TestParseNuclei(t *testing.T) {
	r, err := ParseFile("a.yaml", []byte(nucleiSample))
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "nuclei" || r.RuleID != "unauth-kubecost" || r.Severity != "medium" {
		t.Fatalf("%+v", r)
	}
	if !r.Supported || r.execTmp == nil || len(r.execTmp.Steps) != 1 {
		t.Fatalf("steps: %+v supported=%v", r.execTmp, r.Supported)
	}
	st := r.execTmp.Steps[0]
	if st.Method != "GET" || len(st.Groups) != 3 || st.Logic != "and" {
		t.Fatalf("step: %+v", st)
	}
}

func TestParseXray(t *testing.T) {
	r, err := ParseFile("b.yaml", []byte(xraySample))
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "xray" || r.RuleID != "poc-yaml-DT-File-reading" || r.Severity != "high" {
		t.Fatalf("%+v", r)
	}
	if !r.Supported || len(r.execTmp.Steps) != 1 {
		t.Fatalf("supported=%v steps=%d", r.Supported, len(r.execTmp.Steps))
	}
	g := r.execTmp.Steps[0].Groups
	if len(g) != 2 || g[0].Type != "status" || g[1].Words[0] != "root:" {
		t.Fatalf("groups: %+v", g)
	}
}

func TestParseAfrog(t *testing.T) {
	r, err := ParseFile("c.yaml", []byte(afrogSample))
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "afrog" || r.Severity != "high" || r.execTmp.Vars["adminb64"] != "YWRtaW46YWRtaW4=" {
		t.Fatalf("%+v vars=%v", r, r.execTmp.Vars)
	}
	if !r.Supported || len(r.execTmp.Steps) != 2 || r.execTmp.Logic != "or" {
		t.Fatalf("exec=%+v supported=%v", r.execTmp, r.Supported)
	}
	if r.execTmp.Steps[0].Headers["Authorization"] != "Basic {{adminb64}}" {
		t.Fatalf("headers: %+v", r.execTmp.Steps[0].Headers)
	}
}

func TestParseBranchORCEL(t *testing.T) {
	// 步骤表达式内的顶层 || 现已支持（任一分支命中即检出）
	doc := `
name: poc-or
rules:
  r0:
    request:
      method: GET
      path: /x
    expression: response.status == 200 || response.body.bcontains(b"z")
expression: r0()
`
	r, err := ParseFile("d.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Supported || len(r.execTmp.Steps[0].Branches) != 2 {
		t.Fatalf("应支持 || 分支: supported=%v", r.Supported)
	}
}

func TestParseUnsupportedCEL(t *testing.T) {
	doc := `
name: poc-x
rules:
  r0:
    request:
      method: GET
      path: /x
    expression: response.status == 200 && response.body.bcontains(bytes(md5(string(rand))))
expression: r0()
`
	r, err := ParseFile("d.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if r.Supported {
		t.Fatal("动态函数参数（md5(rand)）应标记不支持")
	}
}

func TestParseCELNewStructures(t *testing.T) {
	cases := map[string]string{
		"bytes(string())包裹": `response.status == 200 && response.body.bcontains(bytes(string("abc")))`,
		"bmatches正则":        `"root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)`,
		"latency时间盲注":       `response.status == 200 && response.latency >= 3000 && response.latency <= 4000`,
	}
	for name, expr := range cases {
		doc := "name: poc-n\ntransport: http\nrules:\n  r0:\n    request:\n      method: GET\n      path: /x\n    expression: '" +
			strings.ReplaceAll(expr, "'", "''") + "'\nexpression: r0()\n"
		r, err := ParseFile("n.yaml", []byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !r.Supported {
			t.Fatalf("%s 应可执行", name)
		}
	}
}

func TestSetVarHelpers(t *testing.T) {
	md5v, ok := evalSetVar(`md5('abc')`)
	if !ok || md5v != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5: %v %v", md5v, ok)
	}
	ue, ok := evalSetVar(`url_encode('a b')`)
	if !ok || ue != "a+b" {
		t.Fatalf("url_encode: %v", ue)
	}
	rs, ok := evalSetVar(`rand_text_alpha(8)`)
	if !ok || rs == "" {
		t.Fatal("rand 占位应可执行")
	}
	if s, ok := evalSetVar(`md5(r1)`); !ok || s != "md5(r1)" {
		t.Fatalf("非字面量参数应保留原表达式: %v %v", s, ok)
	}
}

func TestDslMultiGroup(t *testing.T) {
	gs, ok := dslGroup([]string{`status_code==200`, `contains(content_type, "text/html")`, `contains(to_lower(body), "welcome")`}, false)
	if !ok || len(gs) != 3 {
		t.Fatalf("dsl 多组: %v %v", ok, len(gs))
	}
	if gs[0].Type != "dsl" {
		t.Fatalf("dsl 组解析: %+v", gs)
	}
}

func TestRunResultCarriesTraffic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Marker", "cysec-dump")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	r, _ := ParseFile("dump.yaml", []byte(`
id: dump-traffic
info:
  name: Dump Traffic
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/health"
    matchers:
      - type: word
        words:
          - '"status":"ok"'
`))
	res := Run(r, srv.URL, 5)
	if !res.Matched {
		t.Fatalf("应命中: %+v", res)
	}
	if !strings.Contains(res.Request, "GET ") || !strings.Contains(res.Request, "/api/health") {
		t.Fatalf("请求报文缺失: %q", res.Request)
	}
	if !strings.Contains(res.Response, "HTTP/1.1 200") || !strings.Contains(res.Response, "cysec-dump") || !strings.Contains(res.Response, `"status":"ok"`) {
		t.Fatalf("响应报文缺失: %q", res.Response)
	}
}

func TestRunMatchedAndNotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/manager/html" && req.Header.Get("Authorization") == "Basic YWRtaW46YWRtaW4=" {
			w.Header().Set("Set-Cookie", "JSESSIONID=abc; Path=/")
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><title>/manager</title></html>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	r, err := ParseFile("c.yaml", []byte(afrogSample))
	if err != nil || !r.Supported {
		t.Fatalf("parse: %v supported=%v", err, r.Supported)
	}
	res := Run(r, srv.URL, 5)
	if !res.Matched || res.Requests == 0 {
		t.Fatalf("应命中: %+v", res)
	}

	// nuclei 规则对同目标不命中
	rn, _ := ParseFile("a.yaml", []byte(nucleiSample))
	res2 := Run(rn, srv.URL, 5)
	if res2.Matched {
		t.Fatalf("不应命中: %+v", res2)
	}
}

func TestRunNucleiMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>Kubecost</title></html>"))
	}))
	defer srv.Close()
	rn, _ := ParseFile("a.yaml", []byte(nucleiSample))
	res := Run(rn, srv.URL, 5)
	if !res.Matched {
		t.Fatalf("应命中: %+v", res)
	}
}

func TestXrayRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("root:x:0:0"))
	}))
	defer srv.Close()
	r, _ := ParseFile("b.yaml", []byte(xraySample))
	res := Run(r, srv.URL, 5)
	if !res.Matched {
		t.Fatalf("应命中: %+v", res)
	}
}
