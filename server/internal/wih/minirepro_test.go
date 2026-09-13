package wih

import "testing"

func TestMiniRepro(t *testing.T) {
	st := DefaultSettings()
	st.Excludes = []ExcludeRule{
		{Name: "排除指定站点的阿里云AK", ID: "Aliyun_AK_ID", Target: `regex:cdn\.example\.com`, Enabled: true},
	}
	_ = st
}
