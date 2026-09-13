package ua

import "testing"

func TestSetGet(t *testing.T) {
	orig := Get()
	defer Set(orig)
	Set("MyAgent/2.0")
	if Get() != "MyAgent/2.0" {
		t.Fatalf("got %s", Get())
	}
	Set("  ") // 空白回退不变
	if Get() != "MyAgent/2.0" {
		t.Fatal("空白不应改变值")
	}
	Set("") // 空串不应清空
	if Get() != "MyAgent/2.0" {
		t.Fatal("空串不应改变值")
	}
}

func TestDefault(t *testing.T) {
	if Get() == "" {
		t.Fatal("默认值不应为空")
	}
}
