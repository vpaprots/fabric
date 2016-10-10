package bccsp

import "testing"

func TestGetDefault(t *testing.T) {
	csp, err := GetDefault()
	if err != nil {
		t.Fatalf("Failed getting default BCCSP [%s]", err)
	}
	if csp == nil {
		t.Fatal("Failed getting default BCCSP. Nil instance.")
	}
}