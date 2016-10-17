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

func TestGetBCCP(t *testing.T) {
	csp1, err := GetBCCSP(&SwFactoryOpts{EphemeralFlag:true})
	if err != nil {
		t.Fatalf("Failed getting ephmeral software-based BCCSP [%s]", err)
	}

	csp2, err := GetBCCSP(&SwFactoryOpts{EphemeralFlag:true})
	if err != nil {
		t.Fatalf("Failed getting ephmeral software-based BCCSP [%s]", err)
	}

	if csp1 == csp2 {
		t.Fatal("Ephemeral BCCSPs should point to different instances")
	}
}

func TestGetBCCP2(t *testing.T) {
	csp1, err := GetBCCSP(&SwFactoryOpts{EphemeralFlag:false})
	if err != nil {
		t.Fatalf("Failed getting non-ephmeral software-based BCCSP [%s]", err)
	}

	csp2, err := GetBCCSP(&SwFactoryOpts{EphemeralFlag:false})
	if err != nil {
		t.Fatalf("Failed getting non-ephmeral software-based BCCSP [%s]", err)
	}

	if csp1 != csp2 {
		t.Fatal("Non-Ephemeral BCCSPs should point to the same instance")
	}
}