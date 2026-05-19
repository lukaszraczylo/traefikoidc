package traefikoidc

import "testing"

func TestReady_FalseBeforeMetadata(t *testing.T) {
	tr := &TraefikOidc{}
	if tr.Ready() {
		t.Fatal("Ready() should be false before metadata discovery")
	}
}

func TestReady_TrueAfterAuthURLSet(t *testing.T) {
	tr := &TraefikOidc{}
	tr.metadataMu.Lock()
	tr.authURL = "https://idp.example/authorize"
	tr.metadataMu.Unlock()
	if !tr.Ready() {
		t.Fatal("Ready() should be true once authURL is populated")
	}
}
