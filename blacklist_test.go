package traefikoidc

import (
	"testing"
	"time"
)

func TestTokenBlacklist_Add(t *testing.T) {
	blacklist := NewTokenBlacklist()
	token := "testToken"
	expiry := time.Now().Add(time.Hour)

	blacklist.Add(token, expiry)

	if !blacklist.IsBlacklisted(token) {
		t.Errorf("Expected token to be blacklisted, but it was not")
	}
}

func TestTokenBlacklist_IsBlacklisted(t *testing.T) {
	blacklist := NewTokenBlacklist()
	token := "testToken"
	expiry := time.Now().Add(time.Hour)

	blacklist.Add(token, expiry)

	if !blacklist.IsBlacklisted(token) {
		t.Errorf("Expected token to be blacklisted, but it was not")
	}

	if blacklist.IsBlacklisted("nonExistentToken") {
		t.Errorf("Expected non-existent token to not be blacklisted, but it was")
	}
}

func TestTokenBlacklist_Cleanup(t *testing.T) {
	blacklist := NewTokenBlacklist()
	token := "testToken"
	expiry := time.Now().Add(-time.Hour) // Expired token

	blacklist.Add(token, expiry)
	blacklist.Cleanup()

	if blacklist.IsBlacklisted(token) {
		t.Errorf("Expected expired token to be removed after cleanup, but it was not")
	}
}

func TestTokenBlacklist_Remove(t *testing.T) {
	blacklist := NewTokenBlacklist()
	token := "testToken"
	expiry := time.Now().Add(time.Hour)

	blacklist.Add(token, expiry)
	blacklist.Remove(token)

	if blacklist.IsBlacklisted(token) {
		t.Errorf("Expected token to be removed, but it was not")
	}
}

func TestTokenBlacklist_Count(t *testing.T) {
	blacklist := NewTokenBlacklist()
	token1 := "token1"
	token2 := "token2"
	expiry := time.Now().Add(time.Hour)

	blacklist.Add(token1, expiry)
	blacklist.Add(token2, expiry)

	if blacklist.Count() != 2 {
		t.Errorf("Expected blacklist count to be 2, but got %d", blacklist.Count())
	}
}
